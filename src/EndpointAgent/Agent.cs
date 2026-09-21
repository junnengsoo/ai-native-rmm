using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace EndpointAgent;

internal static class Agent {
    public static async Task Run(Uri endpoint, string thumbprint, string serverPin, string device) {
        if (endpoint.Scheme != "wss" || endpoint.UserInfo.Length != 0 || endpoint.Query.Length != 0 || endpoint.Fragment.Length != 0
            || device.Length is < 1 or > 100 || serverPin.Length != 64) throw new ArgumentException();
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        using var credential = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false).Single();
        if (!credential.HasPrivateKey || !ValidNow(credential)) throw new ArgumentException();
        var expectedPin = Convert.FromHexString(serverPin);
        using var socket = new ClientWebSocket();
        socket.Options.ClientCertificates.Add(credential);
        socket.Options.RemoteCertificateValidationCallback = (_, cert, _, _) => cert is not null
            && ValidNow(new X509Certificate2(cert))
            && CryptographicOperations.FixedTimeEquals(SHA256.HashData(cert.GetRawCertData()), expectedPin);
        using var connectDeadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
        await socket.ConnectAsync(endpoint, connectDeadline.Token);
        await Send(socket, new { type = "hello", protocolVersion = 1, deviceId = device });
        WorkerProcess? worker = null;
        string? session = null;
        var executions = new HashSet<string>(StringComparer.Ordinal);
        var sessions = new HashSet<string>(StringComparer.Ordinal);
        try {
            while (socket.State == WebSocketState.Open) {
                Dispatch? request;
                try { request = Dispatch.Parse(await Receive(socket), device); }
                catch (JsonException) { request = null; }
                if (request is null) { await Reject(socket, "invalid_request"); continue; }
                if (request.Type == "open_session" && worker is null && sessions.Count < 100 && sessions.Add(request.SessionId)) {
                    session = request.SessionId;
                    worker = await WorkerProcess.Start();
                    await Send(socket, new { type = "session_ready", deviceId = device, sessionId = session });
                } else if (request.Type == "close_session" && worker is not null && request.SessionId == session) {
                    await worker.DisposeAsync();
                    worker = null;
                    await Send(socket, new { type = "session_closed", deviceId = device, sessionId = session });
                    session = null;
                } else if (request.Type == "execute" && worker is not null && worker.IsUsable && request.SessionId == session
                    && executions.Count < 1000 && executions.Add(request.ExecutionId!)) {
                    string execution = request.ExecutionId!;
                    await Send(socket, new { type = "running", deviceId = device, sessionId = session, executionId = execution });
                    var result = await worker.Execute(request.Script!, request.TimeoutMs);
                    await Send(socket, new { type = "result", deviceId = device, sessionId = session, executionId = execution,
                        result.State, result.InvocationOutcome, result.ExitCode, result.HadErrors, result.Stdout,
                        result.Stderr, result.DurationMs, result.CaptureTruncated, result.LastNativeExitCode });
                } else await Reject(socket, "invalid_state_or_duplicate");
            }
        } finally { if (worker is not null) await worker.DisposeAsync(); }
    }

    private static bool ValidNow(X509Certificate2 cert) => DateTime.UtcNow >= cert.NotBefore.ToUniversalTime() && DateTime.UtcNow < cert.NotAfter.ToUniversalTime();
    private static Task Reject(WebSocket socket, string code) => Send(socket, new { type = "rejected", code });
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private static async Task Send(WebSocket socket, object value) {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await socket.SendAsync(JsonSerializer.SerializeToUtf8Bytes(value, Json), WebSocketMessageType.Text, true, timeout.Token);
    }
    private static async Task<JsonElement> Receive(WebSocket socket) {
        using var timeout = new CancellationTokenSource(TimeSpan.FromMinutes(2));
        using var data = new MemoryStream();
        var buffer = new byte[8192];
        WebSocketReceiveResult part;
        do {
            part = await socket.ReceiveAsync(buffer, timeout.Token);
            if (part.MessageType != WebSocketMessageType.Text || data.Length + part.Count > 80_000) throw new InvalidDataException();
            data.Write(buffer, 0, part.Count);
        } while (!part.EndOfMessage);
        return JsonDocument.Parse(data.ToArray()).RootElement.Clone();
    }
}
