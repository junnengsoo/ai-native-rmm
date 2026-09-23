using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace EndpointAgent;

// Enrollment and the authenticated long-lived device channel.
internal static class Enrollment {
    public static Task Run(Uri endpoint, string keyName) =>
        Run(endpoint, keyName, EnrollmentStatus.Console, CancellationToken.None);

    public static async Task Run(Uri endpoint, string keyName, IEnrollmentStatus statusSink, CancellationToken cancellation) {
        if (endpoint.Scheme != "wss" || endpoint.AbsolutePath != "/agent"
            || endpoint.UserInfo.Length != 0 || endpoint.Query.Length != 0 || endpoint.Fragment.Length != 0
            || keyName.Length is < 1 or > 100 || keyName.Any(c => !char.IsAsciiLetterOrDigit(c) && c != '-'))
            throw new ArgumentException();
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        using var key = CngKey.Exists(keyName) ? CngKey.Open(keyName) : CngKey.Create(CngAlgorithm.ECDsaP256, keyName,
            new CngKeyCreationParameters { ExportPolicy = CngExportPolicies.None, KeyUsage = CngKeyUsages.Signing });
        if (key.ExportPolicy != CngExportPolicies.None || key.Algorithm != CngAlgorithm.ECDsaP256)
            throw new CryptographicException();
        using var signer = new ECDsaCng(key);
        string publicKey = Convert.ToBase64String(signer.ExportSubjectPublicKeyInfo());
        AgentRuntimeState? runtimeState = null;
        while (!cancellation.IsCancellationRequested) {
            try {
                using var socket = new ClientWebSocket();
                // Platform certificate-chain, hostname and validity checks remain enabled.
                using var deadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
                deadline.CancelAfter(TimeSpan.FromSeconds(15));
                await socket.ConnectAsync(endpoint, deadline.Token);
                var challenge = await Receive(socket);
                string nonce = challenge.GetProperty("nonce").GetString()!;
                if (challenge.GetProperty("type").GetString() != "challenge" || nonce.Length != 43)
                    throw new InvalidDataException();
                byte[] signature = signer.SignData(Encoding.UTF8.GetBytes("rmm-reachability-v1\n" + nonce),
                    HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence);
                await Send(socket, new { public_key = publicKey, signature = Convert.ToBase64String(signature) });
                var status = await Receive(socket);
                string state = status.GetProperty("state").GetString()!;
                if (state == "pending") {
                    if (status.TryGetProperty("code", out var code)) {
                        // Deliberate one-time local delivery, never routine operational logging.
                        string value = code.GetString()!;
                        if (value.Length != 12 || value.Any(c => !(c is >= 'A' and <= 'Z' or >= '2' and <= '7')))
                            throw new InvalidDataException();
                        statusSink.Pending(value);
                    } else statusSink.Pending(null);
                } else if (state == "online") {
                    // These are fixed v1 requirements, not server-controlled scheduling.
                    if (status.GetProperty("heartbeat_seconds").GetInt32() != 15
                        || status.GetProperty("stale_seconds").GetInt32() != 45) throw new InvalidDataException();
                    if (!Guid.TryParse(status.GetProperty("device_id").GetString(), out var device))
                        throw new InvalidDataException();
                    statusSink.Online(device);
                    runtimeState ??= new AgentRuntimeState(device.ToString());
                    await AgentRuntime.Run(socket, device.ToString(), sendHeartbeats: true, runtimeState);
                } else if (state == "denied") throw new UnauthorizedAccessException();
                else if (state == "rate_limited") statusSink.Unavailable("rate_limited");
                else throw new InvalidDataException();
            } catch (WebSocketException) { statusSink.Unavailable("connection_unavailable"); }
            catch (OperationCanceledException) when (!cancellation.IsCancellationRequested) { statusSink.Unavailable("connection_timeout"); }
            await Task.Delay(TimeSpan.FromSeconds(15), cancellation);
        }
    }

    private static async Task Send(WebSocket socket, object value) {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await socket.SendAsync(JsonSerializer.SerializeToUtf8Bytes(value), WebSocketMessageType.Text, true, timeout.Token);
    }

    private static async Task<JsonElement> Receive(WebSocket socket) {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var buffer = new byte[2048];
        using var data = new MemoryStream();
        WebSocketReceiveResult part;
        do {
            part = await socket.ReceiveAsync(buffer, timeout.Token);
            if (part.MessageType == WebSocketMessageType.Close) throw new WebSocketException();
            if (part.MessageType != WebSocketMessageType.Text || data.Length + part.Count > 2048)
                throw new InvalidDataException();
            data.Write(buffer, 0, part.Count);
        } while (!part.EndOfMessage);
        return JsonDocument.Parse(data.ToArray()).RootElement.Clone();
    }
}
