using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;

namespace EndpointAgent;

internal static class Agent {
    private static readonly TimeSpan ReconnectDelay = TimeSpan.FromSeconds(2);

    public static async Task Run(Uri endpoint, string thumbprint, string serverPin, string device,
                                 CancellationToken cancellation = default) {
        if (endpoint.Scheme != "wss" || endpoint.UserInfo.Length != 0 || endpoint.Query.Length != 0 || endpoint.Fragment.Length != 0
            || device.Length is < 1 or > 100 || serverPin.Length != 64) throw new ArgumentException();
        using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
        store.Open(OpenFlags.ReadOnly);
        using var credential = store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false).Single();
        if (!credential.HasPrivateKey || !ValidNow(credential)) throw new ArgumentException();
        var expectedPin = Convert.FromHexString(serverPin);
        var state = new AgentRuntimeState(device);
        while (!cancellation.IsCancellationRequested) {
            try {
                using var socket = new ClientWebSocket();
                socket.Options.ClientCertificates.Add(credential);
                socket.Options.RemoteCertificateValidationCallback = (_, cert, _, _) => cert is not null
                    && ValidNow(new X509Certificate2(cert))
                    && CryptographicOperations.FixedTimeEquals(SHA256.HashData(cert.GetRawCertData()), expectedPin);
                using var connectDeadline = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
                connectDeadline.CancelAfter(TimeSpan.FromSeconds(15));
                await socket.ConnectAsync(endpoint, connectDeadline.Token);
                await Send(socket, new { type = "hello", protocolVersion = 1, deviceId = device }, cancellation);
                await AgentRuntime.Run(socket, device, sendHeartbeats: false, state);
            } catch (OperationCanceledException) when (cancellation.IsCancellationRequested) {
                throw;
            } catch (Exception error) when (error is WebSocketException or IOException or OperationCanceledException) {
            }
            await Task.Delay(ReconnectDelay, cancellation);
        }
    }

    private static bool ValidNow(X509Certificate2 cert) => DateTime.UtcNow >= cert.NotBefore.ToUniversalTime() && DateTime.UtcNow < cert.NotAfter.ToUniversalTime();
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private static async Task Send(WebSocket socket, object value, CancellationToken cancellation) {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
        timeout.CancelAfter(TimeSpan.FromSeconds(10));
        await socket.SendAsync(JsonSerializer.SerializeToUtf8Bytes(value, Json), WebSocketMessageType.Text, true, timeout.Token);
    }
}
