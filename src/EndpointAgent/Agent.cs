using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
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
        await AgentRuntime.Run(socket, device, sendHeartbeats: false);
    }

    private static bool ValidNow(X509Certificate2 cert) => DateTime.UtcNow >= cert.NotBefore.ToUniversalTime() && DateTime.UtcNow < cert.NotAfter.ToUniversalTime();
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private static async Task Send(WebSocket socket, object value) {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        await socket.SendAsync(JsonSerializer.SerializeToUtf8Bytes(value, Json), WebSocketMessageType.Text, true, timeout.Token);
    }
}
