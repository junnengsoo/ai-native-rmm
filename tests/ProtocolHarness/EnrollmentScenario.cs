using System.Diagnostics;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

// Independent peer for reachability v1; deliberately does not call production code.
internal static class EnrollmentScenario {
    public static async Task Run(string agentPath, X509Certificate2 serverCertificate) {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        string keyName = "rmm-harness-" + Guid.NewGuid().ToString("N");
        using var roots = new X509Store(StoreName.Root, StoreLocation.LocalMachine);
        roots.Open(OpenFlags.ReadWrite);
        var builder = WebApplication.CreateSlimBuilder();
        builder.Logging.ClearProviders();
        builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 18444,
            listen => listen.UseHttps(serverCertificate)));
        await using var app = builder.Build();
        app.UseWebSockets();
        var completed = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
        string? publicKey = null;
        string? lastSignature = null;
        int connections = 0;
        app.Map("/agent", async context => {
            using var socket = await context.WebSockets.AcceptWebSocketAsync();
            try {
                string nonce = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)).TrimEnd('=').Replace('+', '-').Replace('/', '_');
                await Send(socket, new { type = "challenge", nonce });
                var proof = await Receive(socket);
                string presented = proof.GetProperty("public_key").GetString()!;
                string signature = proof.GetProperty("signature").GetString()!;
                using var key = ECDsa.Create();
                key.ImportSubjectPublicKeyInfo(Convert.FromBase64String(presented), out _);
                Require(key.VerifyData(Encoding.UTF8.GetBytes("rmm-reachability-v1\n" + nonce),
                    Convert.FromBase64String(signature), HashAlgorithmName.SHA256, DSASignatureFormat.Rfc3279DerSequence), "real key possession");
                Require(publicKey is null || publicKey == presented, "key retained across pending reconnect");
                Require(lastSignature != signature, "fresh challenge proof");
                publicKey = presented;
                lastSignature = signature;
                if (++connections == 1) {
                    await Send(socket, new { state = "pending", code = "ABCDEFGHIJKL", expires_in_seconds = 600 });
                    await socket.CloseOutputAsync(WebSocketCloseStatus.NormalClosure, null, CancellationToken.None);
                } else {
                    await Send(socket, new { state = "online", device_id = Guid.NewGuid().ToString(), heartbeat_seconds = 15, stale_seconds = 45 });
                    var timer = Stopwatch.StartNew();
                    Require((await Receive(socket)).GetProperty("type").GetString() == "heartbeat", "heartbeat only");
                    Require(timer.Elapsed >= TimeSpan.FromSeconds(14) && timer.Elapsed < TimeSpan.FromSeconds(20), "15 second cadence");
                    if (connections == 2) {
                        await socket.CloseOutputAsync(WebSocketCloseStatus.EndpointUnavailable, null, CancellationToken.None);
                        return;
                    }
                    // A reachability peer must never be able to turn this mode into execution.
                    await Send(socket, new { type = "execute", script = "'must-not-run'" });
                    completed.TrySetResult();
                }
            } catch (Exception error) { completed.TrySetException(error); }
        });
        Process? agent = null;
        try {
            roots.Add(new X509Certificate2(serverCertificate.RawData));
            await app.StartAsync();
            var start = new ProcessStartInfo("dotnet") { UseShellExecute = false, RedirectStandardOutput = true, RedirectStandardError = true };
            foreach (var argument in new[] { agentPath, "--enroll", "wss://localhost:18444/agent", keyName }) start.ArgumentList.Add(argument);
            agent = Process.Start(start)!;
            await completed.Task.WaitAsync(TimeSpan.FromSeconds(90));
            await agent.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(10));
            Require(agent.ExitCode == 1, "execution message rejected by enrollment-only mode");
            using var persisted = CngKey.Open(keyName);
            Require(persisted.ExportPolicy == CngExportPolicies.None, "Windows key is nonexportable");
            bool exportDenied = false;
            try { persisted.Export(CngKeyBlobFormat.EccPrivateBlob); } catch (CryptographicException) { exportDenied = true; }
            Require(exportDenied, "private export refused by Windows");
            string output = await agent.StandardOutput.ReadToEndAsync();
            Require(output.Split("PAIRING_CODE ").Length == 2, "one-time local code delivery");
            Require(!(await agent.StandardError.ReadToEndAsync()).Contains("ABCDEFGHIJKL"), "routine error excludes code");
            Console.WriteLine("PASS enrollment proof, protected Windows key, pending reconnect, heartbeat and execution refusal");
        } finally {
            if (agent is not null) { if (!agent.HasExited) agent.Kill(true); agent.Dispose(); }
            await app.StopAsync();
            if (CngKey.Exists(keyName)) { using var key = CngKey.Open(keyName); key.Delete(); }
            roots.Remove(serverCertificate);
        }
    }

    private static void Require(bool condition, string description) {
        if (!condition) throw new InvalidOperationException(description);
    }
    private static Task Send(WebSocket socket, object value) => socket.SendAsync(JsonSerializer.SerializeToUtf8Bytes(value), WebSocketMessageType.Text, true, CancellationToken.None);
    private static async Task<JsonElement> Receive(WebSocket socket) {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var buffer = new byte[2048];
        var message = await socket.ReceiveAsync(buffer, timeout.Token);
        Require(message.EndOfMessage && message.MessageType == WebSocketMessageType.Text, "bounded text frame");
        return JsonDocument.Parse(buffer.AsMemory(0, message.Count)).RootElement.Clone();
    }
}
