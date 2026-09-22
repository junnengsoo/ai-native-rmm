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
                    string device = Guid.NewGuid().ToString();
                    await Send(socket, new { state = "online", device_id = device, heartbeat_seconds = 15, stale_seconds = 45 });
                    var timer = Stopwatch.StartNew();
                    Require((await Receive(socket)).GetProperty("type").GetString() == "heartbeat", "heartbeat only");
                    Require(timer.Elapsed >= TimeSpan.FromSeconds(14) && timer.Elapsed < TimeSpan.FromSeconds(20), "15 second cadence");
                    await Send(socket, new { type = "heartbeat_ack" });
                    if (connections == 2) {
                        await socket.CloseOutputAsync(WebSocketCloseStatus.EndpointUnavailable, null, CancellationToken.None);
                        return;
                    }
                    string session = Guid.NewGuid().ToString();
                    await Send(socket, OpenSession(device, session));
                    Require((await ReceiveDispatch(socket)).GetProperty("type").GetString() == "session_ready", "enrolled worker ready");
                    string execution = Guid.NewGuid().ToString();
                    string script = "$global:enrolledValue=41; 'enrolled execution'";
                    await Send(socket, ExecuteRequest(device, session, execution, script, 5000));
                    var running = await ReceiveDispatch(socket);
                    Require(running.GetProperty("type").GetString() == "running"
                        && running.GetProperty("executionId").GetString() == execution, "enrolled correlated running");
                    var first = await ReceiveResultWithOutput(socket, execution);
                    Require(first.Stdout.Contains("enrolled execution"), "enrolled output frame");
                    Require(first.Result.GetProperty("executionId").GetString() == execution
                        && !first.Result.TryGetProperty("stdout", out _) && !first.Result.TryGetProperty("stderr", out _),
                        "enrolled terminal metadata omits output preview");
                    string second = Guid.NewGuid().ToString();
                    script = "$global:enrolledValue + 1";
                    await Send(socket, ExecuteRequest(device, session, second, script, 5000));
                    Require((await ReceiveDispatch(socket)).GetProperty("type").GetString() == "running", "second invocation running");
                    var result = await ReceiveResultWithOutput(socket, second);
                    Require(result.Stdout.Trim() == "42", "enrolled session state persists");
                    string slow = Guid.NewGuid().ToString();
                    script = "Start-Sleep -Seconds 2; 'finished'";
                    await Send(socket, ExecuteRequest(device, session, slow, script, 5000));
                    Require((await ReceiveDispatch(socket)).GetProperty("type").GetString() == "running", "slow invocation running");
                    string busy = Guid.NewGuid().ToString();
                    script = "'must-not-run-while-busy'";
                    await Send(socket, ExecuteRequest(device, session, busy, script, 5000));
                    Require((await ReceiveDispatch(socket)).GetProperty("type").GetString() == "rejected", "concurrent invocation rejected");
                    result = await ReceiveResultWithOutput(socket, slow);
                    Require(result.Result.GetProperty("executionId").GetString() == slow
                        && result.Stdout.Contains("finished"), "original invocation completes once");
                    await Send(socket, new { type = "close_session", deviceId = device, sessionId = session });
                    Require((await ReceiveDispatch(socket)).GetProperty("type").GetString() == "session_closed", "enrolled worker closed");
                    completed.TrySetResult();

                    async Task<JsonElement> ReceiveDispatch(WebSocket peer) {
                        while (true) {
                            var message = await Receive(peer);
                            if (message.GetProperty("type").GetString() != "heartbeat") return message;
                            await Send(peer, new { type = "heartbeat_ack" });
                        }
                    }

                    async Task<(JsonElement Result, string Stdout, string Stderr)> ReceiveResultWithOutput(WebSocket peer, string expectedExecution) {
                        var stdout = new StringBuilder();
                        var stderr = new StringBuilder();
                        while (true) {
                            var message = await ReceiveDispatch(peer);
                            string type = message.GetProperty("type").GetString()!;
                            if (type == "output") {
                                Require(message.GetProperty("executionId").GetString() == expectedExecution, "correlated enrolled output");
                                string text = message.GetProperty("text").GetString()!;
                                if (message.GetProperty("stream").GetString() == "stdout") stdout.Append(text);
                                else stderr.Append(text);
                                continue;
                            }
                            Require(type == "result", "enrolled terminal result after output");
                            return (message, stdout.ToString(), stderr.ToString());
                        }
                    }
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
            using var persisted = CngKey.Open(keyName);
            Require(persisted.ExportPolicy == CngExportPolicies.None, "Windows key is nonexportable");
            bool exportDenied = false;
            try { persisted.Export(CngKeyBlobFormat.EccPrivateBlob); } catch (CryptographicException) { exportDenied = true; }
            Require(exportDenied, "private export refused by Windows");
            string output = string.Join("\n", new[] {
                await agent.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10)),
                await agent.StandardOutput.ReadLineAsync().WaitAsync(TimeSpan.FromSeconds(10)),
            });
            Require(output.Split("PAIRING_CODE ").Length == 2, "one-time local code delivery");
            if (!agent.HasExited) { agent.Kill(true); await agent.WaitForExitAsync(); }
            Require(!(await agent.StandardError.ReadToEndAsync()).Contains("ABCDEFGHIJKL"), "routine error excludes code");
            Console.WriteLine("PASS enrollment proof, protected Windows key, pending reconnect, heartbeat and enrolled dispatch");
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
    private static object OpenSession(string device, string session) => new {
        type = "open_session", deviceId = device, sessionId = session
    };
    private static object ExecuteRequest(string device, string session, string execution, string script, int timeoutMs) => new {
        type = "execute", deviceId = device, sessionId = session, executionId = execution,
        script, scriptSha256 = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(script))),
        timeoutMs
    };
    private static Task Send(WebSocket socket, object value) => socket.SendAsync(JsonSerializer.SerializeToUtf8Bytes(value), WebSocketMessageType.Text, true, CancellationToken.None);
    private static async Task<JsonElement> Receive(WebSocket socket) {
        using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        var buffer = new byte[2048];
        var message = await socket.ReceiveAsync(buffer, timeout.Token);
        Require(message.EndOfMessage && message.MessageType == WebSocketMessageType.Text, "bounded text frame");
        return JsonDocument.Parse(buffer.AsMemory(0, message.Count)).RootElement.Clone();
    }
}
