using System.Diagnostics;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading.Channels;
using Microsoft.AspNetCore.Server.Kestrel.Https;

// Deliberately independent wire implementation: no reference to agent assemblies.
if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Run on Windows.");
if (args.Length != 4) throw new ArgumentException("Usage: ProtocolHarness agent.dll server-thumbprint endpoint-thumbprint wrong-thumbprint");
using var serverCert = Certificate(args[1]);
using var endpointCert = Certificate(args[2]);
var builder = WebApplication.CreateSlimBuilder();
builder.Logging.ClearProviders();
builder.WebHost.ConfigureKestrel(options => options.Listen(IPAddress.Loopback, 18443, listen =>
    listen.UseHttps(new HttpsConnectionAdapterOptions {
        ServerCertificate = serverCert,
        ClientCertificateMode = ClientCertificateMode.RequireCertificate,
        ClientCertificateValidation = (cert, _, _) => cert.RawData.AsSpan().SequenceEqual(endpointCert.RawData)
            && DateTime.UtcNow >= cert.NotBefore.ToUniversalTime() && DateTime.UtcNow < cert.NotAfter.ToUniversalTime()
    })));
var sockets = Channel.CreateUnbounded<(int Accepted, WebSocket Socket)>();
var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
int acceptedSockets = 0;
string dataRoot = Path.Combine(Path.GetTempPath(), "rmm-harness-" + Guid.NewGuid().ToString("N"));
Directory.CreateDirectory(dataRoot);
await using var app = builder.Build();
app.UseWebSockets();
app.Map("/agent", async context => {
    if (!context.WebSockets.IsWebSocketRequest) { context.Response.StatusCode = 400; return; }
    using var acceptedSocket = await context.WebSockets.AcceptWebSocketAsync();
    int accepted = Interlocked.Increment(ref acceptedSockets);
    await sockets.Writer.WriteAsync((accepted, acceptedSocket));
    await done.Task;
});
await app.StartAsync();
await RejectIdentity(args[3], Convert.ToHexString(SHA256.HashData(serverCert.RawData)));
await RejectIdentity(args[2], new string('0', 64));
using (var privateKey = endpointCert.GetRSAPrivateKey()!) {
    bool denied = false;
    try { privateKey.ExportPkcs8PrivateKey(); } catch (CryptographicException) { denied = true; }
    Require(denied, "endpoint private key is nonexportable");
}
using var agent = StartAgent(args[2]);
try {
    var socket = await NextSocket();
    var hello = await Receive(socket);
    Require(hello.GetProperty("type").GetString() == "hello", "agent authenticates and identifies itself");
    string device = hello.GetProperty("deviceId").GetString()!;
    Require(device == "test-device" && hello.GetProperty("protocolVersion").GetInt32() == 1,
        "certificate peer is bound to the expected device and version");
    string session = Guid.NewGuid().ToString();
    var queuedRecords = new Queue<JsonElement>();
    await OpenSession();

    var result = await ExecuteWithOutput("'hello from Windows'", 5000);
    Require(result.Result.GetProperty("state").GetString() == "completed"
        && result.Result.GetProperty("invocationOutcome").GetString() == "completed_normally"
        && result.Result.GetProperty("exitCode").GetInt32() == 0
        && result.Result.GetProperty("exitCodeSource").GetString() == "normalized_invocation"
        && result.Stdout.Contains("hello from Windows")
        && result.Result.GetProperty("durationMs").GetDouble() >= 0, "harmless command has correlated structured evidence");
    Console.WriteLine("SMOKE " + result.Result.GetRawText());

    var error = await ExecuteWithOutput("throw 'expected-smoke-error'", 5000);
    Require(error.Result.GetProperty("invocationOutcome").GetString() == "terminating_error"
        && error.Result.GetProperty("exitCode").GetInt32() == 1
        && error.Result.GetProperty("hadErrors").GetBoolean()
        && error.Stderr.Contains("expected-smoke-error"), "terminating error has definitive invocation evidence");

    var native = await Execute("cmd /c exit 7", 5000);
    Require(native.GetProperty("exitCode").GetInt32() == 0 && native.GetProperty("lastNativeExitCode").GetInt32() == 7,
        "native failure is separate evidence, not a universal script exit");
    var clean = await ExecuteWithOutput("$null -eq $LASTEXITCODE", 5000);
    Require(clean.Stdout.Contains("True") && clean.Result.GetProperty("lastNativeExitCode").ValueKind == JsonValueKind.Null,
        "previous native status cannot leak into the next execution");
    await Execute("$global:investigationValue=42; function Get-InvestigationValue { $global:investigationValue }; Set-Location $env:SystemRoot", 5000);
    var state = await ExecuteWithOutput("Get-InvestigationValue; (Get-Location).Path", 5000);
    Require(state.Stdout.Contains("42") && state.Stdout.Contains("Windows"), "variables functions and directory persist");
    var nonterminating = await ExecuteWithOutput("Write-Error 'nonterminating'; 'continued'", 5000);
    Require(nonterminating.Result.GetProperty("invocationOutcome").GetString() == "completed_normally"
        && nonterminating.Result.GetProperty("exitCode").GetInt32() == 0
        && nonterminating.Result.GetProperty("hadErrors").GetBoolean()
        && nonterminating.Stdout.Contains("continued"), "nonterminating error remains normal completion");
    var fake = await ExecuteWithOutput("'{\"type\":\"result\",\"state\":\"completed\"}'; throw 'still-an-error'", 5000);
    Require(fake.Result.GetProperty("invocationOutcome").GetString() == "terminating_error"
        && fake.Stdout.Contains("completed"), "printed lifecycle is only output and pre-error output is retained");
    var bounded = await ExecuteWithOutput("'x' * 100000", 30000);
    Require(!bounded.Result.GetProperty("captureTruncated").GetBoolean()
        && bounded.Stdout.Length >= 100000, "long output is retained incrementally");

    var explicitExit = await Execute("exit 23", 5000);
    Require(explicitExit.GetProperty("invocationOutcome").GetString() == "explicit_exit"
        && explicitExit.GetProperty("exitCode").GetInt32() == 23
        && explicitExit.GetProperty("exitCodeSource").GetString() == "explicit_script_exit",
        "explicit exit keeps requested code and provenance");
    await Rejected(Request("'must-not-run'"), "explicit exit retires the worker until replacement");
    await OpenReplacementSession();

    var fresh = await ExecuteWithOutput("$null -eq (Get-Variable investigationValue -ErrorAction SilentlyContinue); -not (Test-Path Function:\\Get-InvestigationValue)", 5000);
    Require(fresh.Stdout.Trim() == "True\nTrue", "replacement session has fresh variable and function state");
    Console.WriteLine("PASS invocation and persistent-session scenario");

    var secret = await ExecuteWithOutput("$null -eq $env:RMM_TEST_SECRET; [Environment]::GetCommandLineArgs() -join ' '", 5000);
    Require(secret.Stdout.StartsWith("True\n")
        && !secret.Stdout.Contains(args[2]), "worker does not inherit agent secret environment or certificate configuration");
    var altered = Request("'must-not-run'");
    altered["scriptSha256"] = new string('0', 64);
    await Rejected(altered, "altered script hash");
    var wrongBinding = Request("'must-not-run'"); wrongBinding["deviceId"] = "another-device";
    await Rejected(wrongBinding, "wrong device binding");
    wrongBinding = Request("'must-not-run'"); wrongBinding["sessionId"] = Guid.NewGuid().ToString();
    await Rejected(wrongBinding, "wrong session binding");
    var malformed = Request("'must-not-run'"); malformed["unexpected"] = "secret-that-must-not-be-reflected";
    await Rejected(malformed, "unknown field");
    malformed = Request("'must-not-run'"); malformed["timeoutMs"] = 0;
    await Rejected(malformed, "unbounded or invalid timeout");
    await socket.SendAsync(Encoding.UTF8.GetBytes("{broken json"), WebSocketMessageType.Text, true, CancellationToken.None);
    Require((await Receive(socket)).GetProperty("type").GetString() == "rejected", "malformed JSON is rejected safely");
    Console.WriteLine("PASS authentication and validation scenario");

    string duplicateId = Guid.NewGuid().ToString();
    await Execute("$global:duplicateCounter++; 'once'", 5000, duplicateId);
    var duplicate = Request("$global:duplicateCounter++; 'once'"); duplicate["executionId"] = duplicateId;
    await Rejected(duplicate, "duplicate execution");
    Require((await ExecuteWithOutput("$global:duplicateCounter", 5000)).Stdout.Trim() == "1",
        "rejected duplicate does not repeat its side effect");

    var timeoutWatch = Stopwatch.StartNew();
    var timedOut = await ExecuteWithOutput("'started'; Start-Sleep -Seconds 10; 'finished'", 500);
    timeoutWatch.Stop();
    Require(timedOut.Result.GetProperty("state").GetString() == "timed_out"
        && timedOut.Result.GetProperty("invocationOutcome").GetString() == "stopped"
        && timedOut.Result.GetProperty("exitCode").ValueKind == JsonValueKind.Null
        && timedOut.Stdout.Contains("started") && !timedOut.Stdout.Contains("finished")
        && timeoutWatch.Elapsed < TimeSpan.FromSeconds(5),
        "execution timeout stops the invocation at its requested deadline");
    await Rejected(Request("'must-not-run'"), "timed-out worker is retired");
    await OpenReplacementSession();
    Console.WriteLine("PASS per-execution timeout scenario");

    string reconnectExecution = Guid.NewGuid().ToString();
    string reconnectScript = "$global:lateEvidence=1; Start-Sleep -Seconds 3; $global:lateEvidence=2";
    var reconnect = Request(reconnectScript);
    reconnect["executionId"] = reconnectExecution;
    await Send(socket, reconnect);
    await WaitRecord(record => IsRecord(record, "execution_started", reconnectExecution));
    int acceptedBeforeReconnect = Volatile.Read(ref acceptedSockets);
    socket.Abort();
    socket = await NextSocketAfter(acceptedBeforeReconnect);
    var rehello = await Receive(socket);
    Require(rehello.GetProperty("type").GetString() == "hello"
        && rehello.GetProperty("deviceId").GetString() == device, "agent reconnects with same identity");
    var reconnectFinished = await WaitRecord(record => IsRecord(record, "execution_finished", reconnectExecution));
    Require(reconnectFinished.GetProperty("data").GetProperty("state").GetString() == "completed",
        "active invocation survives reconnect and reports ordinary terminal result");
    var reconnectState = await ExecuteWithOutput("$global:lateEvidence", 5000);
    Require(reconnectState.Stdout.Trim() == "2", "reconnected invocation ran exactly once to completion");

    string drainExecution = Guid.NewGuid().ToString();
    var drainDuringReconnect = Request("1..25 | ForEach-Object { \"drain $_\"; Start-Sleep -Milliseconds 40 }; $global:drainComplete=25");
    drainDuringReconnect["executionId"] = drainExecution;
    await Send(socket, drainDuringReconnect);
    await WaitRecord(record => IsRecord(record, "execution_started", drainExecution));
    int acceptedBeforeDrainReconnect = Volatile.Read(ref acceptedSockets);
    socket.Abort();
    socket = await NextSocketAfter(acceptedBeforeDrainReconnect);
    var drainHello = await Receive(socket);
    Require(drainHello.GetProperty("type").GetString() == "hello"
        && drainHello.GetProperty("deviceId").GetString() == device, "agent reconnects while draining output");
    var drainedOutput = new StringBuilder();
    while (true) {
        var record = await WaitRecord(value => {
            if (!value.TryGetProperty("data", out var data)
                || !data.TryGetProperty("executionId", out var id)
                || id.GetString() != drainExecution) return false;
            string? type = value.GetProperty("recordType").GetString();
            return type is "output_chunk" or "execution_finished";
        });
        if (record.GetProperty("recordType").GetString() == "execution_finished") {
            Require(record.GetProperty("data").GetProperty("state").GetString() == "completed",
                "chatty disconnected invocation reaches terminal state");
            break;
        }
        drainedOutput.Append(record.GetProperty("data").GetProperty("text").GetString());
    }
    Require(drainedOutput.ToString().Contains("drain 25"), "worker output draining does not wait for socket delivery");
    var drainState = await ExecuteWithOutput("$global:drainComplete", 5000);
    Require(drainState.Stdout.Trim() == "25", "chatty disconnected invocation keeps the worker reusable");

    string retransmitExecution = Guid.NewGuid().ToString();
    var retransmit = Request("$global:ackDropCounter++; $global:ackDropCounter");
    retransmit["executionId"] = retransmitExecution;
    await Send(socket, retransmit);
    var terminalWithoutAck = await WaitRecordWithoutAck(record => IsRecord(record, "execution_finished", retransmitExecution));
    long retransmitSequence = terminalWithoutAck.GetProperty("sequence").GetInt64();
    int acceptedBeforeAckDropReconnect = Volatile.Read(ref acceptedSockets);
    socket.Abort();
    socket = await NextSocketAfter(acceptedBeforeAckDropReconnect);
    var ackDropHello = await Receive(socket);
    Require(ackDropHello.GetProperty("type").GetString() == "hello"
        && ackDropHello.GetProperty("deviceId").GetString() == device, "agent reconnects after dropped ack");
    var resentTerminal = await WaitRecord(record => IsRecord(record, "execution_finished", retransmitExecution)
        && record.GetProperty("sequence").GetInt64() == retransmitSequence);
    Require(resentTerminal.GetProperty("data").GetProperty("state").GetString() == "completed",
        "dropped ack retransmits terminal evidence");
    var counterAfterRetransmit = await ExecuteWithOutput("$global:ackDropCounter", 5000);
    Require(counterAfterRetransmit.Stdout.Trim() == "1", "dropped ack retransmission does not rerun the script");

    string cancelledExecution = Guid.NewGuid().ToString();
    var cancelRequest = Request("'before-cancel'; Start-Sleep -Seconds 20");
    cancelRequest["executionId"] = cancelledExecution;
    await Send(socket, cancelRequest);
    await WaitRecord(record => IsRecord(record, "execution_started", cancelledExecution));
    await Send(socket, new { type = "cancel_execution", deviceId = device, sessionId = session, executionId = cancelledExecution });
    var cancelled = (await WaitRecord(record => IsRecord(record, "execution_finished", cancelledExecution))).GetProperty("data");
    Require(cancelled.GetProperty("state").GetString() == "cancelled"
        && cancelled.GetProperty("invocationOutcome").GetString() == "stopped"
        && cancelled.GetProperty("exitCode").ValueKind == JsonValueKind.Null, "caller cancellation confirms stopping");
    await WaitRecord(record => IsRecord(record, "worker_stopped", cancelledExecution));
    await Rejected(Request("'must-not-run'"), "cancelled worker is retired");
    await OpenReplacementSession();

    string closeExecution = Guid.NewGuid().ToString();
    var activeClose = Request("$ownedChild = Start-Process -FilePath $env:ComSpec -ArgumentList '/c ping -n 60 127.0.0.1 > nul' -PassThru; $ownedChild.Id; Start-Sleep -Seconds 20");
    activeClose["executionId"] = closeExecution;
    await Send(socket, activeClose);
    var childOutput = await WaitRecord(record => IsRecord(record, "output_chunk", closeExecution)
        && record.GetProperty("data").GetProperty("stream").GetString() == "stdout");
    int childId = int.Parse(childOutput.GetProperty("data").GetProperty("text").GetString()!.Trim());
    await Send(socket, new { type = "close_session", deviceId = device, sessionId = session });
    var closeCancelled = (await WaitRecord(record => IsRecord(record, "execution_finished", closeExecution))).GetProperty("data");
    Require(closeCancelled.GetProperty("state").GetString() == "cancelled"
        && closeCancelled.GetProperty("invocationOutcome").GetString() == "stopped",
        "active close cancels the invocation truthfully; actual=" + closeCancelled.GetRawText());
    await WaitRecord(record => record.GetProperty("recordType").GetString() == "session_closed"
        && record.GetProperty("data").GetProperty("sessionId").GetString() == session);
    await OpenReplacementSession();
    var cleanup = await ExecuteWithOutput($"$null -eq (Get-Process -Id {childId} -ErrorAction SilentlyContinue)", 5000);
    Require(cleanup.Stdout.Trim() == "True", "active close terminated the session-owned native child");

    var capped = await ExecuteWithOutput("'z' * 500000", 30000);
    Require(capped.Result.GetProperty("captureTruncated").GetBoolean()
        && capped.Stdout.Length > 0
        && capped.Stdout.Length < 500000,
        "endpoint ledger capacity records output loss without blocking lifecycle records");

    var lost = await Execute("[Environment]::Exit(19)", 5000);
    Require(lost.GetProperty("state").GetString() == "outcome_unknown"
        && lost.GetProperty("exitCode").ValueKind == JsonValueKind.Null,
        "worker disappearance cannot forge definitive completion");
    await OpenReplacementSession();
    Console.WriteLine("PASS reconnect, cancellation, active close cleanup, and worker-loss scenario");

    Dictionary<string, object> Request(string script) => new() {
        ["type"] = "execute", ["deviceId"] = device, ["sessionId"] = session,
        ["executionId"] = Guid.NewGuid().ToString(), ["script"] = script,
        ["scriptSha256"] = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(script))).ToLowerInvariant(),
        ["timeoutMs"] = 5000
    };

    async Task OpenSession() {
        await Send(socket, new { type = "open_session", deviceId = device, sessionId = session });
        var started = await WaitRecord(record => record.GetProperty("recordType").GetString() == "session_started"
            && record.GetProperty("data").GetProperty("sessionId").GetString() == session);
        Require(started.GetProperty("sequence").GetInt64() > 0, "session start is written through the ledger");
    }

    async Task OpenReplacementSession() {
        session = Guid.NewGuid().ToString();
        await OpenSession();
    }

    async Task Rejected(object request, string description) {
        await Send(socket, request);
        var rejected = await Receive(socket);
        Require(rejected.GetProperty("type").GetString() == "rejected"
            && !rejected.GetRawText().Contains("secret-that-must-not-be-reflected"), description);
    }

    async Task<JsonElement> Execute(string script, int timeoutMs, string? executionId = null) {
        return (await ExecuteWithOutput(script, timeoutMs, executionId)).Result;
    }

    async Task<(JsonElement Result, string Stdout, string Stderr)> ExecuteWithOutput(string script, int timeoutMs, string? executionId = null) {
        string execution = executionId ?? Guid.NewGuid().ToString();
        var request = Request(script);
        request["executionId"] = execution;
        request["timeoutMs"] = timeoutMs;
        await Send(socket, request);
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        while (true) {
            var record = await WaitRecord(value => {
                if (!value.TryGetProperty("data", out var data)
                    || !data.TryGetProperty("executionId", out var id)
                    || id.GetString() != execution) return false;
                string? type = value.GetProperty("recordType").GetString();
                return type is "output_chunk" or "execution_finished" or "worker_stopped";
            });
            string type = record.GetProperty("recordType").GetString()!;
            var data = record.GetProperty("data");
            if (type == "output_chunk") {
                string text = data.GetProperty("text").GetString()!;
                if (data.GetProperty("stream").GetString() == "stdout") stdout.Append(text);
                else stderr.Append(text);
                continue;
            }
            if (type == "worker_stopped") {
                using var unknown = JsonDocument.Parse("""
                    {"state":"outcome_unknown","invocationOutcome":null,"exitCode":null,"exitCodeSource":null}
                    """);
                return (unknown.RootElement.Clone(), stdout.ToString(), stderr.ToString());
            }
            if (data.GetProperty("state").GetString() is "cancelled" or "timed_out" or "outcome_unknown"
                || data.GetProperty("invocationOutcome").GetString() == "explicit_exit")
                await WaitRecord(value => IsRecord(value, "worker_stopped", execution));
            return (data.Clone(), stdout.ToString(), stderr.ToString());
        }
    }

    bool IsRecord(JsonElement record, string type, string execution) =>
        record.GetProperty("recordType").GetString() == type
        && record.GetProperty("data").TryGetProperty("executionId", out var id)
        && id.GetString() == execution;

    async Task<JsonElement> WaitRecord(Func<JsonElement, bool> predicate) {
        while (true) {
            int queuedCount = queuedRecords.Count;
            for (int i = 0; i < queuedCount; i++) {
                var record = queuedRecords.Dequeue();
                if (predicate(record)) return record;
                queuedRecords.Enqueue(record);
            }
            var message = await Receive(socket);
            if (message.GetProperty("type").GetString() != "ledger_batch")
                throw new InvalidOperationException("Expected ledger_batch: " + message.GetRawText());
            var records = message.GetProperty("records").EnumerateArray().Select(record => record.Clone()).ToArray();
            long acknowledgedThrough = records.Max(record => record.GetProperty("sequence").GetInt64());
            await Send(socket, new {
                type = "ledger_ack",
                ledger_id = message.GetProperty("ledgerId").GetString(),
                acknowledged_through = acknowledgedThrough
            });
            JsonElement? matched = null;
            foreach (var record in records) {
                if (matched is null && predicate(record)) matched = record;
                else queuedRecords.Enqueue(record);
            }
            if (matched is not null) return matched.Value;
        }
    }

    async Task<JsonElement> WaitRecordWithoutAck(Func<JsonElement, bool> predicate) {
        while (true) {
            int queuedCount = queuedRecords.Count;
            for (int i = 0; i < queuedCount; i++) {
                var record = queuedRecords.Dequeue();
                if (predicate(record)) return record;
                queuedRecords.Enqueue(record);
            }
            var message = await Receive(socket);
            if (message.GetProperty("type").GetString() != "ledger_batch")
                throw new InvalidOperationException("Expected ledger_batch: " + message.GetRawText());
            var records = message.GetProperty("records").EnumerateArray().Select(record => record.Clone()).ToArray();
            if (records.Any(predicate)) return records.First(predicate);
            long acknowledgedThrough = records.Max(record => record.GetProperty("sequence").GetInt64());
            await Send(socket, new {
                type = "ledger_ack",
                ledger_id = message.GetProperty("ledgerId").GetString(),
                acknowledged_through = acknowledgedThrough
            });
            foreach (var record in records) queuedRecords.Enqueue(record);
        }
    }

    async Task<WebSocket> NextSocket() {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        return (await sockets.Reader.ReadAsync(deadline.Token)).Socket;
    }

    async Task<WebSocket> NextSocketAfter(int acceptedBefore) {
        using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(20));
        while (true) {
            var next = await sockets.Reader.ReadAsync(deadline.Token);
            if (next.Accepted > acceptedBefore) return next.Socket;
        }
    }
} finally {
    done.TrySetResult();
    if (!agent.HasExited) {
        try { await agent.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2)); }
        catch (TimeoutException) { agent.Kill(true); await agent.WaitForExitAsync(); }
    }
    await app.StopAsync();
    try { Directory.Delete(dataRoot, recursive: true); } catch { }
}

await EnrollmentScenario.Run(args[0], serverCert);

async Task RejectIdentity(string thumbprint, string pin) {
    int acceptedBefore = Volatile.Read(ref acceptedSockets);
    using var invalid = StartAgent(thumbprint, pin);
    try {
        await Task.Delay(TimeSpan.FromSeconds(5));
        Require(!invalid.HasExited && Volatile.Read(ref acceptedSockets) == acceptedBefore,
            "wrong endpoint identity/server pin cannot establish a dispatch channel");
    } finally {
        if (!invalid.HasExited) {
            invalid.Kill(true);
            await invalid.WaitForExitAsync();
        }
    }
}

Process StartAgent(string thumbprint, string? pin = null) => Process.Start(new ProcessStartInfo("dotnet") {
    UseShellExecute = false,
    Environment = {
        ["RMM_TEST_SECRET"] = "isolated-dummy-secret",
        ["RMM_ENDPOINT_LEDGER_CAPACITY_BYTES"] = "1400000",
        ["RMM_ENDPOINT_DATA_DIR"] = dataRoot,
    },
    ArgumentList = { args[0], "--agent", "wss://localhost:18443/agent", thumbprint,
        pin ?? Convert.ToHexString(SHA256.HashData(serverCert.RawData)).ToLowerInvariant(), "test-device" }
})!;

static X509Certificate2 Certificate(string thumbprint) {
    using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
    store.Open(OpenFlags.ReadOnly);
    return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false).Single();
}

static void Require(bool condition, string description) {
    if (!condition) throw new InvalidOperationException("FAIL: " + description);
}

static async Task Send(WebSocket socket, object value) =>
    await socket.SendAsync(JsonSerializer.SerializeToUtf8Bytes(value), WebSocketMessageType.Text, true, CancellationToken.None);

static async Task<JsonElement> Receive(WebSocket socket) {
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
    using var content = new MemoryStream();
    var buffer = new byte[8192];
    WebSocketReceiveResult frame;
    do {
        frame = await socket.ReceiveAsync(buffer, deadline.Token);
        if (frame.MessageType != WebSocketMessageType.Text) throw new InvalidOperationException("Unexpected connection close");
        content.Write(buffer, 0, frame.Count);
        if (content.Length > 5_000_000) throw new InvalidOperationException("Oversize message");
    } while (!frame.EndOfMessage);
    return JsonDocument.Parse(content.ToArray()).RootElement.Clone();
}
