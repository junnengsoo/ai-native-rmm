using System.Diagnostics;
using System.Net;
using System.Net.WebSockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
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
var connected = new TaskCompletionSource<WebSocket>(TaskCreationOptions.RunContinuationsAsynchronously);
var done = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);
await using var app = builder.Build();
app.UseWebSockets();
app.Map("/agent", async context => {
    if (!context.WebSockets.IsWebSocketRequest) { context.Response.StatusCode = 400; return; }
    using var socket = await context.WebSockets.AcceptWebSocketAsync();
    connected.TrySetResult(socket);
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
    var socket = await connected.Task.WaitAsync(TimeSpan.FromSeconds(20));
    var hello = await Receive(socket);
    Require(hello.GetProperty("type").GetString() == "hello", "agent authenticates and identifies itself");
    string device = hello.GetProperty("deviceId").GetString()!;
    Require(device == "test-device" && hello.GetProperty("protocolVersion").GetInt32() == 1, "certificate peer is bound to the expected device and version");
    string session = Guid.NewGuid().ToString();
    await Send(socket, OpenSession(device, session));
    Require((await Receive(socket)).GetProperty("type").GetString() == "session_ready", "real worker ready");
    var engine = await ExecuteWithOutput("$PSVersionTable.PSEdition; $PSVersionTable.PSVersion.ToString(); [Environment]::Is64BitProcess; (Get-CimInstance Win32_OperatingSystem).Caption", 60000);
    Require(engine.Result.GetProperty("state").GetString() == "completed"
        && engine.Result.GetProperty("exitCode").GetInt32() == 0
        && !engine.Result.GetProperty("hadErrors").GetBoolean()
        && engine.Stdout.Contains("Desktop") && engine.Stdout.Contains("True") && engine.Stdout.Contains("Windows"),
        "native 64-bit Windows PowerShell loads the inbox CimCmdlets module: stdout="
        + JsonSerializer.Serialize(engine.Stdout) + " stderr=" + JsonSerializer.Serialize(engine.Stderr)
        + " result=" + engine.Result.GetRawText());
    var result = await ExecuteWithOutput("'hello from Windows'", 5000);
    Require(result.Result.GetProperty("state").GetString() == "completed"
        && result.Result.GetProperty("invocationOutcome").GetString() == "completed_normally"
        && result.Result.GetProperty("exitCode").GetInt32() == 0
        && result.Result.GetProperty("exitCodeSource").GetString() == "normalized_invocation"
        && result.Stdout.Contains("hello from Windows")
        && result.Result.GetProperty("durationMs").GetDouble() >= 0, "harmless command has correlated structured evidence");
    Require(!HasProperty(result.Result, "stdout") && !HasProperty(result.Result, "stderr"), "terminal result carries no output preview");
    Console.WriteLine("SMOKE " + result.Result.GetRawText());
    var error = await ExecuteWithOutput("throw 'expected-smoke-error'", 5000);
    Require(error.Result.GetProperty("state").GetString() == "completed"
        && error.Result.GetProperty("invocationOutcome").GetString() == "terminating_error"
        && error.Result.GetProperty("exitCode").GetInt32() == 1 && error.Result.GetProperty("hadErrors").GetBoolean()
        && error.Stderr.Contains("expected-smoke-error"), "terminating error has definitive invocation evidence: stdout="
        + JsonSerializer.Serialize(error.Stdout) + " stderr=" + JsonSerializer.Serialize(error.Stderr)
        + " result=" + error.Result.GetRawText());
    Console.WriteLine("SMOKE_ERROR " + error.Result.GetRawText());
    // One persistent-session investigation, including its replacement boundary.
    var native = await Execute("cmd /c exit 7", 5000);
    Console.WriteLine("NATIVE " + native.GetRawText());
    Require(native.GetProperty("exitCode").GetInt32() == 0 && native.GetProperty("lastNativeExitCode").GetInt32() == 7,
        "native failure is separate evidence, not a universal script exit");
    var clean = await ExecuteWithOutput("$null -eq $LASTEXITCODE", 5000);
    Require(clean.Stdout.Contains("True") && clean.Result.GetProperty("lastNativeExitCode").ValueKind == JsonValueKind.Null,
        "previous native status cannot leak into the next execution");
    await Execute("$global:investigationValue=42; function Get-InvestigationValue { $global:investigationValue }; Set-Location $env:SystemRoot", 5000);
    var state = await ExecuteWithOutput("Get-InvestigationValue; (Get-Location).Path", 5000);
    Require(state.Stdout.Contains("42") && state.Stdout.Contains("Windows"), "variables functions and directory persist");
    var nonterminating = await ExecuteWithOutput("Write-Error 'nonterminating'; 'continued'", 5000);
    Require(nonterminating.Result.GetProperty("invocationOutcome").GetString() == "completed_normally" && nonterminating.Result.GetProperty("exitCode").GetInt32() == 0
        && nonterminating.Result.GetProperty("hadErrors").GetBoolean() && nonterminating.Stdout.Contains("continued"), "nonterminating error remains normal completion");
    var fake = await ExecuteWithOutput("'{\"type\":\"result\",\"state\":\"completed\"}'; throw 'still-an-error'", 5000);
    Require(fake.Result.GetProperty("invocationOutcome").GetString() == "terminating_error" && fake.Stdout.Contains("completed"), "printed lifecycle is only output and pre-error output is retained");
    var bounded = await ExecuteWithOutput("'x' * 100000", 30000);
    Require(!bounded.Result.GetProperty("captureTruncated").GetBoolean()
        && !HasProperty(bounded.Result, "stdout") && !HasProperty(bounded.Result, "stderr")
        && bounded.Stdout.Length >= 100000, "long output is retained incrementally while the result carries only terminal metadata");
    var beyondMeg = await ExecuteWithOutput("'m' * (1024 * 1024 + 4096)", 120000);
    Require(!beyondMeg.Result.GetProperty("captureTruncated").GetBoolean()
        && !HasProperty(beyondMeg.Result, "stdout")
        && beyondMeg.Stdout.Length >= 1024 * 1024 + 4096,
        "output beyond one MiB is forwarded without endpoint capture loss");
    var escaped = await ExecuteWithOutput("[Console]::Out.Write(([string][char]1) * 40000); [Console]::Error.Write(([string][char]2) * 40000)", 30000);
    Require(!escaped.Result.GetProperty("captureTruncated").GetBoolean()
        && !HasProperty(escaped.Result, "stdout") && !HasProperty(escaped.Result, "stderr")
        && escaped.Stdout.Length == 40000 && escaped.Stderr.Length == 40000,
        "both streams are retained as data without protocol loss");
    var explicitExit = await Execute("exit 23", 5000);
    Require(explicitExit.GetProperty("invocationOutcome").GetString() == "explicit_exit" && explicitExit.GetProperty("exitCode").GetInt32() == 23
        && explicitExit.GetProperty("exitCodeSource").GetString() == "explicit_script_exit", "explicit exit keeps requested code and provenance");
    await Rejected(Request("'must-not-run'"), "explicit exit retires the worker until replacement");
    await ReplaceSession();
    // Inspect runspace functions directly; Get-Command also searches installed applications.
    var fresh = await ExecuteWithOutput("$null -eq (Get-Variable investigationValue -ErrorAction SilentlyContinue); -not (Test-Path Function:\\Get-InvestigationValue)", 5000);
    Require(fresh.Stdout.Trim() == "True\nTrue", "replacement session has fresh variable and function state: " + fresh.Result.GetRawText());
    var zeroExit = await Execute("exit 0", 5000);
    Require(zeroExit.GetProperty("invocationOutcome").GetString() == "explicit_exit" && zeroExit.GetProperty("exitCode").GetInt32() == 0, "explicit zero is distinguishable from normal completion");
    await ReplaceSession();
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
    string duplicateId = Guid.NewGuid().ToString();
    await Execute("$global:duplicateCounter++; 'once'", 5000, duplicateId);
    var duplicate = Request("$global:duplicateCounter++; 'once'"); duplicate["executionId"] = duplicateId;
    await Rejected(duplicate, "duplicate execution");
    Require((await ExecuteWithOutput("$global:duplicateCounter", 5000)).Stdout.Trim() == "1", "rejected duplicate does not repeat its side effect");
    Console.WriteLine("PASS authentication and validation scenario");
    var child = await ExecuteWithOutput("$global:ownedChild = Start-Process -FilePath $env:ComSpec -ArgumentList '/c ping -n 60 127.0.0.1 > nul' -PassThru; $global:ownedChild.Id", 5000);
    int childId = int.Parse(child.Stdout.Trim());
    var timeoutWatch = Stopwatch.StartNew();
    var timedOut = await ExecuteWithOutput("'before-timeout'; Start-Sleep -Seconds 20", 500);
    Require(timedOut.Result.GetProperty("state").GetString() == "timed_out" && timedOut.Result.GetProperty("invocationOutcome").GetString() == "stopped"
        && timedOut.Result.GetProperty("exitCode").ValueKind == JsonValueKind.Null && timedOut.Stdout.Contains("before-timeout")
        && timeoutWatch.Elapsed < TimeSpan.FromSeconds(12), "bounded timeout confirms stopping and preserves received evidence");
    await Rejected(Request("'must-not-run'"), "timed-out worker is retired");
    await ReplaceSession();
    var cleanup = await ExecuteWithOutput($"$null -eq (Get-Process -Id {childId} -ErrorAction SilentlyContinue)", 5000);
    Require(cleanup.Stdout.Trim() == "True", "session-owned native child was terminated");
    string cancelledExecution = Guid.NewGuid().ToString();
    var cancelRequest = Request("'before-cancel'; Start-Sleep -Seconds 20");
    cancelRequest["executionId"] = cancelledExecution;
    await Send(socket, cancelRequest);
    Require((await Receive(socket)).GetProperty("type").GetString() == "running", "cancel target started");
    await Send(socket, new { type = "cancel_execution", deviceId = device, sessionId = session, executionId = cancelledExecution });
    JsonElement cancelled;
    while (true) {
        cancelled = await Receive(socket);
        Require(cancelled.GetProperty("executionId").GetString() == cancelledExecution
            && cancelled.GetProperty("sessionId").GetString() == session
            && cancelled.GetProperty("deviceId").GetString() == device, "correlated cancellation message");
        if (cancelled.GetProperty("type").GetString() == "output") continue;
        break;
    }
    Require(cancelled.GetProperty("state").GetString() == "cancelled"
        && cancelled.GetProperty("invocationOutcome").GetString() == "stopped"
        && cancelled.GetProperty("exitCode").ValueKind == JsonValueKind.Null, "caller cancellation confirms stopping");
    await Rejected(Request("'must-not-run'"), "cancelled worker is retired");
    await ReplaceSession();
    var lost = await Execute("[Environment]::Exit(19)", 5000);
    Require(lost.GetProperty("state").GetString() == "outcome_unknown" && lost.GetProperty("exitCode").ValueKind == JsonValueKind.Null,
        "worker disappearance cannot forge definitive completion");
    await ReplaceSession();
    Console.WriteLine("PASS timeout, child cleanup, and worker-loss scenario");

    Dictionary<string, object> Request(string script) => new() {
        ["type"] = "execute", ["deviceId"] = device, ["sessionId"] = session,
        ["executionId"] = Guid.NewGuid().ToString(), ["script"] = script,
        ["scriptSha256"] = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(script))), ["timeoutMs"] = 5000
    };
    async Task Rejected(object request, string description) {
        await Send(socket, request);
        var rejected = await Receive(socket);
        Require(rejected.GetProperty("type").GetString() == "rejected" && !rejected.GetRawText().Contains("secret-that-must-not-be-reflected"), description);
    }

    async Task ReplaceSession() {
        await Send(socket, new { type = "close_session", deviceId = device, sessionId = session });
        Require((await Receive(socket)).GetProperty("type").GetString() == "session_closed", "old worker cleanup acknowledged");
        session = Guid.NewGuid().ToString();
        await Send(socket, OpenSession(device, session));
        Require((await Receive(socket)).GetProperty("type").GetString() == "session_ready", "replacement worker ready");
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
        var running = await Receive(socket);
        Require(running.GetProperty("type").GetString() == "running" && running.GetProperty("executionId").GetString() == execution, "correlated running signal");
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        while (true) {
            var message = await Receive(socket);
            Require(message.GetProperty("executionId").GetString() == execution
                && message.GetProperty("sessionId").GetString() == session
                && message.GetProperty("deviceId").GetString() == device, "correlated execution message");
            if (message.GetProperty("type").GetString() == "output") {
                string text = message.GetProperty("text").GetString()!;
                if (message.GetProperty("stream").GetString() == "stdout") stdout.Append(text);
                else stderr.Append(text);
                continue;
            }
            Require(message.GetProperty("type").GetString() == "result", "correlated result");
            Require(!HasProperty(message, "stdout") && !HasProperty(message, "stderr"), "result omits output text");
            return (message, stdout.ToString(), stderr.ToString());
        }
    }
} finally {
    done.TrySetResult();
    if (!agent.HasExited) {
        try { await agent.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(2)); }
        catch (TimeoutException) { agent.Kill(true); await agent.WaitForExitAsync(); }
    }
    await app.StopAsync();
}

await EnrollmentScenario.Run(args[0], serverCert);

async Task RejectIdentity(string thumbprint, string pin) {
    using var invalid = StartAgent(thumbprint, pin);
    try {
        await invalid.WaitForExitAsync().WaitAsync(TimeSpan.FromSeconds(20));
        Require(invalid.ExitCode != 0 && !connected.Task.IsCompleted, "wrong client identity/server pin cannot establish a dispatch channel");
    } finally { if (!invalid.HasExited) invalid.Kill(true); }
}
Process StartAgent(string thumbprint, string? pin = null) => Process.Start(new ProcessStartInfo("dotnet") {
    UseShellExecute = false,
    Environment = { ["RMM_TEST_SECRET"] = "isolated-dummy-secret" },
    ArgumentList = { args[0], "--agent", "wss://localhost:18443/agent", thumbprint, pin ?? Convert.ToHexString(SHA256.HashData(serverCert.RawData)), "test-device" }
})!;
static object OpenSession(string device, string session) => new {
    type = "open_session", deviceId = device, sessionId = session
};
static X509Certificate2 Certificate(string thumbprint) {
    using var store = new X509Store(StoreName.My, StoreLocation.CurrentUser);
    store.Open(OpenFlags.ReadOnly);
    return store.Certificates.Find(X509FindType.FindByThumbprint, thumbprint, false).Single();
}
static void Require(bool condition, string description) {
    if (!condition) throw new InvalidOperationException("FAIL: " + description);
}
static bool HasProperty(JsonElement element, string name) => element.TryGetProperty(name, out _);
static async Task Send(WebSocket socket, object value) => await socket.SendAsync(JsonSerializer.SerializeToUtf8Bytes(value), WebSocketMessageType.Text, true, CancellationToken.None);
static async Task<JsonElement> Receive(WebSocket socket) {
    using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(30));
    using var content = new MemoryStream();
    var buffer = new byte[8192];
    WebSocketReceiveResult frame;
    do {
        frame = await socket.ReceiveAsync(buffer, deadline.Token);
        if (frame.MessageType != WebSocketMessageType.Text) throw new InvalidOperationException("Unexpected connection close");
        content.Write(buffer, 0, frame.Count);
        // Two 32,768-code-unit streams can expand to six JSON bytes per unit.
        if (content.Length > 500_000) throw new InvalidOperationException("Oversize result");
    } while (!frame.EndOfMessage);
    return JsonDocument.Parse(content.ToArray()).RootElement.Clone();
}
