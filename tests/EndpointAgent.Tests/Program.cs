using System.Reflection;
using System.Net.WebSockets;
using EndpointAgent;

var root = Path.Combine(Path.GetTempPath(), "rmm-endpoint-tests-" + Guid.NewGuid().ToString("N"));
Environment.SetEnvironmentVariable("RMM_ENDPOINT_DATA_DIR", root);
try {
    Directory.CreateDirectory(root);
    RetransmitsUnacknowledgedTerminalBatch();
    await PrunesAcknowledgedClosedRecordsFromMemoryAndStartup();
    await ReconnectDoesNotRefreshExistingSessionDeadline();
    await WorkerProcessStartsNativeWorkerOnWindows();
    Console.WriteLine("EndpointAgent.Tests passed");
    return 0;
} finally {
    try { if (Directory.Exists(root)) Directory.Delete(root, recursive: true); }
    catch (IOException) { }
    catch (UnauthorizedAccessException) { }
}

static void RetransmitsUnacknowledgedTerminalBatch() {
    var ledger = new EndpointLedger("test-device-retransmit");
    string session = Guid.NewGuid().ToString();
    string execution = Guid.NewGuid().ToString();
    string scriptHash = new string('a', 64);
    ledger.SessionStarted(session);
    Assert(ledger.TryExecutionAccepted(session, execution, scriptHash), "execution accepted once");
    ledger.ExecutionStarted(session, execution, scriptHash);
    ledger.OutputChunk(session, execution, scriptHash, "stdout", "first\n");
    ledger.ExecutionFinished(session, execution, scriptHash, new WorkerResult(
        "completed", "completed_normally", 0, "normalized_invocation", false, 1.0, false, null));

    var first = ledger.PendingBatch();
    var second = ledger.PendingBatch();
    Assert(first.Count == second.Count, "dropped ack does not advance pending cursor");
    Assert(first.Select(record => record.Sequence).SequenceEqual(second.Select(record => record.Sequence)),
        "dropped ack retransmits the same records");
    Assert(first.Count(record => record.RecordType == "output_chunk") == 1, "one output record retained");
    Assert(first.Count(record => record.RecordType == "execution_finished") == 1, "one terminal record retained");

    ledger.Acknowledge(ledger.LedgerId, first[^1].Sequence);
    Assert(ledger.PendingBatch().Count == 0, "acknowledged records are not resent");
}

static async Task PrunesAcknowledgedClosedRecordsFromMemoryAndStartup() {
    var ledger = new EndpointLedger("test-device-prune");
    string session = Guid.NewGuid().ToString();
    ledger.SessionStarted(session);
    ledger.SessionClosed(session);
    var batch = ledger.PendingBatch();
    ledger.Acknowledge(ledger.LedgerId, batch[^1].Sequence);
    await WaitForRecordCount(ledger, 0);
    ledger.Acknowledge(ledger.LedgerId, batch[^1].Sequence);
    Assert(ledger.AcknowledgedThrough == batch[^1].Sequence,
        "duplicate ack after pruning does not move checkpoint backwards");

    var restarted = new EndpointLedger("test-device-prune");
    await WaitForRecordCount(restarted, 0);
    string ledgerRoot = (string)PrivateField(restarted, "root").GetValue(restarted)!;
    Assert(ledgerRoot.StartsWith(EndpointPaths.DataDirectory, StringComparison.Ordinal),
        "ledger lives under service data directory");
}

static async Task WorkerProcessStartsNativeWorkerOnWindows() {
    if (!OperatingSystem.IsWindows()) {
        Console.WriteLine("WorkerProcess smoke skipped: Windows-only");
        return;
    }
    await using var worker = await WorkerProcess.Start();
    var output = new List<string>();
    var first = await worker.Execute("$global:workerSmoke = 41", (stream, text) => {
        output.Add(stream + ":" + text);
        return Task.CompletedTask;
    }, CancellationToken.None, () => "cancelled");
    Assert(first.State == "completed" && first.ExitCode == 0, "first worker invocation completed");
    var second = await worker.Execute("$global:workerSmoke + 1", (stream, text) => {
        output.Add(stream + ":" + text);
        return Task.CompletedTask;
    }, CancellationToken.None, () => "cancelled");
    Assert(second.State == "completed" && output.Any(value => value.Contains("42")),
        "worker preserves PowerShell state across invocations");
}

static async Task ReconnectDoesNotRefreshExistingSessionDeadline() {
    var state = new AgentRuntimeState("test-device-deadline");
    string session = Guid.NewGuid().ToString();
    state.Ledger.SessionStarted(session);
    var batch = state.Ledger.PendingBatch();
    state.Ledger.Acknowledge(state.Ledger.LedgerId, batch[^1].Sequence);
    var originalDeadline = DateTimeOffset.UtcNow.AddSeconds(30);
    state.SessionDeadline = originalDeadline;

    await AgentRuntime.Run(new ClosedWebSocket(), "test-device-deadline", sendHeartbeats: false, state);

    Assert(state.SessionDeadline == originalDeadline, "reconnect does not refresh active session deadline");
}

static async Task WaitForRecordCount(EndpointLedger ledger, int expected) {
    var field = PrivateField(ledger, "records");
    for (int attempt = 0; attempt < 100; attempt++) {
        var records = (System.Collections.ICollection)field.GetValue(ledger)!;
        if (records.Count == expected) return;
        await Task.Delay(25);
    }
    var finalRecords = (System.Collections.ICollection)field.GetValue(ledger)!;
    throw new InvalidOperationException($"expected {expected} records, found {finalRecords.Count}");
}

static FieldInfo PrivateField(object target, string name) =>
    target.GetType().GetField(name, BindingFlags.Instance | BindingFlags.NonPublic)
    ?? throw new MissingFieldException(target.GetType().Name, name);

static void Assert(bool condition, string message) {
    if (!condition) throw new InvalidOperationException(message);
}

sealed class ClosedWebSocket : WebSocket {
    public override WebSocketCloseStatus? CloseStatus => WebSocketCloseStatus.NormalClosure;
    public override string? CloseStatusDescription => null;
    public override WebSocketState State => WebSocketState.Closed;
    public override string? SubProtocol => null;
    public override void Abort() { }
    public override Task CloseAsync(WebSocketCloseStatus closeStatus, string? statusDescription,
                                    CancellationToken cancellationToken) => Task.CompletedTask;
    public override Task CloseOutputAsync(WebSocketCloseStatus closeStatus, string? statusDescription,
                                          CancellationToken cancellationToken) => Task.CompletedTask;
    public override void Dispose() { }
    public override Task<WebSocketReceiveResult> ReceiveAsync(ArraySegment<byte> buffer,
                                                              CancellationToken cancellationToken) =>
        throw new NotSupportedException();
    public override Task SendAsync(ArraySegment<byte> buffer, WebSocketMessageType messageType,
                                   bool endOfMessage, CancellationToken cancellationToken) =>
        throw new NotSupportedException();
}
