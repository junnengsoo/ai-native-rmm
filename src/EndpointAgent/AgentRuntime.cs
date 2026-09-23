using System.Net.WebSockets;
using System.Text.Json;

namespace EndpointAgent;

internal static class AgentRuntime {
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private static readonly TimeSpan FrameReceiveLimit = TimeSpan.FromMinutes(2);
    private static readonly TimeSpan SessionTimeout = ConfiguredSessionTimeout();

    private sealed class RuntimeFrame {
        public WorkerProcess? Worker { get; set; }
        public string? Session { get; set; }
        public string? CurrentExecution { get; set; }
        public string? CurrentScriptHash { get; set; }
        public Task<(string Session, string Execution, string ScriptSha256, WorkerResult Result)>? Invocation { get; set; }
        public CancellationTokenSource? InvocationStop { get; set; }
        public string InvocationStopReason { get; set; } = "cancelled";
        public bool CloseAfterInvocation { get; set; }
        public DateTimeOffset? SessionDeadline { get; set; }
    }

    private sealed class LedgerTransport {
        private readonly SemaphoreSlim sendLock = new(1, 1);
        private readonly object gate = new();
        private long inFlightThrough;

        public SemaphoreSlim SendLock => sendLock;

        public async Task SendPending(WebSocket socket, EndpointLedger ledger, string device) {
            IReadOnlyList<LedgerRecord> batch;
            long batchThrough;
            lock (gate) {
                if (inFlightThrough > ledger.AcknowledgedThrough) return;
                batch = ledger.PendingBatch();
                if (batch.Count == 0) return;
                batchThrough = batch[^1].Sequence;
                inFlightThrough = batchThrough;
            }
            try {
                await Send(socket, sendLock, new {
                    type = "ledger_batch",
                    deviceId = device,
                    ledgerId = ledger.LedgerId,
                    records = batch,
                });
            } catch {
                lock (gate) {
                    if (inFlightThrough == batchThrough) inFlightThrough = 0;
                }
                throw;
            }
        }

        public void ObserveAck(EndpointLedger ledger) {
            lock (gate) {
                if (inFlightThrough <= ledger.AcknowledgedThrough) inFlightThrough = 0;
            }
        }
    }

    public static async Task Run(WebSocket socket, string device, bool sendHeartbeats, AgentRuntimeState state) {
        var ledger = state.Ledger;
        var frame = new RuntimeFrame {
            Worker = state.Worker,
            Session = ledger.Snapshot.SessionId,
            CurrentExecution = ledger.Snapshot.ExecutionId,
            CurrentScriptHash = ledger.Snapshot.ScriptSha256,
            Invocation = state.Invocation,
            InvocationStop = state.InvocationStop,
            SessionDeadline = state.SessionDeadline,
        };
        EnsureSessionDeadline(frame, state);
        Task<JsonElement>? incoming = null;
        using var stopped = new CancellationTokenSource();
        var transport = new LedgerTransport();
        Task heartbeats = sendHeartbeats ? Heartbeats(socket, transport.SendLock, stopped.Token) : Task.CompletedTask;
        try {
            await TrySendPendingLedger(socket, transport, ledger, device);
            while (socket.State == WebSocketState.Open) {
                await TrySendPendingLedger(socket, transport, ledger, device);
                if (SessionExpired(frame)) {
                    await ExpireSession(socket, transport, ledger, device, frame, state);
                    incoming = null;
                    continue;
                }
                if (frame.Invocation is not null) {
                    incoming ??= Receive(socket, ReceiveWait(frame));
                    var ready = await Task.WhenAny(incoming, frame.Invocation);
                    if (ready == frame.Invocation) {
                        var completed = await frame.Invocation;
                        await FinalizeCompletedInvocation(ledger, completed, frame, state);
                        await TrySendPendingLedger(socket, transport, ledger, device);
                    } else {
                        try {
                            var message = await incoming;
                            await HandleMessage(socket, transport, ledger, device, message, frame, state);
                        } catch (JsonException) {
                            await Reject(socket, transport.SendLock, device, "invalid_request");
                        } catch (OperationCanceledException) {
                            if (SessionExpired(frame))
                                await ExpireSession(socket, transport, ledger, device, frame, state);
                        } finally {
                            incoming = null;
                        }
                    }
                    continue;
                }

                incoming ??= Receive(socket, ReceiveWait(frame));
                try {
                    var message = await incoming;
                    await HandleMessage(socket, transport, ledger, device, message, frame, state);
                } catch (JsonException) {
                    await Reject(socket, transport.SendLock, device, "invalid_request");
                } catch (OperationCanceledException) {
                    if (SessionExpired(frame))
                        await ExpireSession(socket, transport, ledger, device, frame, state);
                } finally {
                    incoming = null;
                }
            }
        } finally {
            stopped.Cancel();
            try { await heartbeats; }
            catch (Exception error) when (error is OperationCanceledException or WebSocketException) { }
        }
    }

    private static async Task HandleMessage(WebSocket socket, LedgerTransport transport, EndpointLedger ledger,
                                            string device, JsonElement message, RuntimeFrame frame,
                                            AgentRuntimeState state) {
        if (TryApplyAck(ledger, transport, message)) return;
        if (message.TryGetProperty("type", out var typeElement)
            && typeElement.ValueKind == JsonValueKind.String
            && typeElement.GetString() == "heartbeat_ack") return;

        Dispatch? request;
        try { request = Dispatch.Parse(message, device); }
        catch (JsonException) { request = null; }
        if (request is null) {
            await Reject(socket, transport.SendLock, device, "invalid_request");
            return;
        }
        if (ledger.HasUnacknowledgedRecords && (request.Type is "open_session" or "execute")) {
            await Reject(socket, transport.SendLock, device, "reconciliation_pending", request);
            return;
        }

        if (request.Type == "open_session" && frame.Worker is null && frame.Invocation is null) {
            frame.Worker = await WorkerProcess.Start();
            state.Worker = frame.Worker;
            frame.Session = request.SessionId;
            ledger.SessionStarted(frame.Session);
            RefreshSessionDeadline(frame, state);
            await TrySendPendingLedger(socket, transport, ledger, device);
        } else if (request.Type == "close_session" && request.SessionId == frame.Session && frame.Invocation is null) {
            bool cleaned = await Cleanup(frame.Worker);
            if (cleaned) ledger.SessionClosed(request.SessionId);
            else ledger.WorkerStopped(request.SessionId, null, null, "cleanup_unconfirmed", false);
            frame.Worker = null;
            state.Worker = null;
            frame.Session = null;
            frame.SessionDeadline = null;
            state.SessionDeadline = null;
            await TrySendPendingLedger(socket, transport, ledger, device);
        } else if (request.Type == "close_session" && request.SessionId == frame.Session && frame.Invocation is not null) {
            frame.CloseAfterInvocation = true;
            frame.InvocationStopReason = "cancelled";
            frame.InvocationStop?.Cancel();
        } else if (request.Type == "execute" && frame.Worker is not null && frame.Worker.IsUsable && frame.Invocation is null
                   && request.SessionId == frame.Session) {
            string execution = request.ExecutionId!;
            string scriptHash = request.ScriptSha256!;
            if (!ledger.TryExecutionAccepted(frame.Session!, execution, scriptHash)) {
                await Reject(socket, transport.SendLock, device, "invalid_state_or_duplicate", request);
                return;
            }
            frame.InvocationStop = new CancellationTokenSource();
            state.InvocationStop = frame.InvocationStop;
            frame.CurrentExecution = execution;
            frame.CurrentScriptHash = scriptHash;
            frame.CloseAfterInvocation = false;
            frame.InvocationStopReason = "cancelled";
            RefreshSessionDeadline(frame, state);
            ArmInvocationDeadline(frame);
            frame.Invocation = CompleteAndLedger(socket, transport, ledger, device, frame.Worker, frame.Session!, execution,
                scriptHash, request.Script!, frame.InvocationStop.Token, () => CancellationState(frame));
            state.Invocation = frame.Invocation;
            await TrySendPendingLedger(socket, transport, ledger, device);
        } else if (request.Type == "cancel_execution" && request.SessionId == frame.Session
                   && request.ExecutionId == frame.CurrentExecution && frame.CurrentScriptHash is not null) {
            ledger.CancellationRequested(request.SessionId, request.ExecutionId!, frame.CurrentScriptHash);
            await TrySendPendingLedger(socket, transport, ledger, device);
            frame.InvocationStopReason = "cancelled";
            frame.InvocationStop?.Cancel();
        } else {
            await Reject(socket, transport.SendLock, device, "invalid_state_or_duplicate", request);
        }
    }

    private static async Task<(string Session, string Execution, string ScriptSha256, WorkerResult Result)> CompleteAndLedger(
        WebSocket socket, LedgerTransport transport, EndpointLedger ledger, string device, WorkerProcess worker,
        string session, string execution, string scriptSha256, string script, CancellationToken cancellation,
        Func<string> cancellationState) {
        ledger.ExecutionStarted(session, execution, scriptSha256);
        await TrySendPendingLedger(socket, transport, ledger, device);
        var result = await worker.Execute(script, async (stream, text) => {
            ledger.OutputChunk(session, execution, scriptSha256, stream, text);
            await TrySendPendingLedger(socket, transport, ledger, device);
        }, cancellation, cancellationState);
        if (result.State == "outcome_unknown")
            ledger.WorkerStopped(session, execution, scriptSha256, "worker_result_unknown",
                result.CleanupConfirmed is true, result.CaptureTruncated);
        else {
            ledger.ExecutionFinished(session, execution, scriptSha256, result);
            if (InvocationRetiresWorker(result))
                ledger.WorkerStopped(session, execution, scriptSha256, WorkerStopReason(result),
                    result.CleanupConfirmed is true, result.CaptureTruncated);
        }
        return (session, execution, scriptSha256, result);
    }

    private static bool TryApplyAck(EndpointLedger ledger, LedgerTransport transport, JsonElement message) {
        if (!message.TryGetProperty("type", out var typeElement)
            || typeElement.ValueKind != JsonValueKind.String
            || typeElement.GetString() != "ledger_ack") return false;
        string? ledgerId = message.TryGetProperty("ledger_id", out var id) ? id.GetString() : null;
        if (ledgerId is null && message.TryGetProperty("ledgerId", out var camelId)) ledgerId = camelId.GetString();
        if (ledgerId is null || !message.TryGetProperty("acknowledged_through", out var ack)) return true;
        ledger.Acknowledge(ledgerId, ack.GetInt64());
        transport.ObserveAck(ledger);
        return true;
    }

    private static async Task TrySendPendingLedger(WebSocket socket, LedgerTransport transport,
                                                   EndpointLedger ledger, string device) {
        try { await transport.SendPending(socket, ledger, device); }
        catch (Exception error) when (error is WebSocketException or OperationCanceledException or ObjectDisposedException) { }
    }

    private static async Task<bool> Cleanup(WorkerProcess? worker) {
        if (worker is null) return true;
        try {
            await worker.DisposeAsync();
            return true;
        } catch (InvalidOperationException) {
            return false;
        }
    }

    private static async Task FinalizeCompletedInvocation(EndpointLedger ledger,
        (string Session, string Execution, string ScriptSha256, WorkerResult Result) completed,
        RuntimeFrame frame, AgentRuntimeState state) {
        frame.Invocation = null;
        state.Invocation = null;
        state.InvocationStop?.Dispose();
        state.InvocationStop = null;
        frame.InvocationStop = null;
        frame.CurrentExecution = null;
        frame.CurrentScriptHash = null;
        if (completed.Result.State == "outcome_unknown") {
            await Cleanup(frame.Worker);
            frame.Worker = null;
            state.Worker = null;
            frame.Session = null;
            frame.SessionDeadline = null;
            state.SessionDeadline = null;
            frame.CloseAfterInvocation = false;
        } else if (frame.CloseAfterInvocation) {
            bool cleaned = completed.Result.CleanupConfirmed ?? await Cleanup(frame.Worker);
            if (cleaned) ledger.SessionClosed(completed.Session);
            else if (!InvocationRetiresWorker(completed.Result)) ledger.WorkerStopped(completed.Session, completed.Execution, completed.ScriptSha256,
                "cleanup_unconfirmed", false, completed.Result.CaptureTruncated);
            frame.Worker = null;
            state.Worker = null;
            frame.Session = null;
            frame.SessionDeadline = null;
            state.SessionDeadline = null;
            frame.CloseAfterInvocation = false;
        } else if (completed.Result.State is "cancelled" or "timed_out"
            || completed.Result.InvocationOutcome == "explicit_exit"
            || frame.Worker is { IsUsable: false }) {
            if (!InvocationRetiresWorker(completed.Result)) {
                bool cleaned = await Cleanup(frame.Worker);
                ledger.WorkerStopped(completed.Session, completed.Execution, completed.ScriptSha256,
                    WorkerStopReason(completed.Result), cleaned, completed.Result.CaptureTruncated);
            }
            frame.Worker = null;
            state.Worker = null;
            frame.Session = null;
            frame.SessionDeadline = null;
            state.SessionDeadline = null;
            frame.CloseAfterInvocation = false;
        } else {
            RefreshSessionDeadline(frame, state);
        }
    }

    private static async Task ExpireSession(WebSocket socket, LedgerTransport transport, EndpointLedger ledger,
                                            string device, RuntimeFrame frame, AgentRuntimeState state) {
        if (frame.Session is null) return;
        if (frame.Invocation is not null) {
            frame.InvocationStopReason = "timed_out";
            frame.InvocationStop?.Cancel();
            var completed = await frame.Invocation;
            await FinalizeCompletedInvocation(ledger, completed, frame, state);
        } else {
            string session = frame.Session;
            bool cleaned = await Cleanup(frame.Worker);
            if (cleaned) ledger.SessionClosed(session);
            else ledger.WorkerStopped(session, null, null, "session_timeout_cleanup_unconfirmed", false);
            frame.Worker = null;
            state.Worker = null;
            frame.Session = null;
            frame.SessionDeadline = null;
            state.SessionDeadline = null;
            frame.CloseAfterInvocation = false;
        }
        await TrySendPendingLedger(socket, transport, ledger, device);
    }

    private static void EnsureSessionDeadline(RuntimeFrame frame, AgentRuntimeState state) {
        if (frame.Session is null) {
            frame.SessionDeadline = null;
            state.SessionDeadline = null;
        } else if (frame.SessionDeadline is null) {
            RefreshSessionDeadline(frame, state);
        }
    }

    private static void RefreshSessionDeadline(RuntimeFrame frame, AgentRuntimeState state) {
        frame.SessionDeadline = frame.Session is null ? null : DateTimeOffset.UtcNow + SessionTimeout;
        state.SessionDeadline = frame.SessionDeadline;
    }

    private static void ArmInvocationDeadline(RuntimeFrame frame) {
        if (frame.InvocationStop is null || frame.SessionDeadline is not { } deadline) return;
        var remaining = deadline - DateTimeOffset.UtcNow;
        if (remaining <= TimeSpan.Zero) frame.InvocationStop.Cancel();
        else frame.InvocationStop.CancelAfter(remaining);
    }

    private static string CancellationState(RuntimeFrame frame) =>
        SessionExpired(frame) ? "timed_out" : frame.InvocationStopReason;

    private static bool InvocationRetiresWorker(WorkerResult result) =>
        result.State is "cancelled" or "timed_out" or "outcome_unknown"
        || result.InvocationOutcome == "explicit_exit";

    private static string WorkerStopReason(WorkerResult result) =>
        result.InvocationOutcome == "explicit_exit" ? "explicit_exit" : result.State;

    private static bool SessionExpired(RuntimeFrame frame) =>
        frame.SessionDeadline is { } deadline && DateTimeOffset.UtcNow >= deadline;

    private static TimeSpan ReceiveWait(RuntimeFrame frame) {
        if (frame.SessionDeadline is not { } deadline) return FrameReceiveLimit;
        var remaining = deadline - DateTimeOffset.UtcNow;
        if (remaining <= TimeSpan.Zero) return TimeSpan.Zero;
        return remaining < FrameReceiveLimit ? remaining : FrameReceiveLimit;
    }

    private static TimeSpan ConfiguredSessionTimeout() {
        string? configured = Environment.GetEnvironmentVariable("RMM_ENDPOINT_SESSION_TIMEOUT_MS");
        return int.TryParse(configured, out int milliseconds) && milliseconds >= 1000
            ? TimeSpan.FromMilliseconds(milliseconds)
            : TimeSpan.FromMinutes(2);
    }

    private static async Task Heartbeats(WebSocket socket, SemaphoreSlim sendLock, CancellationToken stopped) {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
        while (await timer.WaitForNextTickAsync(stopped))
            await Send(socket, sendLock, new { type = "heartbeat" }, stopped);
    }

    private static Task Reject(WebSocket socket, SemaphoreSlim sendLock, string device, string code,
                               Dispatch? request = null) {
        var payload = new Dictionary<string, object?> {
            ["type"] = "rejected",
            ["code"] = code,
            ["deviceId"] = device,
        };
        if (request?.SessionId is not null) payload["sessionId"] = request.SessionId;
        if (request?.ExecutionId is not null) payload["executionId"] = request.ExecutionId;
        return Send(socket, sendLock, payload);
    }

    private static async Task Send(WebSocket socket, SemaphoreSlim sendLock, object value,
                                   CancellationToken cancellation = default) {
        await sendLock.WaitAsync(cancellation);
        try {
            using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellation);
            timeout.CancelAfter(TimeSpan.FromSeconds(10));
            await socket.SendAsync(JsonSerializer.SerializeToUtf8Bytes(value, Json),
                WebSocketMessageType.Text, true, timeout.Token);
        } finally { sendLock.Release(); }
    }

    private static async Task<JsonElement> Receive(WebSocket socket, TimeSpan wait) {
        using var timeout = new CancellationTokenSource(wait);
        using var data = new MemoryStream();
        var buffer = new byte[8192];
        WebSocketReceiveResult part;
        do {
            part = await socket.ReceiveAsync(buffer, timeout.Token);
            if (part.MessageType == WebSocketMessageType.Close) throw new WebSocketException();
            if (part.MessageType != WebSocketMessageType.Text || data.Length + part.Count > 300_000)
                throw new InvalidDataException();
            data.Write(buffer, 0, part.Count);
        } while (!part.EndOfMessage);
        return JsonDocument.Parse(data.ToArray()).RootElement.Clone();
    }
}
