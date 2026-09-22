using System.Net.WebSockets;
using System.Text.Json;

namespace EndpointAgent;

// Shared session/execution runtime for every authenticated endpoint connection.
// Authentication entry points decide whether their peer supports reachability
// heartbeats; dispatch, worker lifecycle, and protocol bounds live only here.
internal static class AgentRuntime {
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);

    public static async Task Run(WebSocket socket, string device, bool sendHeartbeats) {
        WorkerProcess? worker = null;
        string? session = null;
        int idleTimeoutMs = 0;
        DateTimeOffset? idleDeadline = null;
        DateTimeOffset? absoluteDeadline = null;
        var sessions = new HashSet<string>(StringComparer.Ordinal);
        var executions = new HashSet<string>(StringComparer.Ordinal);
        Task<(string Session, string Execution, WorkerResult Result)>? invocation = null;
        Task<JsonElement>? incoming = null;
        using var stopped = new CancellationTokenSource();
        using var sendLock = new SemaphoreSlim(1, 1);
        Task heartbeats = sendHeartbeats ? Heartbeats(socket, sendLock, stopped.Token) : Task.CompletedTask;
        try {
            while (socket.State == WebSocketState.Open) {
                if (invocation is not null) {
                    incoming ??= Receive(socket, TimeSpan.FromMinutes(2));
                    var ready = await Task.WhenAny(incoming, invocation);
                    if (ready == invocation) {
                        var completed = await invocation;
                        invocation = null;
                        idleDeadline = DateTimeOffset.UtcNow.AddMilliseconds(idleTimeoutMs);
                        await Send(socket, sendLock, new { type = "result", deviceId = device,
                            sessionId = completed.Session, executionId = completed.Execution,
                            completed.Result.State, completed.Result.InvocationOutcome, completed.Result.ExitCode,
                            completed.Result.ExitCodeSource, completed.Result.HadErrors, completed.Result.Stdout,
                            completed.Result.Stderr, completed.Result.DurationMs, completed.Result.CaptureTruncated,
                            completed.Result.LastNativeExitCode });
                    } else {
                        try {
                            var runningMessage = await incoming;
                            if (!runningMessage.TryGetProperty("type", out var runningMessageType)
                                || runningMessageType.ValueKind != JsonValueKind.String
                                || runningMessageType.GetString() != "heartbeat_ack")
                                await Reject(socket, sendLock, "invalid_state_or_duplicate");
                        } catch (JsonException) {
                            await Reject(socket, sendLock, "invalid_request");
                        } catch (OperationCanceledException) {
                        } finally {
                            incoming = null;
                        }
                    }
                    continue;
                }
                if (worker is not null && DeadlineReached(idleDeadline, absoluteDeadline)) {
                    await worker.DisposeAsync();
                    worker = null;
                    await Send(socket, sendLock, new { type = "session_closed", deviceId = device, sessionId = session });
                    session = null;
                    idleDeadline = absoluteDeadline = null;
                    continue;
                }
                JsonElement message;
                incoming ??= Receive(socket, TimeUntilNextDeadline(idleDeadline, absoluteDeadline));
                try { message = await incoming; }
                catch (JsonException) {
                    incoming = null;
                    await Reject(socket, sendLock, "invalid_request");
                    continue;
                } catch (OperationCanceledException) {
                    incoming = null;
                    continue;
                }
                incoming = null;
                if (message.TryGetProperty("type", out var messageType)
                    && messageType.ValueKind == JsonValueKind.String
                    && messageType.GetString() == "heartbeat_ack") continue;

                Dispatch? request;
                try { request = Dispatch.Parse(message, device); }
                catch (JsonException) { request = null; }
                if (request is null) { await Reject(socket, sendLock, "invalid_request"); continue; }

                if (request.Type == "open_session" && worker is null && invocation is null
                    && sessions.Count < 100 && sessions.Add(request.SessionId)) {
                    session = request.SessionId;
                    idleTimeoutMs = request.IdleTimeoutMs;
                    absoluteDeadline = request.AbsoluteDeadline;
                    idleDeadline = DateTimeOffset.UtcNow.AddMilliseconds(idleTimeoutMs);
                    worker = await WorkerProcess.Start();
                    await Send(socket, sendLock, new { type = "session_ready", deviceId = device, sessionId = session });
                } else if (request.Type == "close_session" && worker is not null && invocation is null
                    && request.SessionId == session) {
                    await worker.DisposeAsync();
                    worker = null;
                    await Send(socket, sendLock, new { type = "session_closed", deviceId = device, sessionId = session });
                    session = null;
                    idleDeadline = absoluteDeadline = null;
                } else if (request.Type == "execute" && worker is not null && worker.IsUsable && invocation is null
                    && request.SessionId == session && executions.Count < 1000
                    && request.StartDeadline > DateTimeOffset.UtcNow
                    && absoluteDeadline > DateTimeOffset.UtcNow.AddMilliseconds(request.TimeoutMs)
                    && executions.Add(request.ExecutionId!)) {
                    string execution = request.ExecutionId!;
                    await Send(socket, sendLock, new { type = "running", deviceId = device,
                        sessionId = session, executionId = execution });
                    idleDeadline = null;
                    invocation = Complete(worker, session!, execution, request.Script!, request.TimeoutMs);
                } else await Reject(socket, sendLock, "invalid_state_or_duplicate");
            }
        } finally {
            stopped.Cancel();
            try { await heartbeats; }
            catch (Exception error) when (error is OperationCanceledException or WebSocketException) { }
            if (worker is not null) await worker.DisposeAsync();
        }
    }

    private static async Task<(string Session, string Execution, WorkerResult Result)> Complete(
        WorkerProcess worker, string session, string execution, string script, int timeoutMs) =>
        (session, execution, await worker.Execute(script, timeoutMs));

    private static async Task Heartbeats(WebSocket socket, SemaphoreSlim sendLock, CancellationToken stopped) {
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(15));
        while (await timer.WaitForNextTickAsync(stopped))
            await Send(socket, sendLock, new { type = "heartbeat" }, stopped);
    }

    private static Task Reject(WebSocket socket, SemaphoreSlim sendLock, string code) =>
        Send(socket, sendLock, new { type = "rejected", code });

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

    private static bool DeadlineReached(DateTimeOffset? idleDeadline, DateTimeOffset? absoluteDeadline) =>
        (idleDeadline is not null && idleDeadline <= DateTimeOffset.UtcNow)
        || (absoluteDeadline is not null && absoluteDeadline <= DateTimeOffset.UtcNow);

    private static TimeSpan TimeUntilNextDeadline(DateTimeOffset? idleDeadline, DateTimeOffset? absoluteDeadline) {
        var next = new[] { idleDeadline, absoluteDeadline }.Where(value => value is not null).Min();
        if (next is null) return TimeSpan.FromMinutes(2);
        var remaining = next.Value - DateTimeOffset.UtcNow;
        if (remaining < TimeSpan.FromMilliseconds(1)) return TimeSpan.FromMilliseconds(1);
        return remaining < TimeSpan.FromMinutes(2) ? remaining : TimeSpan.FromMinutes(2);
    }

    private static async Task<JsonElement> Receive(WebSocket socket, TimeSpan wait) {
        using var timeout = new CancellationTokenSource(wait);
        using var data = new MemoryStream();
        var buffer = new byte[8192];
        WebSocketReceiveResult part;
        do {
            part = await socket.ReceiveAsync(buffer, timeout.Token);
            if (part.MessageType == WebSocketMessageType.Close) throw new WebSocketException();
            if (part.MessageType != WebSocketMessageType.Text || data.Length + part.Count > 80_000)
                throw new InvalidDataException();
            data.Write(buffer, 0, part.Count);
        } while (!part.EndOfMessage);
        return JsonDocument.Parse(data.ToArray()).RootElement.Clone();
    }
}
