using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace EndpointAgent;

internal sealed record LedgerRecord(long Sequence, string RecordType, DateTimeOffset EndpointObservedAt,
    Dictionary<string, object?> Data);

internal sealed record LedgerSnapshot(string? SessionId, string? ExecutionId, string? ScriptSha256,
    bool OutputDropped);

internal sealed record AckCheckpoint(string DeviceId, string LedgerId, long AcknowledgedThrough);

internal sealed class AgentRuntimeState {
    public AgentRuntimeState(string device) {
        Ledger = new EndpointLedger(device);
    }

    public EndpointLedger Ledger { get; }
    public WorkerProcess? Worker { get; set; }
    public Task<(string Session, string Execution, string ScriptSha256, WorkerResult Result)>? Invocation { get; set; }
    public CancellationTokenSource? InvocationStop { get; set; }
    public DateTimeOffset? SessionDeadline { get; set; }
}

internal sealed class EndpointLedger {
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web);
    private const long SegmentBytes = 8 * 1024 * 1024;
    private const long DefaultCapacityBytes = 100 * 1024 * 1024;
    private const long ReservedLifecycleBytes = 1024 * 1024;
    private const int MaxBatchRecords = 256;
    private const int MaxBatchSerializedBytes = 240_000;
    private const long OutputFlushBytes = 64 * 1024;
    private static readonly TimeSpan OutputFlushInterval = TimeSpan.FromMilliseconds(250);
    private readonly object gate = new();
    private readonly string deviceId;
    private readonly string root;
    private readonly string checkpointPath;
    private readonly string executionClaimPath;
    private readonly long capacityBytes;
    private readonly List<LedgerRecord> records = [];
    private readonly HashSet<string> acceptedExecutionIds = new(StringComparer.OrdinalIgnoreCase);
    private readonly HashSet<string> dirtySegments = new(StringComparer.OrdinalIgnoreCase);
    private LedgerSnapshot snapshot = new(null, null, null, false);
    private long nextSequence = 1;
    private long durableThrough;
    private long acknowledgedThrough;
    private string currentSegmentPath;
    private long currentSegmentStart;
    private long safePruneThrough;
    private bool outputDropRecorded;
    private long bufferedOutputBytes;
    private long pendingFlushThrough;
    private DateTimeOffset lastOutputFlush = DateTimeOffset.UtcNow;
    private Timer? flushTimer;

    public event Action? DurableRecordsAvailable;

    public EndpointLedger(string deviceId) {
        this.deviceId = deviceId;
        string name = Convert.ToHexString(SHA256.HashData(Encoding.UTF8.GetBytes(deviceId))).ToLowerInvariant();
        root = Path.Combine(EndpointPaths.DataDirectory, "ledger-" + name);
        Directory.CreateDirectory(root);
        checkpointPath = Path.Combine(root, "ack.json");
        executionClaimPath = Path.Combine(root, "execution-claims.jsonl");
        capacityBytes = CapacityFromEnvironment();
        var checkpoint = LoadCheckpoint();
        LedgerId = checkpoint.LedgerId;
        acknowledgedThrough = checkpoint.AcknowledgedThrough;
        LoadExecutionClaims();
        LoadRecords();
        durableThrough = records.Count == 0 ? 0 : records[^1].Sequence;
        currentSegmentStart = records.Count == 0 ? nextSequence : records[^1].Sequence;
        currentSegmentPath = SegmentPath(currentSegmentStart);
        RecordRestartLossIfNeeded();
        QueuePrune();
    }

    public string LedgerId { get; }

    public long AcknowledgedThrough {
        get { lock (gate) return acknowledgedThrough; }
    }

    public LedgerSnapshot Snapshot {
        get { lock (gate) return snapshot; }
    }

    public bool HasUnacknowledgedRecords {
        get { lock (gate) return records.Any(record => record.Sequence > acknowledgedThrough); }
    }

    public LedgerRecord SessionStarted(string sessionId) =>
        Append("session_started", new() { ["sessionId"] = sessionId });

    public bool TryExecutionAccepted(string sessionId, string executionId, string scriptSha256) {
        lock (gate) {
            if (acceptedExecutionIds.Contains(executionId)) return false;
            AppendLocked("execution_accepted", ExecutionBinding(sessionId, executionId, scriptSha256), forceDurable: true);
            PersistExecutionClaimLocked(sessionId, executionId, scriptSha256);
            return true;
        }
    }

    public LedgerRecord ExecutionStarted(string sessionId, string executionId, string scriptSha256) =>
        Append("execution_started", ExecutionBinding(sessionId, executionId, scriptSha256));

    public IReadOnlyList<LedgerRecord> OutputChunk(string sessionId, string executionId, string scriptSha256,
                                                   string stream, string text) {
        List<LedgerRecord> appended = [];
        foreach (var chunk in SplitUtf8(text, 8192)) {
            var data = ExecutionBinding(sessionId, executionId, scriptSha256);
            data["stream"] = stream;
            data["text"] = chunk;
            var estimate = Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(new {
                sequence = nextSequence, recordType = "output_chunk",
                endpointObservedAt = DateTimeOffset.UtcNow, data
            }, Json)) + 1;
            lock (gate) {
                if (outputDropRecorded || TotalLedgerBytes() + estimate > Math.Max(0, capacityBytes - ReservedLifecycleBytes)) {
                    if (!outputDropRecorded) {
                        outputDropRecorded = true;
                        appended.Add(AppendLocked("output_dropped", new() {
                            ["sessionId"] = sessionId,
                            ["executionId"] = executionId,
                            ["scriptSha256"] = scriptSha256,
                            ["reason"] = "endpoint_ledger_capacity_exceeded",
                        }, forceDurable: true));
                    }
                    continue;
                }
                appended.Add(AppendLocked("output_chunk", data, forceDurable: false));
            }
        }
        return appended;
    }

    public LedgerRecord ExecutionFinished(string sessionId, string executionId, string scriptSha256,
                                          WorkerResult result) {
        var data = ExecutionBinding(sessionId, executionId, scriptSha256);
        data["state"] = result.State;
        data["invocationOutcome"] = result.InvocationOutcome;
        data["exitCode"] = result.ExitCode;
        data["exitCodeSource"] = result.ExitCodeSource;
        data["hadErrors"] = result.HadErrors;
        data["durationMs"] = result.DurationMs;
        data["captureTruncated"] = result.CaptureTruncated || snapshot.OutputDropped;
        data["lastNativeExitCode"] = result.LastNativeExitCode;
        return Append("execution_finished", data);
    }

    public LedgerRecord CancellationRequested(string sessionId, string executionId, string scriptSha256) =>
        Append("cancellation_requested", ExecutionBinding(sessionId, executionId, scriptSha256));

    public LedgerRecord WorkerStopped(string sessionId, string? executionId, string? scriptSha256,
                                      string reason, bool cleanupConfirmed, bool captureTruncated = false) =>
        Append("worker_stopped", new() {
            ["sessionId"] = sessionId,
            ["executionId"] = executionId,
            ["scriptSha256"] = scriptSha256,
            ["reason"] = reason,
            ["cleanupConfirmed"] = cleanupConfirmed,
            ["captureTruncated"] = captureTruncated,
        });

    public LedgerRecord SessionClosed(string sessionId) =>
        Append("session_closed", new() { ["sessionId"] = sessionId });

    public IReadOnlyList<LedgerRecord> PendingBatch(int maxRecords = MaxBatchRecords,
                                                    int maxSerializedBytes = MaxBatchSerializedBytes) {
        lock (gate) {
            List<LedgerRecord> batch = [];
            int serializedBytes = 0;
            foreach (var record in records.Where(record => record.Sequence > acknowledgedThrough
                                                           && record.Sequence <= durableThrough)
                         .OrderBy(record => record.Sequence)) {
                int recordBytes = Encoding.UTF8.GetByteCount(JsonSerializer.Serialize(record, Json)) + 2;
                if (recordBytes > maxSerializedBytes)
                    throw new InvalidDataException("ledger_record_exceeds_transport_limit");
                if (batch.Count > 0 && serializedBytes + recordBytes > maxSerializedBytes)
                    break;
                batch.Add(record);
                serializedBytes += recordBytes;
                if (batch.Count >= maxRecords) break;
            }
            return batch;
        }
    }

    public void Acknowledge(string ledgerId, long acknowledged) {
        bool shouldPrune = false;
        lock (gate) {
            if (!string.Equals(ledgerId, LedgerId, StringComparison.Ordinal) || acknowledged < acknowledgedThrough)
                return;
            long highest = Math.Max(durableThrough, records.Count == 0 ? 0 : records[^1].Sequence);
            acknowledgedThrough = Math.Min(acknowledged, highest);
            SaveCheckpoint();
            shouldPrune = safePruneThrough > 0 && Math.Min(acknowledgedThrough, safePruneThrough) > 0;
        }
        if (shouldPrune) QueuePrune();
    }

    private AckCheckpoint LoadCheckpoint() {
        try {
            if (File.Exists(checkpointPath)) {
                using var stream = File.OpenRead(checkpointPath);
                var loaded = JsonSerializer.Deserialize<AckCheckpoint>(stream, Json);
                if (loaded is not null && loaded.DeviceId == deviceId
                    && loaded.LedgerId.Length is >= 1 and <= 64 && loaded.AcknowledgedThrough >= 0)
                    return loaded;
            }
        } catch (Exception error) when (error is IOException or UnauthorizedAccessException or JsonException) { }
        var created = new AckCheckpoint(deviceId, Guid.NewGuid().ToString("N"), 0);
        SaveCheckpoint(created);
        return created;
    }

    private void SaveCheckpoint() => SaveCheckpoint(new AckCheckpoint(deviceId, LedgerId, acknowledgedThrough));

    private void SaveCheckpoint(AckCheckpoint checkpoint) {
        string temp = checkpointPath + ".tmp";
        using (var stream = File.Create(temp)) {
            JsonSerializer.Serialize(stream, checkpoint, Json);
            stream.Flush(true);
        }
        File.Move(temp, checkpointPath, true);
    }

    private void LoadExecutionClaims() {
        if (!File.Exists(executionClaimPath)) return;
        foreach (var line in File.ReadLines(executionClaimPath)) {
            if (string.IsNullOrWhiteSpace(line)) continue;
            try {
                using var document = JsonDocument.Parse(line);
                if (document.RootElement.TryGetProperty("executionId", out var id)
                    && id.ValueKind == JsonValueKind.String
                    && Guid.TryParseExact(id.GetString(), "D", out _))
                    acceptedExecutionIds.Add(id.GetString()!);
            } catch (JsonException) { }
        }
    }

    private void PersistExecutionClaimLocked(string sessionId, string executionId, string scriptSha256) {
        var line = JsonSerializer.Serialize(new {
            sessionId,
            executionId,
            scriptSha256,
            claimedAt = DateTimeOffset.UtcNow,
        }, Json) + Environment.NewLine;
        using var stream = new FileStream(executionClaimPath, FileMode.Append, FileAccess.Write, FileShare.Read);
        var bytes = Encoding.UTF8.GetBytes(line);
        stream.Write(bytes, 0, bytes.Length);
        stream.Flush(true);
    }

    private void LoadRecords() {
        long lastSequence = 0;
        foreach (var file in Directory.GetFiles(root, "segment-*.jsonl").OrderBy(name => name, StringComparer.Ordinal)) {
            foreach (var line in File.ReadLines(file)) {
                if (string.IsNullOrWhiteSpace(line)) continue;
                try {
                    var record = JsonSerializer.Deserialize<LedgerRecord>(line, Json);
                    if (record is null || record.Sequence <= lastSequence || record.RecordType.Length == 0)
                        break;
                    records.Add(record);
                    ApplyToSnapshot(record);
                    lastSequence = record.Sequence;
                    nextSequence = Math.Max(nextSequence, record.Sequence + 1);
                } catch (JsonException) {
                    break;
                }
            }
        }
        nextSequence = Math.Max(nextSequence, acknowledgedThrough + 1);
    }

    private void RecordRestartLossIfNeeded() {
        lock (gate) {
            if (snapshot.SessionId is null) return;
            WorkerStopped(snapshot.SessionId, snapshot.ExecutionId, snapshot.ScriptSha256,
                "endpoint_service_restart", cleanupConfirmed: true,
                captureTruncated: snapshot.ExecutionId is not null || snapshot.OutputDropped);
        }
    }

    private LedgerRecord Append(string recordType, Dictionary<string, object?> data) {
        lock (gate) return AppendLocked(recordType, data, forceDurable: true);
    }

    private LedgerRecord AppendLocked(string recordType, Dictionary<string, object?> data, bool forceDurable) {
        if (CurrentSegmentBytes() >= SegmentBytes) {
            currentSegmentStart = nextSequence;
            currentSegmentPath = SegmentPath(currentSegmentStart);
        }
        var record = new LedgerRecord(nextSequence++, recordType, DateTimeOffset.UtcNow, data);
        var line = JsonSerializer.Serialize(record, Json) + Environment.NewLine;
        using (var stream = new FileStream(currentSegmentPath, FileMode.Append, FileAccess.Write, FileShare.Read)) {
            var bytes = Encoding.UTF8.GetBytes(line);
            stream.Write(bytes, 0, bytes.Length);
            bool flushDurably = forceDurable
                || bufferedOutputBytes + bytes.Length >= OutputFlushBytes
                || DateTimeOffset.UtcNow - lastOutputFlush >= OutputFlushInterval;
            if (flushDurably) {
                stream.Flush(true);
            } else {
                stream.Flush(false);
                dirtySegments.Add(currentSegmentPath);
                bufferedOutputBytes += bytes.Length;
                pendingFlushThrough = record.Sequence;
            }
        }
        if (forceDurable || bufferedOutputBytes >= OutputFlushBytes
            || DateTimeOffset.UtcNow - lastOutputFlush >= OutputFlushInterval) {
            FlushDirtySegmentsLocked(currentSegmentPath);
            durableThrough = record.Sequence;
            pendingFlushThrough = 0;
            bufferedOutputBytes = 0;
            lastOutputFlush = DateTimeOffset.UtcNow;
        } else {
            ScheduleFlushLocked();
        }
        records.Add(record);
        ApplyToSnapshot(record);
        return record;
    }

    private void ScheduleFlushLocked() {
        flushTimer ??= new Timer(_ => FlushBufferedOutput(), null, Timeout.InfiniteTimeSpan, Timeout.InfiniteTimeSpan);
        flushTimer.Change(OutputFlushInterval, Timeout.InfiniteTimeSpan);
    }

    private void FlushBufferedOutput() {
        bool advanced = false;
        lock (gate) {
            if (pendingFlushThrough <= durableThrough) return;
            try {
                FlushDirtySegmentsLocked(currentSegmentPath);
                durableThrough = pendingFlushThrough;
                pendingFlushThrough = 0;
                bufferedOutputBytes = 0;
                lastOutputFlush = DateTimeOffset.UtcNow;
                advanced = true;
            } catch (Exception error) when (error is IOException or UnauthorizedAccessException) {
                ScheduleFlushLocked();
            }
        }
        if (advanced) DurableRecordsAvailable?.Invoke();
    }

    private void FlushDirtySegmentsLocked(string includePath) {
        dirtySegments.Add(includePath);
        foreach (var path in dirtySegments.ToArray()) {
            if (!File.Exists(path)) continue;
            using var stream = new FileStream(path, FileMode.Open, FileAccess.ReadWrite, FileShare.Read);
            stream.Flush(true);
        }
        dirtySegments.Clear();
    }

    private void ApplyToSnapshot(LedgerRecord record) {
        var data = record.Data;
        string? session = data.TryGetValue("sessionId", out var sessionValue) ? sessionValue?.ToString() : null;
        string? execution = data.TryGetValue("executionId", out var executionValue) ? executionValue?.ToString() : null;
        string? scriptHash = data.TryGetValue("scriptSha256", out var hashValue) ? hashValue?.ToString() : null;
        switch (record.RecordType) {
            case "session_started":
                snapshot = new(session, null, null, false);
                outputDropRecorded = false;
                break;
            case "execution_accepted":
                if (execution is not null) acceptedExecutionIds.Add(execution);
                snapshot = new(session, execution, scriptHash, false);
                outputDropRecorded = false;
                break;
            case "execution_started":
                snapshot = new(session, execution, scriptHash, false);
                outputDropRecorded = false;
                break;
            case "output_dropped":
                snapshot = snapshot with { OutputDropped = true };
                outputDropRecorded = true;
                break;
            case "execution_finished":
                snapshot = new(session, null, null, snapshot.OutputDropped);
                outputDropRecorded = false;
                break;
            case "worker_stopped":
            case "session_closed":
                snapshot = new(null, null, null, false);
                outputDropRecorded = false;
                safePruneThrough = record.Sequence;
                break;
        }
    }

    private void QueuePrune() {
        long pruneThrough;
        string activeSegment;
        lock (gate) {
            if (safePruneThrough <= 0) return;
            pruneThrough = Math.Min(acknowledgedThrough, safePruneThrough);
            if (pruneThrough <= 0) return;
            activeSegment = currentSegmentPath;
        }
        _ = Task.Run(() => PruneAcknowledgedClosedSegments(activeSegment, pruneThrough));
    }

    private void PruneAcknowledgedClosedSegments(string activeSegment, long pruneThrough) {
        foreach (var file in Directory.GetFiles(root, "segment-*.jsonl").OrderBy(name => name, StringComparer.Ordinal)) {
            if (string.Equals(file, activeSegment, StringComparison.Ordinal)) continue;
            long max = SegmentMaxSequence(file);
            if (max > 0 && max <= pruneThrough) {
                try { File.Delete(file); }
                catch (IOException) { }
                catch (UnauthorizedAccessException) { }
            }
        }
        lock (gate) {
            records.RemoveAll(record => record.Sequence <= pruneThrough);
        }
    }

    private static long SegmentMaxSequence(string file) {
        long max = 0;
        foreach (var line in File.ReadLines(file)) {
            try {
                using var document = JsonDocument.Parse(line);
                max = Math.Max(max, document.RootElement.GetProperty("sequence").GetInt64());
            } catch (JsonException) { }
        }
        return max;
    }

    private string SegmentPath(long start) => Path.Combine(root, "segment-" + start.ToString("D20") + ".jsonl");

    private long CurrentSegmentBytes() => File.Exists(currentSegmentPath) ? new FileInfo(currentSegmentPath).Length : 0;

    private long TotalLedgerBytes() =>
        Directory.GetFiles(root, "segment-*.jsonl").Sum(file => new FileInfo(file).Length);

    private static long CapacityFromEnvironment() {
        string? configured = Environment.GetEnvironmentVariable("RMM_ENDPOINT_LEDGER_CAPACITY_BYTES");
        return long.TryParse(configured, out var value) && value >= ReservedLifecycleBytes
            ? value
            : DefaultCapacityBytes;
    }

    private static Dictionary<string, object?> ExecutionBinding(string sessionId, string executionId, string scriptSha256) =>
        new() { ["sessionId"] = sessionId, ["executionId"] = executionId, ["scriptSha256"] = scriptSha256 };

    private static IEnumerable<string> SplitUtf8(string value, int limit) {
        var builder = new StringBuilder();
        var size = 0;
        foreach (var rune in value.EnumerateRunes()) {
            string text = rune.ToString();
            int encoded = Encoding.UTF8.GetByteCount(text);
            if (builder.Length > 0 && size + encoded > limit) {
                yield return builder.ToString();
                builder.Clear();
                size = 0;
            }
            builder.Append(text);
            size += encoded;
        }
        if (builder.Length > 0) yield return builder.ToString();
    }
}
