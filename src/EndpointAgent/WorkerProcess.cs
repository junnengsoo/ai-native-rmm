using System.Diagnostics;
using System.IO.Pipes;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;

namespace EndpointAgent;

internal sealed record WorkerResult(string State, string? InvocationOutcome, int? ExitCode, string? ExitCodeSource, bool HadErrors,
    double? DurationMs, bool CaptureTruncated, int? LastNativeExitCode);

internal sealed class WorkerProcess : IAsyncDisposable {
    public bool IsUsable { get; private set; } = true;
    private readonly NamedPipeServerStream pipe;
    private readonly Process process;
    private readonly StreamReader reader;
    private readonly StreamWriter writer;
    private readonly OwnedJob job;
    private bool stopped;
    private bool disposed;

    private WorkerProcess(NamedPipeServerStream pipe, Process process, OwnedJob job) {
        this.pipe = pipe;
        this.process = process;
        this.job = job;
        reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, true);
        writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, true) { AutoFlush = true };
    }
    public static async Task<WorkerProcess> Start() {
        string executable = NativeWindowsPowerShell();
        string workerScript = Path.Combine(AppContext.BaseDirectory, "NativePowerShellWorker.ps1");
        if (!File.Exists(workerScript)) throw new FileNotFoundException("native_powershell_worker_missing", workerScript);
        // The name is an unguessable local rendezvous, not a network listener.
        var name = "rmm-" + Guid.NewGuid().ToString("N");
        var pipe = new NamedPipeServerStream(name, PipeDirection.InOut, 1, PipeTransmissionMode.Byte,
            PipeOptions.Asynchronous | PipeOptions.CurrentUserOnly);
        var start = new ProcessStartInfo(executable) { UseShellExecute = false,
            RedirectStandardOutput = true, RedirectStandardError = true, CreateNoWindow = true };
        start.ArgumentList.Add("-NoLogo");
        start.ArgumentList.Add("-NoProfile");
        start.ArgumentList.Add("-NonInteractive");
        start.ArgumentList.Add("-File");
        start.ArgumentList.Add(workerScript);
        start.ArgumentList.Add("-PipeName");
        start.ArgumentList.Add(name);
        var allowed = new[] { "SystemRoot", "WINDIR", "TEMP", "TMP", "PATH", "PATHEXT", "ComSpec", "SystemDrive", "ProgramFiles", "ProgramFiles(x86)", "ProgramData" };
        var environment = allowed.ToDictionary(key => key, Environment.GetEnvironmentVariable);
        start.Environment.Clear();
        foreach (var (key, value) in environment) if (value is not null) start.Environment[key] = value;
        var job = new OwnedJob();
        Process? process = null;
        try { process = Process.Start(start)!; job.Assign(process); }
        catch {
            if (process is not null) { if (!process.HasExited) process.Kill(true); process.Dispose(); }
            job.Dispose(); pipe.Dispose(); throw;
        }
        _ = Drain(process.StandardOutput);
        _ = DrainDiagnostics(process.StandardError);
        WorkerProcess? worker = null;
        try {
            using var deadline = new CancellationTokenSource(TimeSpan.FromSeconds(15));
            await pipe.WaitForConnectionAsync(deadline.Token);
            worker = new WorkerProcess(pipe, process, job);
            var ready = await worker.reader.ReadLineAsync(deadline.Token);
            if (!NativeWorkerReady(ready)) {
                if (ready is not null && ready.StartsWith("startup_failed:") && ready.Length < 100)
                    Console.Error.WriteLine(ready);
                throw new InvalidDataException();
            }
            return worker;
        } catch {
            if (worker is not null) await worker.DisposeAsync();
            else {
                if (!process.HasExited) process.Kill(true);
                job.Dispose(); process.Dispose(); pipe.Dispose();
            }
            throw;
        }
    }
    public async Task<WorkerResult> Execute(string script, int timeoutMs, Func<string, string, Task> onOutput,
                                            CancellationToken cancellation) {
        var watch = Stopwatch.StartNew();
        using var deadline = new CancellationTokenSource(timeoutMs);
        using var stopSignal = CancellationTokenSource.CreateLinkedTokenSource(deadline.Token, cancellation);
        try {
            await writer.WriteLineAsync(JsonSerializer.Serialize(new { script }).AsMemory(), stopSignal.Token);
            while (true) {
                string line = await reader.ReadLineAsync(stopSignal.Token) ?? throw new EndOfStreamException();
                using var message = JsonDocument.Parse(line);
                if (message.RootElement.TryGetProperty("kind", out var kind) && kind.GetString() == "output") {
                    var stream = message.RootElement.GetProperty("stream").GetString() == "stdout" ? "stdout" : "stderr";
                    var text = message.RootElement.GetProperty("text").GetString();
                    if (!string.IsNullOrEmpty(text)) await onOutput(stream, text);
                    continue;
                }
                var result = JsonSerializer.Deserialize<WorkerResult>(line)!;
                if (result.InvocationOutcome == "explicit_exit") { IsUsable = false; stopped = await job.Stop(); }
                return result;
            }
        } catch (Exception error) when (error is OperationCanceledException or IOException or JsonException) {
            IsUsable = false;
            stopped = await job.Stop();
            bool confirmedCancellation = error is OperationCanceledException && stopped;
            string? state = confirmedCancellation
                ? cancellation.IsCancellationRequested ? "cancelled" : "timed_out"
                : "outcome_unknown";
            return new WorkerResult(state, confirmedCancellation ? "stopped" : null,
                null, null, false, watch.Elapsed.TotalMilliseconds, true, null);
        }
    }
    public async ValueTask DisposeAsync() {
        if (disposed) return;
        disposed = true;
        bool confirmed = stopped || await job.Stop();
        try { reader.Dispose(); writer.Dispose(); }
        finally { pipe.Dispose(); process.Dispose(); job.Dispose(); }
        if (!confirmed) throw new InvalidOperationException("cleanup_unconfirmed");
    }
    private static async Task Drain(StreamReader stream) {
        var buffer = new char[4096];
        while (await stream.ReadAsync(buffer) is var count && count > 0) {
            // Child diagnostics are not forwarded: scripts can write arbitrary bytes.
        }
    }

    private static async Task DrainDiagnostics(StreamReader stream) {
        while (await stream.ReadLineAsync() is { } line) {
            if (line.StartsWith("startup_failed:", StringComparison.Ordinal) && line.Length < 100)
                Console.Error.WriteLine(line);
        }
    }

    private static bool NativeWorkerReady(string? value) {
        try {
            using var message = JsonDocument.Parse(value ?? "");
            var root = message.RootElement;
            return root.GetProperty("kind").GetString() == "ready"
                && root.GetProperty("edition").GetString() == "Desktop"
                && root.GetProperty("is64Bit").GetBoolean()
                && root.GetProperty("version").GetString() is { Length: > 0 };
        } catch (Exception error) when (error is JsonException or InvalidOperationException or KeyNotFoundException) {
            return false;
        }
    }

    private static string NativeWindowsPowerShell() {
        if (!Environment.Is64BitProcess) throw new PlatformNotSupportedException("native_64_bit_powershell_required");
        var system = new StringBuilder(260);
        uint length = GetSystemDirectoryW(system, (uint)system.Capacity);
        if (length >= (uint)system.Capacity) {
            system.Capacity = checked((int)length);
            length = GetSystemDirectoryW(system, (uint)system.Capacity);
        }
        if (length == 0 || length >= (uint)system.Capacity) throw new InvalidOperationException("system_directory_unavailable");
        string executable = Path.Combine(system.ToString(), "WindowsPowerShell", "v1.0", "powershell.exe");
        if (!File.Exists(executable)) throw new FileNotFoundException("native_powershell_unavailable", executable);
        return executable;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern uint GetSystemDirectoryW(StringBuilder buffer, uint size);
}
