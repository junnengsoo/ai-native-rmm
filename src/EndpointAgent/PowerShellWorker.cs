using System.Diagnostics;
using System.Globalization;
using System.IO.Pipes;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Management.Automation.Runspaces;
using System.Text;
using System.Text.Json;

namespace EndpointAgent;

internal static class PowerShellWorker {
    public static async Task Run(string name) {
        using var pipe = new NamedPipeClientStream(".", name, PipeDirection.InOut, PipeOptions.Asynchronous);
        await pipe.ConnectAsync(15_000);
        using var reader = new StreamReader(pipe, Encoding.UTF8, false, 4096, true);
        using var writer = new StreamWriter(pipe, new UTF8Encoding(false), 4096, true) { AutoFlush = true };
        var host = new InvocationHost();
        using var runspace = RunspaceFactory.CreateRunspace(host, InitialSessionState.CreateDefault2());
        try { runspace.Open(); }
        catch (Exception error) {
            await writer.WriteLineAsync("startup_failed:" + error.GetType().Name);
            return;
        }
        await writer.WriteLineAsync("ready");
        while (await reader.ReadLineAsync() is { } line) {
            var script = JsonDocument.Parse(line).RootElement.GetProperty("script").GetString()!;
            host.ExitCode = null;
            runspace.SessionStateProxy.SetVariable("LASTEXITCODE", null);
            void Retain(string stream, string text) {
                lock (writer) writer.WriteLine(JsonSerializer.Serialize(new { kind = "output", stream, text }));
            }
            using var stdout = new BoundedOutput(text => Retain("stdout", text));
            using var stderr = new BoundedOutput(text => Retain("stderr", text));
            Console.SetOut(stdout); Console.SetError(stderr);
            using var powershell = PowerShell.Create();
            powershell.Runspace = runspace;
            powershell.AddScript(script, useLocalScope: false);
            using var output = new PSDataCollection<PSObject>();
            output.DataAdded += (_, _) => {
                foreach (var value in output.ReadAll()) stdout.WriteLine(value?.ToString());
            };
            bool hadErrors = false;
            powershell.Streams.Error.DataAdded += (_, _) => {
                hadErrors = true;
                foreach (var value in powershell.Streams.Error.ReadAll()) stderr.WriteLine(value.ToString());
            };
            powershell.Streams.Warning.DataAdded += (_, _) => {
                foreach (var value in powershell.Streams.Warning.ReadAll()) stderr.WriteLine(value.Message);
            };
            powershell.Streams.Information.DataAdded += (_, _) => {
                foreach (var value in powershell.Streams.Information.ReadAll()) stdout.WriteLine(value.MessageData?.ToString());
            };
            powershell.Streams.Verbose.DataAdded += (_, _) => powershell.Streams.Verbose.Clear();
            powershell.Streams.Debug.DataAdded += (_, _) => powershell.Streams.Debug.Clear();
            powershell.Streams.Progress.DataAdded += (_, _) => powershell.Streams.Progress.Clear();
            var watch = Stopwatch.StartNew();
            bool terminated = false;
            try { powershell.Invoke<PSObject, PSObject>(null, output, null); }
            catch (RuntimeException error) { terminated = true; stderr.WriteLine(error.ErrorRecord.ToString()); }
            int? nativeCode = runspace.SessionStateProxy.GetVariable("LASTEXITCODE") is int code ? code : null;
            string outcome = host.ExitCode.HasValue ? "explicit_exit" : terminated ? "terminating_error" : "completed_normally";
            var result = new WorkerResult("completed", outcome, host.ExitCode ?? (terminated ? 1 : 0), hadErrors || terminated,
                stdout.ToString(), stderr.ToString(), watch.Elapsed.TotalMilliseconds, stdout.Truncated || stderr.Truncated, nativeCode);
            await writer.WriteLineAsync(JsonSerializer.Serialize(result));
            if (host.ExitCode.HasValue) break;
        }
    }
}

internal sealed class InvocationHost : PSHost {
    public int? ExitCode { get; set; }
    public override Guid InstanceId { get; } = Guid.NewGuid();
    public override string Name => "RmmExecutionWorker";
    public override Version Version => new(1, 0);
    public override PSHostUserInterface UI => null!;
    public override CultureInfo CurrentCulture => CultureInfo.InvariantCulture;
    public override CultureInfo CurrentUICulture => CultureInfo.InvariantCulture;
    public override void SetShouldExit(int exitCode) => ExitCode = exitCode;
    public override void EnterNestedPrompt() => throw new NotSupportedException();
    public override void ExitNestedPrompt() => throw new NotSupportedException();
    public override void NotifyBeginApplication() { }
    public override void NotifyEndApplication() { }
}
