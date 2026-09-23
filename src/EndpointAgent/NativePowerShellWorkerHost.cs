using System.Diagnostics;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Text;

namespace EndpointAgent;

[SupportedOSPlatform("windows")]
internal static class NativePowerShellWorkerHost {
    public static async Task<int> Run(string pipeName) {
        string script = Path.Combine(AppContext.BaseDirectory, "NativePowerShellWorker.ps1");
        if (!File.Exists(script)) throw new FileNotFoundException("worker_script_missing", script);
        using var process = Process.Start(new ProcessStartInfo(NativeWindowsPowerShell()) {
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            CreateNoWindow = true,
            ArgumentList = {
                "-NoLogo", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
                "-File", script, "-PipeName", pipeName,
            },
        }) ?? throw new InvalidOperationException("worker_start_failed");
        _ = Drain(process.StandardOutput);
        _ = Drain(process.StandardError);
        await process.WaitForExitAsync();
        return process.ExitCode;
    }

    private static async Task Drain(StreamReader stream) {
        while (await stream.ReadLineAsync() is { } line) {
            if (line.StartsWith("startup_failed:", StringComparison.Ordinal) && line.Length < 100)
                Console.Error.WriteLine(line);
        }
    }

    private static string NativeWindowsPowerShell() {
        if (!Environment.Is64BitProcess) throw new PlatformNotSupportedException("native_64_bit_powershell_required");
        var system = new StringBuilder(260);
        uint length = GetSystemDirectoryW(system, (uint)system.Capacity);
        if (length >= (uint)system.Capacity) {
            system.Capacity = checked((int)length + 1);
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
