using System.ServiceProcess;
using System.Security.Cryptography;
using System.Runtime.Versioning;
using Microsoft.Win32;

namespace EndpointAgent;

[SupportedOSPlatform("windows")]
internal sealed class WindowsServiceHost : ServiceBase {
    public const string ServiceNameValue = "SquashEndpointAgent";
    public const string RegistryPath = @"SOFTWARE\Prosper\AiNativeRmm";
    public const string DefaultKeyName = "SquashEndpointAgent";
    public static string DataDirectory => EndpointPaths.DataDirectory;
    public static string StatusPath => EndpointPaths.StatusPath;

    private CancellationTokenSource? cancellation;
    private Task? runTask;

    public WindowsServiceHost() {
        ServiceName = ServiceNameValue;
        CanStop = true;
        CanShutdown = true;
    }

    public static void RunService() => ServiceBase.Run(new WindowsServiceHost());

    public static async Task RunConsoleService(CancellationToken cancellationToken) {
        var config = ReadConfig();
        await Enrollment.Run(config.Endpoint, config.KeyName, new FileEnrollmentStatus(StatusPath), cancellationToken);
    }

    protected override void OnStart(string[] args) {
        cancellation = new CancellationTokenSource();
        runTask = Task.Run(async () => {
            try { await RunConsoleService(cancellation.Token); }
            catch (OperationCanceledException) when (cancellation.IsCancellationRequested) { }
            catch (Exception error) {
                new FileEnrollmentStatus(StatusPath).Unavailable("service_failed_" + error.GetType().Name);
                throw;
            }
        });
    }

    protected override void OnStop() => StopWorker();

    protected override void OnShutdown() => StopWorker();

    private void StopWorker() {
        if (cancellation is null || runTask is null) return;
        cancellation.Cancel();
        try {
            if (!runTask.Wait(TimeSpan.FromSeconds(10)))
                Environment.Exit(0);
        }
        catch (AggregateException error) when (error.InnerExceptions.All(e => e is OperationCanceledException)) { }
        cancellation.Dispose();
        cancellation = null;
        runTask = null;
    }

    public static ServiceConfig ReadConfig() {
        using var key = Registry.LocalMachine.OpenSubKey(RegistryPath, writable: false)
            ?? throw new InvalidOperationException("missing_service_configuration");
        string endpoint = key.GetValue("Endpoint") as string ?? "";
        string keyName = key.GetValue("KeyName") as string ?? "";
        if (!Uri.TryCreate(endpoint, UriKind.Absolute, out var uri)) throw new InvalidOperationException("invalid_endpoint");
        if (string.IsNullOrWhiteSpace(keyName)) throw new InvalidOperationException("invalid_key_name");
        return new(uri, keyName);
    }

    public static void CleanupInstalledState(string? configuredKeyName = null) {
        string keyName = configuredKeyName ?? TryReadConfiguredKeyName() ?? DefaultKeyName;
        if (File.Exists(StatusPath)) File.Delete(StatusPath);
        if (Directory.Exists(DataDirectory) && !Directory.EnumerateFileSystemEntries(DataDirectory).Any())
            Directory.Delete(DataDirectory);
        if (OperatingSystem.IsWindows() && CngKey.Exists(keyName)) {
            using var key = CngKey.Open(keyName);
            key.Delete();
        }
    }

    private static string? TryReadConfiguredKeyName() {
        try {
            using var key = Registry.LocalMachine.OpenSubKey(RegistryPath, writable: false);
            return key?.GetValue("KeyName") as string;
        } catch { return null; }
    }

}

internal sealed record ServiceConfig(Uri Endpoint, string KeyName);
