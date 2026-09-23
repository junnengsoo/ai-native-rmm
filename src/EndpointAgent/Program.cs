using EndpointAgent;

try {
    if (args is ["--worker", var pipeName]) {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        return await NativePowerShellWorkerHost.Run(pipeName);
    }
    if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
    if (args is ["--enroll", var endpoint, var keyName])
        await Enrollment.Run(new Uri(endpoint), keyName);
    else if (args is ["--service"])
        WindowsServiceHost.RunService();
    else if (args is ["--service-console"])
        await WindowsServiceHost.RunConsoleService(CancellationToken.None);
    else if (args is ["--service-uninstall-cleanup"])
        WindowsServiceHost.CleanupInstalledState();
    else if (args is ["--service-uninstall-cleanup", var cleanupKeyName])
        WindowsServiceHost.CleanupInstalledState(cleanupKeyName);
    else if (args is ["--agent", var url, var certificate, var serverPin, var device])
        await Agent.Run(new Uri(url), certificate, serverPin, device);
    else throw new ArgumentException();
    return 0;
} catch (Exception error) {
    // Metadata only. Never echo configuration, exceptions, scripts, or credentials.
    Console.Error.WriteLine("endpoint_stopped: " + error.GetType().Name);
    return 1;
}
