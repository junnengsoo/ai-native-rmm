using EndpointAgent;

try {
    if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
    if (args is ["--worker", var pipe]) await PowerShellWorker.Run(pipe);
    else if (args is ["--agent", var url, var certificate, var serverPin, var device])
        await Agent.Run(new Uri(url), certificate, serverPin, device);
    else throw new ArgumentException();
    return 0;
} catch (Exception error) {
    // Metadata only. Never echo configuration, exceptions, scripts, or credentials.
    Console.Error.WriteLine("endpoint_stopped: " + error.GetType().Name);
    return 1;
}
