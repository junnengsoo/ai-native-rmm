namespace EndpointAgent;

internal static class EndpointPaths {
    public static string DataDirectory =>
        Environment.GetEnvironmentVariable("RMM_ENDPOINT_DATA_DIR")
        ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
            "Prosper", "AiNativeRmm");

    public static string StatusPath => Path.Combine(DataDirectory, "status.json");
}
