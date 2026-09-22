using System.Security.AccessControl;
using System.Security.Principal;
using System.Runtime.Versioning;
using System.Text.Json;

namespace EndpointAgent;

internal interface IEnrollmentStatus {
    void Pending(string? code);
    void Online(Guid device);
    void Unavailable(string reason);
}

internal sealed class ConsoleEnrollmentStatus : IEnrollmentStatus {
    public void Pending(string? code) => Console.WriteLine(code is null ? "pending" : "PAIRING_CODE " + code);
    public void Online(Guid device) => Console.WriteLine("online " + device);
    public void Unavailable(string reason) => Console.Error.WriteLine(reason);
}

[SupportedOSPlatform("windows")]
internal sealed class FileEnrollmentStatus : IEnrollmentStatus {
    private static readonly JsonSerializerOptions Json = new(JsonSerializerDefaults.Web) { WriteIndented = true };
    private readonly string path;

    public FileEnrollmentStatus(string path) {
        this.path = path;
        var directory = Path.GetDirectoryName(path)!;
        Directory.CreateDirectory(directory);
        if (OperatingSystem.IsWindows()) {
            var security = new DirectorySecurity();
            security.SetAccessRuleProtection(isProtected: true, preserveInheritance: false);
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null),
                FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            security.AddAccessRule(new FileSystemAccessRule(
                new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null),
                FileSystemRights.FullControl, InheritanceFlags.ContainerInherit | InheritanceFlags.ObjectInherit,
                PropagationFlags.None, AccessControlType.Allow));
            new DirectoryInfo(directory).SetAccessControl(security);
        }
    }

    public void Pending(string? code) => Write(new {
        state = "pending",
        pairing_code = code,
        ready = false,
        updated_at = DateTimeOffset.UtcNow,
    });

    public void Online(Guid device) => Write(new {
        state = "online",
        device_id = device,
        ready = true,
        updated_at = DateTimeOffset.UtcNow,
    });

    public void Unavailable(string reason) => Write(new {
        state = "unavailable",
        reason,
        ready = false,
        updated_at = DateTimeOffset.UtcNow,
    });

    private void Write<T>(T status) {
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(status, Json));
        File.Move(temp, path, overwrite: true);
    }
}

internal static class EnrollmentStatus {
    public static readonly IEnrollmentStatus Console = new ConsoleEnrollmentStatus();
}
