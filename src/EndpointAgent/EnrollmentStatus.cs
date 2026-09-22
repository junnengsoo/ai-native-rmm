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
    private string? pairingCode;

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
        pairingCode = ExistingPairingCode();
    }

    public void Pending(string? code) {
        pairingCode = code ?? pairingCode;
        Write(new {
            state = "pending",
            pairing_code = pairingCode,
            ready = false,
            updated_at = DateTimeOffset.UtcNow,
        });
    }

    public void Online(Guid device) {
        pairingCode = null;
        Write(new {
            state = "online",
            device_id = device,
            ready = true,
            updated_at = DateTimeOffset.UtcNow,
        });
    }

    public void Unavailable(string reason) => Write(new {
        state = "unavailable",
        reason,
        pairing_code = pairingCode,
        ready = false,
        updated_at = DateTimeOffset.UtcNow,
    });

    private string? ExistingPairingCode() {
        try {
            if (!File.Exists(path)) return null;
            using var document = JsonDocument.Parse(File.ReadAllText(path));
            var status = document.RootElement;
            if (status.TryGetProperty("pairing_code", out var code) && code.GetString() is { } value
                && value.Length == 12
                && value.All(c => c is >= 'A' and <= 'Z' or >= '2' and <= '7')) return value;
        } catch (IOException) { }
        catch (JsonException) { }
        return null;
    }

    private void Write<T>(T status) {
        var temp = path + ".tmp";
        File.WriteAllText(temp, JsonSerializer.Serialize(status, Json));
        File.Move(temp, path, overwrite: true);
    }
}

internal static class EnrollmentStatus {
    public static readonly IEnrollmentStatus Console = new ConsoleEnrollmentStatus();
}
