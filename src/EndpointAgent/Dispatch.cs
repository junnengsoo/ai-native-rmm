using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace EndpointAgent;

internal sealed record Dispatch(string Type, string SessionId, string? ExecutionId, string? Script,
    string? ScriptSha256, int TimeoutMs) {
    // Reject ambiguous JSON, unknown fields and mismatched resource/content bindings.
    public static Dispatch? Parse(JsonElement request, string device) {
        try {
            string type = request.GetProperty("type").GetString()!;
            string[] fields = type switch {
                "open_session" => ["type", "deviceId", "sessionId"],
                "close_session" => ["type", "deviceId", "sessionId"],
                "cancel_execution" => ["type", "deviceId", "sessionId", "executionId"],
                "execute" => ["type", "deviceId", "sessionId", "executionId", "script", "scriptSha256"],
                _ => []
            };
            var names = request.EnumerateObject().Select(property => property.Name).ToArray();
            string[] allowed = type == "execute" ? [..fields, "timeoutMs"] : fields;
            if (fields.Length == 0 || names.Distinct(StringComparer.Ordinal).Count() != names.Length
                || fields.Except(names, StringComparer.Ordinal).Any()
                || names.Except(allowed, StringComparer.Ordinal).Any()
                || request.GetProperty("deviceId").GetString() != device) return null;
            string session = request.GetProperty("sessionId").GetString()!;
            if (!Guid.TryParseExact(session, "D", out _)) return null;
            if (type is "open_session" or "close_session") return new(type, session, null, null, null, 0);
            string execution = request.GetProperty("executionId").GetString()!;
            if (!Guid.TryParseExact(execution, "D", out _)) return null;
            if (type == "cancel_execution") return new(type, session, execution, null, null, 0);
            string script = request.GetProperty("script").GetString()!;
            int timeout = request.TryGetProperty("timeoutMs", out var timeoutElement)
                ? timeoutElement.GetInt32()
                : 3600000;
            string hash = request.GetProperty("scriptSha256").GetString()!;
            if (script is null || script.Length > 32768
                || timeout is < 100 or > 3600000 || hash is null || hash.Length != 64
                || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(script)), Convert.FromHexString(hash))) return null;
            return new(type, session, execution, script, hash, timeout);
        } catch (Exception error) when (error is InvalidOperationException or KeyNotFoundException or FormatException or ArgumentException) {
            return null;
        }
    }
}
