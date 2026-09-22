using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace EndpointAgent;

internal sealed record Dispatch(string Type, string SessionId, string? ExecutionId, string? Script, int TimeoutMs,
    int IdleTimeoutMs, DateTimeOffset? AbsoluteDeadline, DateTimeOffset? StartDeadline) {
    // Reject ambiguous JSON, unknown fields and mismatched resource/content bindings.
    public static Dispatch? Parse(JsonElement request, string device) {
        try {
            string type = request.GetProperty("type").GetString()!;
            string[] fields = type switch {
                "open_session" => ["type", "deviceId", "sessionId", "idleTimeoutMs", "absoluteDeadlineUnixMs"],
                "close_session" => ["type", "deviceId", "sessionId"],
                "execute" => ["type", "deviceId", "sessionId", "executionId", "script", "scriptSha256", "timeoutMs", "startDeadlineUnixMs"],
                _ => []
            };
            var names = request.EnumerateObject().Select(property => property.Name).ToArray();
            if (fields.Length == 0 || names.Length != fields.Length || names.Distinct(StringComparer.Ordinal).Count() != names.Length
                || names.Except(fields, StringComparer.Ordinal).Any() || request.GetProperty("deviceId").GetString() != device) return null;
            string session = request.GetProperty("sessionId").GetString()!;
            if (!Guid.TryParseExact(session, "D", out _)) return null;
            if (type == "open_session") {
                int idle = request.GetProperty("idleTimeoutMs").GetInt32();
                long absolute = request.GetProperty("absoluteDeadlineUnixMs").GetInt64();
                if (idle is < 1000 or > 7200000) return null;
                var deadline = DateTimeOffset.FromUnixTimeMilliseconds(absolute);
                if (deadline <= DateTimeOffset.UtcNow || deadline > DateTimeOffset.UtcNow.AddHours(8).AddMinutes(5)) return null;
                return new(type, session, null, null, 0, idle, deadline, null);
            }
            if (type == "close_session") return new(type, session, null, null, 0, 0, null, null);
            string execution = request.GetProperty("executionId").GetString()!;
            string script = request.GetProperty("script").GetString()!;
            int timeout = request.GetProperty("timeoutMs").GetInt32();
            long startDeadline = request.GetProperty("startDeadlineUnixMs").GetInt64();
            string hash = request.GetProperty("scriptSha256").GetString()!;
            if (!Guid.TryParseExact(execution, "D", out _) || script is null || script.Length > 32768
                || timeout is < 100 or > 3600000 || hash is null || hash.Length != 64
                || !CryptographicOperations.FixedTimeEquals(SHA256.HashData(Encoding.UTF8.GetBytes(script)), Convert.FromHexString(hash))) return null;
            var startsBy = DateTimeOffset.FromUnixTimeMilliseconds(startDeadline);
            if (startsBy <= DateTimeOffset.UtcNow || startsBy > DateTimeOffset.UtcNow.AddSeconds(65)) return null;
            return new(type, session, execution, script, timeout, 0, null,
                startsBy);
        } catch (Exception error) when (error is InvalidOperationException or KeyNotFoundException or FormatException or ArgumentException) {
            return null;
        }
    }
}
