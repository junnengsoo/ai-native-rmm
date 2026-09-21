using System.Text;

namespace EndpointAgent;

// The engine must keep draining after the retention bound is reached.
internal sealed class BoundedOutput : TextWriter {
    private const int Limit = 32768;
    private readonly StringBuilder content = new();
    private readonly Action<string>? onRetained;
    public BoundedOutput(Action<string>? onRetained = null) { NewLine = "\n"; this.onRetained = onRetained; }
    public override Encoding Encoding => Encoding.UTF8;
    public bool Truncated { get; private set; }
    public override void Write(char value) => Write(value.ToString());
    public override void Write(string? value) {
        if (value is null) return;
        lock (content) {
            int count = Math.Min(value.Length, Limit - content.Length);
            if (count > 0 && count < value.Length && char.IsHighSurrogate(value[count - 1])) count--;
            content.Append(value, 0, count);
            Truncated |= count != value.Length;
            if (count > 0) onRetained?.Invoke(value[..count]);
        }
    }
    public override string ToString() { lock (content) return content.ToString(); }
}
