using System.Text;

namespace EndpointAgent;

// The engine must keep draining after the retention bound is reached.
internal sealed class BoundedOutput : TextWriter {
    private const int PreviewLimit = 8192;
    private const int CaptureLimit = 1024 * 1024;
    private const int ChunkLimit = 8192;
    private readonly StringBuilder preview = new();
    private readonly Action<string>? onRetained;
    private int retainedBytes;
    private int previewBytes;
    public BoundedOutput(Action<string>? onRetained = null) { NewLine = "\n"; this.onRetained = onRetained; }
    public override Encoding Encoding => Encoding.UTF8;
    public bool Truncated { get; private set; }
    public override void Write(char value) => Write(value.ToString());
    public override void Write(string? value) {
        if (value is null) return;
        lock (preview) {
            int retainedCount = 0;
            for (int index = 0; index < value.Length;) {
                int charCount = char.IsHighSurrogate(value[index]) && index + 1 < value.Length ? 2 : 1;
                int byteCount = Encoding.UTF8.GetByteCount(value.AsSpan(index, charCount));
                if (retainedBytes + byteCount > CaptureLimit) break;
                retainedBytes += byteCount;
                retainedCount += charCount;
                index += charCount;
            }
            if (retainedCount > 0) {
                for (int offset = 0; offset < retainedCount;) {
                    int count = Math.Min(ChunkLimit, retainedCount - offset);
                    if (count > 0 && offset + count < retainedCount && char.IsHighSurrogate(value[offset + count - 1]))
                        count--;
                    onRetained?.Invoke(value.Substring(offset, count));
                    offset += count;
                }
                for (int index = 0; index < retainedCount;) {
                    string character = char.IsHighSurrogate(value[index]) && index + 1 < retainedCount
                        ? value.Substring(index, 2)
                        : value[index].ToString();
                    int byteCount = Encoding.UTF8.GetByteCount(character);
                    if (previewBytes + byteCount > PreviewLimit) break;
                    preview.Append(character);
                    previewBytes += byteCount;
                    index += character.Length;
                }
            }
            Truncated |= retainedCount != value.Length;
        }
    }
    public override string ToString() { lock (preview) return preview.ToString(); }
}
