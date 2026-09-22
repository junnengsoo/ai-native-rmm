using System.Text;

namespace EndpointAgent;

// The engine must keep draining while output is forwarded in bounded chunks.
internal sealed class BoundedOutput : TextWriter {
    private const int ChunkLimit = 8192;
    private readonly Action<string>? onRetained;
    public BoundedOutput(Action<string>? onRetained = null) { NewLine = "\n"; this.onRetained = onRetained; }
    public override Encoding Encoding => Encoding.UTF8;
    public override void Write(char value) => Write(value.ToString());
    public override void Write(string? value) {
        if (value is null) return;
        lock (this) {
            foreach (var chunk in Utf8Chunks(value)) onRetained?.Invoke(chunk);
        }
    }

    private static IEnumerable<string> Utf8Chunks(string value) {
        var chunk = new StringBuilder();
        int chunkBytes = 0;
        for (int index = 0; index < value.Length;) {
            int charCount = char.IsHighSurrogate(value[index]) && index + 1 < value.Length ? 2 : 1;
            int byteCount = Encoding.UTF8.GetByteCount(value.AsSpan(index, charCount));
            if (chunk.Length > 0 && chunkBytes + byteCount > ChunkLimit) {
                yield return chunk.ToString();
                chunk.Clear();
                chunkBytes = 0;
            }
            chunk.Append(value, index, charCount);
            chunkBytes += byteCount;
            index += charCount;
        }
        if (chunk.Length > 0) yield return chunk.ToString();
    }
}
