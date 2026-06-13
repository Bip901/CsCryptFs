using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FileAbstractions;

namespace CsCryptFs;

public static class VirtualFileExtensions
{
    public static async Task<string> ReadAllTextAsync(
        this IReadable readable,
        FileMode fileMode,
        CancellationToken cancellationToken
    )
    {
        await using Stream stream = await readable.OpenReadAsync(fileMode, cancellationToken).ConfigureAwait(false);
        using StreamReader streamReader = new(stream, Encoding.UTF8, leaveOpen: true);
        return await streamReader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
    }

    public static async Task WriteAllTextAsync(
        this IWritable writable,
        FileMode fileMode,
        string text,
        CancellationToken cancellationToken
    )
    {
        await using Stream stream = await writable.OpenWriteAsync(fileMode, cancellationToken).ConfigureAwait(false);
        using StreamWriter writer = new(stream, Encoding.UTF8, leaveOpen: true);
        writer.Write(text);
    }
}
