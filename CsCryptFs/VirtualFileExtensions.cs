using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FileAbstractions;

namespace CsCryptFs;

/// <summary>
/// Extension methods for <see cref="IVirtualFile"/>.
/// </summary>
public static class VirtualFileExtensions
{
    /// <summary>
    /// Reads the entire content of a file as a string using UTF-8 encoding.
    /// </summary>
    /// <returns>A task that represents the asynchronous read operation, containing the file content string.</returns>
    public static async Task<string> ReadAllTextAsync(
        this IReadable readable,
        FileMode fileMode,
        CancellationToken cancellationToken
    )
    {
        await using Stream stream = await readable
            .OpenReadAsync(fileMode, new StreamOptions() { SeekingDesired = false }, cancellationToken)
            .ConfigureAwait(false);
        using StreamReader streamReader = new(stream, leaveOpen: true);
        return await streamReader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
    }

    /// <summary>
    /// Writes the specified string to a file using UTF-8 encoding, truncating it.
    /// </summary>
    /// <returns>A task that represents the asynchronous write operation.</returns>
    public static async Task WriteAllTextAsync(
        this IWritable writable,
        FileMode fileMode,
        string text,
        CancellationToken cancellationToken
    )
    {
        await using Stream stream = await writable
            .OpenWriteAsync(fileMode, new StreamOptions() { SeekingDesired = false }, cancellationToken)
            .ConfigureAwait(false);
        await using StreamWriter writer = new(stream, leaveOpen: true);
        await writer.WriteAsync(text.AsMemory(), cancellationToken).ConfigureAwait(false);
    }
}
