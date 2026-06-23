using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using FileAbstractions;
using FileAttributes = FileAbstractions.FileAttributes;

namespace CsCryptFs;

/// <summary>
/// A file backed by another <see cref="IVirtualFile"/> and encrypted/decrypted on-the-fly.
/// </summary>
public class CryptFsFile : CryptFsFileOrDirectory, IReadableVirtualFile, IReadableWriteable
{
    internal CryptFsFile(
        CryptFsConfigWithKeys config,
        IVirtualFileOrDirectory inner,
        CryptFsDirectory parent,
        IVirtualFile? longNameFile,
        string fullEncryptedName
    )
        : base(config, inner, parent, longNameFile, fullEncryptedName) { }

    /// <inheritdoc/>
    public override async Task<FileAttributes> GetAttributesAsync(CancellationToken cancellationToken)
    {
        FileAttributes attributes = await inner.GetAttributesAsync(cancellationToken).ConfigureAwait(false);
        return attributes with
        {
            FileSize = (ulong)FileContentCrypto.GetPlaintextSize((long)attributes.FileSize.GetValueOrDefault()),
        };
    }

    /// <inheritdoc/>
    public async Task<Stream> OpenReadAsync(FileMode fileMode, CancellationToken cancellationToken)
    {
        if (inner is not IReadable readable)
        {
            throw new InvalidOperationException("Inner file does not support reading");
        }
        if (fileMode == FileMode.OpenOrCreate)
        {
            await EnsureLongNameFileExistsAsync(cancellationToken).ConfigureAwait(false);
        }
        Stream innerStream = await readable.OpenReadAsync(fileMode, cancellationToken).ConfigureAwait(false);
        return new CryptFsStream(innerStream, Config.ContentKey);
    }

    /// <inheritdoc/>
    public async Task<Stream> OpenWriteAsync(FileMode fileMode, CancellationToken cancellationToken)
    {
        if (inner is not IWritable writable)
        {
            throw new InvalidOperationException("Inner file does not support writing");
        }
        if (fileMode != FileMode.Truncate && fileMode != FileMode.Create && fileMode != FileMode.CreateNew)
        {
            // Truncate and similar modes are easier to implement because there is no need to pre-read the header - data is just overwritten completely
            throw new NotSupportedException($"File mode {fileMode} is currently not supported for writes");
        }
        if (fileMode != FileMode.Open && fileMode != FileMode.Truncate) // These modes require the file to exist anyway, so there is no need to ensure its name exists
        {
            await EnsureLongNameFileExistsAsync(cancellationToken).ConfigureAwait(false);
        }
        Stream innerStream = await writable.OpenWriteAsync(fileMode, cancellationToken).ConfigureAwait(false);
        return new CryptFsStream(innerStream, Config.ContentKey);
    }

    /// <inheritdoc/>
    public async Task<Stream> OpenReadWriteAsync(FileMode fileMode, CancellationToken cancellationToken)
    {
        throw new NotSupportedException($"Read-write access is not currently supported");
    }

    private Task EnsureLongNameFileExistsAsync(CancellationToken cancellationToken)
    {
        if (longNameFile == null)
        {
            return Task.CompletedTask;
        }
        if (longNameFile is not IWritable writable)
        {
            throw new InvalidOperationException("Long name file is not writable");
        }
        return writable.WriteAllTextAsync(FileMode.Create, fullEncryptedName!, cancellationToken);
    }
}
