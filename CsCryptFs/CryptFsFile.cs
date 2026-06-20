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
            FileSize = FileContentSizeCrypto.GetPlaintextSize(attributes.FileSize.GetValueOrDefault()),
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
        return new CryptFsStream(innerStream, Config.ContentKey, isReadOnly: true);
    }

    /// <inheritdoc/>
    public async Task<Stream> OpenWriteAsync(FileMode fileMode, CancellationToken cancellationToken)
    {
        if (inner is not IWritable writable)
        {
            throw new InvalidOperationException("Inner file does not support writing");
        }
        if (fileMode == FileMode.OpenOrCreate || fileMode == FileMode.Append || fileMode == FileMode.CreateNew)
        {
            await EnsureLongNameFileExistsAsync(cancellationToken).ConfigureAwait(false);
        }
        Stream innerStream = await writable.OpenWriteAsync(fileMode, cancellationToken).ConfigureAwait(false);
        return new CryptFsStream(innerStream, Config.ContentKey, isReadOnly: false);
    }

    /// <inheritdoc/>
    public async Task<Stream> OpenReadWriteAsync(FileMode fileMode, CancellationToken cancellationToken)
    {
        if (inner is not IReadableWriteable readableWriteable)
        {
            throw new InvalidOperationException("Inner file does not support read-write access");
        }
        if (fileMode == FileMode.OpenOrCreate || fileMode == FileMode.Append || fileMode == FileMode.CreateNew)
        {
            await EnsureLongNameFileExistsAsync(cancellationToken).ConfigureAwait(false);
        }
        Stream innerStream = await readableWriteable
            .OpenReadWriteAsync(fileMode, cancellationToken)
            .ConfigureAwait(false);
        return new CryptFsStream(innerStream, Config.ContentKey, isReadOnly: false);
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
