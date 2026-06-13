using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using FileAbstractions;

namespace CsCryptFs;

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
        await using Stream innerStream = await readable
            .OpenReadAsync(fileMode, cancellationToken)
            .ConfigureAwait(false);
        return await CryptContentCrypto
            .OpenReadAsync(innerStream, Config.ContentKey, cancellationToken)
            .ConfigureAwait(false);
    }

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
        return CryptContentCrypto.OpenWrite(innerStream, Config.ContentKey);
    }

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
        return await CryptContentCrypto
            .OpenReadWriteAsync(innerStream, Config.ContentKey, cancellationToken)
            .ConfigureAwait(false);
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
