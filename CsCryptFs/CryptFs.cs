using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FileAbstractions;

namespace CsCryptFs;

/// <summary>
/// A gocryptfs volume.
/// </summary>
public class CryptFs : IVirtualDirectory
{
    private const string CONFIG_FILE_NAME = "gocryptfs.conf";

    public CryptFsConfigWithKeys Config { get; }

    private readonly IVirtualDirectory inner;

    private CryptFs(CryptFsConfigWithKeys config, IVirtualDirectory inner)
    {
        Config = config;
        this.inner = inner;
    }

    /// <summary>
    /// Creates a new cryptfs volume in the given directory.
    /// The directory must be empty.
    /// </summary>
    /// <param name="inner">The inner directory to wrap.</param>
    /// <param name="password">The password to use for encrypting/decrypting the files. Exactly one of this or <paramref name="kek"/> must be non-null.</param>
    /// <param name="kek">The key derived from <paramref name="password"/>. Exactly one of this or <paramref name="password"/> must be non-null.</param>
    /// <param name="cancellationToken"></param>
    /// <exception cref="InvalidOperationException"></exception>
    public static async Task<CryptFs> CreateNewAsync(
        IVirtualDirectory inner,
        string? password = null,
        byte[]? kek = null,
        CancellationToken cancellationToken = default
    )
    {
        if (password == null && kek == null)
        {
            throw new ArgumentException("No password nor key were given.", nameof(password));
        }
        if (password != null && kek != null)
        {
            throw new ArgumentException("Both a password and a key were given.", nameof(kek));
        }
        if (inner.GetChildFile(CONFIG_FILE_NAME) is not IWritable writable)
        {
            throw new InvalidOperationException($"Config file {CONFIG_FILE_NAME} is not writable");
        }
        if (await inner.ListChildren(cancellationToken).AnyAsync(cancellationToken))
        {
            throw new InvalidOperationException("Refusing to initialize cryptfs in a non-empty directory");
        }
        CryptFsConfigWithKeys configWithKeys;
        if (password != null)
        {
            configWithKeys = await CryptFsConfigWithKeys.CreateNewAsync(password).ConfigureAwait(false);
        }
        else
        {
            configWithKeys = CryptFsConfigWithKeys.CreateNew(kek!);
        }
        await using Stream writeStream = await writable
            .OpenWriteAsync(FileMode.CreateNew, cancellationToken)
            .ConfigureAwait(false);
        await writeStream.WriteAsync(configWithKeys.Config.Serialize(), cancellationToken).ConfigureAwait(false);
        return new CryptFs(configWithKeys, inner);
    }

    /// <summary>
    /// Opens the given directory as an existing cryptfs volume.
    /// </summary>
    /// <param name="inner">The inner directory to wrap.</param>
    /// <param name="cancellationToken">Optionally, a cancellation token.</param>
    /// <param name="password">The password to use for encrypting/decrypting the files. Exactly one of this or <paramref name="kek"/> must be non-null.</param>
    /// <param name="kek">The key derived from <paramref name="password"/>. Exactly one of this or <paramref name="password"/> must be non-null.</param>
    /// <returns>A new <see cref="CryptFs"/> instance over the given directory.</returns>
    /// <exception cref="ArgumentException"/>
    /// <exception cref="InvalidOperationException"/>
    /// <exception cref="InvalidDataException"/>
    /// <exception cref="OperationCanceledException"/>
    public static async Task<CryptFs> OpenExistingAsync(
        IVirtualDirectory inner,
        string? password = null,
        byte[]? kek = null,
        CancellationToken cancellationToken = default
    )
    {
        if (password == null && kek == null)
        {
            throw new ArgumentException("No password nor key were given.", nameof(password));
        }
        if (password != null && kek != null)
        {
            throw new ArgumentException("Both a password and a key were given.", nameof(kek));
        }
        IVirtualFile configFile = inner.GetChildFile(CONFIG_FILE_NAME);
        if (configFile is not IReadable readable)
        {
            throw new InvalidOperationException($"Config file {CONFIG_FILE_NAME} is not readable");
        }
        CryptFsConfig config;
        try
        {
            await using Stream readStream = await readable
                .OpenReadAsync(FileMode.OpenOrCreate, cancellationToken)
                .ConfigureAwait(false);
            using MemoryStream memoryStream = new();
            await readStream.CopyToAsync(memoryStream, cancellationToken).ConfigureAwait(false);
            if (!memoryStream.TryGetBuffer(out ArraySegment<byte> buffer))
            {
                throw new InvalidOperationException();
            }
            config = CryptFsConfig.DeserializeAndValidate(buffer);
        }
        catch (FileNotFoundException ex)
        {
            throw new InvalidOperationException($"Config file {CONFIG_FILE_NAME} does not exist", ex);
        }
        CryptFsConfigWithKeys configWithKeys;
        if (kek != null)
        {
            configWithKeys = CryptFsConfigWithKeys.Load(config, kek);
        }
        else
        {
            configWithKeys = await CryptFsConfigWithKeys.LoadAsync(config, password!).ConfigureAwait(false);
        }
        return new CryptFs(configWithKeys, inner);
    }

    public IVirtualDirectory GetDescendantDirectory(ReadOnlySpan<char> relativePath)
    {
        return new CryptFs(Config, inner.GetDescendantDirectory(relativePath));
    }

    public IVirtualFile GetChildFile(ReadOnlySpan<char> name)
    {
        throw new NotImplementedException(); // TODO
    }

    public IVirtualDirectory GetChildDir(ReadOnlySpan<char> name)
    {
        throw new NotImplementedException(); // TODO
    }

    public Task<IVirtualDirectory> MakeDirAsync(
        ReadOnlySpan<char> name,
        FileAbstractions.FileAttributes attributes,
        CancellationToken cancellationToken
    )
    {
        throw new NotImplementedException(); // TODO
    }

    public IAsyncEnumerable<FileEntry> ListChildren(CancellationToken cancellationToken)
    {
        throw new NotImplementedException(); // TODO
    }

    public Task DeleteAsync(CancellationToken cancellationToken)
    {
        throw new NotImplementedException(); // TODO
    }

    public Task<FileAbstractions.FileAttributes> GetAttributesAsync(CancellationToken cancellationToken)
    {
        throw new NotImplementedException(); // TODO
    }

    public Task SetAttributesAsync(FileAbstractions.FileAttributes attributes, CancellationToken cancellationToken)
    {
        throw new NotImplementedException(); // TODO
    }

    public IVirtualFileOrDirectory GetExistingChild(ReadOnlySpan<char> name)
    {
        throw new NotSupportedException();
    }

    public Task RenameAsync(string newName, bool allowOverwrite, CancellationToken cancellationToken)
    {
        throw new NotSupportedException();
    }

    public Task MoveToAsync(
        IVirtualDirectory newParent,
        string newName,
        bool allowOverwrite,
        CancellationToken cancellationToken
    )
    {
        throw new NotSupportedException();
    }
}
