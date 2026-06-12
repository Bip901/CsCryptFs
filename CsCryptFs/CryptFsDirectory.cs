using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FileAbstractions;

namespace CsCryptFs;

/// <summary>
/// A gocryptfs volume.
/// </summary>
public class CryptFsDirectory : CryptFsFileOrDirectory, IVirtualDirectory, IDisposable
{
    private const string CONFIG_FILE_NAME = "gocryptfs.conf";
    private static readonly byte[] EMPTY_TWEAK = new byte[16];

    private CryptFsDirectory(
        CryptFsConfigWithKeys config,
        IVirtualDirectory inner,
        IVirtualDirectory? innerParent,
        IVirtualFile? longNameFile
    )
        : base(config, inner, innerParent, longNameFile) { }

    /// <summary>
    /// Creates a new cryptfs volume in the given directory.
    /// The <paramref name="inner"/> directory must be existing and empty.
    /// </summary>
    /// <param name="inner">The inner directory to wrap.</param>
    /// <param name="config">The configuration and keys to use.</param>
    /// <param name="cancellationToken"></param>
    /// <exception cref="InvalidOperationException"></exception>
    public static async Task<CryptFsDirectory> CreateNewAsync(
        IVirtualDirectory inner,
        CryptFsConfigWithKeys config,
        CancellationToken cancellationToken = default
    )
    {
        if (inner.GetChildFile(CONFIG_FILE_NAME) is not IWritable writable)
        {
            throw new InvalidOperationException($"Config file {CONFIG_FILE_NAME} is not writable");
        }
        if (await inner.ListChildren(cancellationToken).AnyAsync(cancellationToken))
        {
            throw new InvalidOperationException("Refusing to initialize cryptfs in a non-empty directory");
        }
        await using Stream writeStream = await writable
            .OpenWriteAsync(FileMode.CreateNew, cancellationToken)
            .ConfigureAwait(false);
        await writeStream.WriteAsync(config.Config.Serialize(), cancellationToken).ConfigureAwait(false);
        return new CryptFsDirectory(config, inner, null, null);
    }

    /// <summary>
    /// Opens the given directory as an existing cryptfs volume.
    /// </summary>
    /// <param name="inner">The inner directory to wrap.</param>
    /// <param name="cancellationToken">Optionally, a cancellation token.</param>
    /// <param name="password">The password to use for encrypting/decrypting the files. Exactly one of this or <paramref name="kek"/> must be non-null.</param>
    /// <param name="kek">The key derived from <paramref name="password"/>. Exactly one of this or <paramref name="password"/> must be non-null.</param>
    /// <returns>A new <see cref="CryptFsDirectory"/> instance over the given directory.</returns>
    /// <exception cref="ArgumentException"/>
    /// <exception cref="InvalidOperationException"/>
    /// <exception cref="InvalidDataException"/>
    /// <exception cref="OperationCanceledException"/>
    public static async Task<CryptFsDirectory> OpenExistingAsync(
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
        return new CryptFsDirectory(configWithKeys, inner, null, null);
    }

    public IVirtualFile GetChildFile(ReadOnlySpan<char> name)
    {
        SanitizeName(name);
        string shortEncryptedName = GetShortEncryptedName(name.ToString());
        IVirtualDirectory innerDir = (IVirtualDirectory)inner;
        IVirtualFile newInner = innerDir.GetChildFile(shortEncryptedName);
        IVirtualFile? longNameFile = null;
        if (shortEncryptedName.StartsWith(FileNameCrypto.LONGNAME_FILE_PREFIX))
        {
            longNameFile = innerDir.GetChildFile(shortEncryptedName + FileNameCrypto.LONGNAME_NAME_FILE_SUFFIX);
        }
        return new CryptFsFile(Config, newInner, innerDir, longNameFile);
    }

    public IVirtualDirectory GetChildDir(ReadOnlySpan<char> name)
    {
        SanitizeName(name);
        string shortEncryptedName = GetShortEncryptedName(name.ToString());
        IVirtualDirectory innerDir = (IVirtualDirectory)inner;
        IVirtualDirectory newInner = innerDir.GetChildDir(shortEncryptedName);
        IVirtualFile? longNameFile = null;
        if (shortEncryptedName.StartsWith(FileNameCrypto.LONGNAME_FILE_PREFIX))
        {
            longNameFile = innerDir.GetChildFile(shortEncryptedName + FileNameCrypto.LONGNAME_NAME_FILE_SUFFIX);
        }
        return new CryptFsDirectory(Config, newInner, innerDir, longNameFile);
    }

    public Task<IVirtualDirectory> MakeDirAsync(
        ReadOnlySpan<char> name,
        FileAbstractions.FileAttributes attributes,
        CancellationToken cancellationToken
    )
    {
        SanitizeName(name);
        return MakeDirInternalAsync(name.ToString(), attributes, cancellationToken);
    }

    private async Task<IVirtualDirectory> MakeDirInternalAsync(
        string name,
        FileAbstractions.FileAttributes attributes,
        CancellationToken cancellationToken
    )
    {
        (string shortEncryptedName, IVirtualFile? longNameFile) = await EnsureNameAsync(
                name,
                EMPTY_TWEAK,
                cancellationToken
            )
            .ConfigureAwait(false);
        IVirtualDirectory newInnerDir = await ((IVirtualDirectory)inner).MakeDirAsync(
            shortEncryptedName,
            attributes,
            cancellationToken
        );
        return new CryptFsDirectory(Config, newInnerDir, (IVirtualDirectory)inner, longNameFile);
    }

    public async IAsyncEnumerable<FileEntry> ListChildren([EnumeratorCancellation] CancellationToken cancellationToken)
    {
        await foreach (FileEntry fileEntry in ((IVirtualDirectory)inner).ListChildren(cancellationToken))
        {
            // Base64URL does not include '.', so checking for the '.name' suffix is sufficient
            if (fileEntry.Name == CONFIG_FILE_NAME || fileEntry.Name.EndsWith(FileNameCrypto.LONGNAME_NAME_FILE_SUFFIX))
            {
                continue;
            }
            string fullEncryptedFileName = await GetFullEncryptedNameAsync(
                    (IVirtualDirectory)inner,
                    fileEntry.Name,
                    cancellationToken
                )
                .ConfigureAwait(false);
            string decryptedFileName = Config.FileNameCrypto.Decrypt(fullEncryptedFileName, EMPTY_TWEAK);
            yield return new FileEntry(decryptedFileName, fileEntry.Attributes);
        }
    }

    private string GetShortEncryptedName(string name)
    {
        return Config.FileNameCrypto.Encrypt(name, EMPTY_TWEAK, Config.Config.LongNameMax);
    }

    private static async Task<string> GetFullEncryptedNameAsync(
        IVirtualDirectory parent,
        string shortEncryptedName,
        CancellationToken cancellationToken
    )
    {
        if (!shortEncryptedName.StartsWith(FileNameCrypto.LONGNAME_FILE_PREFIX))
        {
            return shortEncryptedName;
        }
        string nameFileName = shortEncryptedName + FileNameCrypto.LONGNAME_NAME_FILE_SUFFIX;
        if (parent.GetChildFile(nameFileName) is not IReadable readable)
        {
            throw new InvalidOperationException($"File {nameFileName} is not readable!");
        }
        await using Stream stream = await readable
            .OpenReadAsync(FileMode.Open, cancellationToken)
            .ConfigureAwait(false);
        using StreamReader streamReader = new(stream, Encoding.UTF8, leaveOpen: true);
        return await streamReader.ReadToEndAsync(cancellationToken).ConfigureAwait(false);
    }

    public IVirtualFileOrDirectory GetExistingChild(ReadOnlySpan<char> name)
    {
        throw new NotSupportedException();
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
        Config.Dispose();
    }
}
