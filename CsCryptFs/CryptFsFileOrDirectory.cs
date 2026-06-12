using System;
using System.IO;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using FileAbstractions;
using FileAttributes = FileAbstractions.FileAttributes;

namespace CsCryptFs;

public class CryptFsFileOrDirectory : IVirtualFileOrDirectory
{
    public CryptFsConfigWithKeys Config { get; }

    protected readonly IVirtualFileOrDirectory inner;
    private readonly IVirtualDirectory? innerParent;
    private IVirtualFile? longNameFile;

    internal CryptFsFileOrDirectory(
        CryptFsConfigWithKeys config,
        IVirtualFileOrDirectory inner,
        IVirtualDirectory? innerParent,
        IVirtualFile? longNameFile
    )
    {
        Config = config;
        this.inner = inner;
        this.innerParent = innerParent;
        this.longNameFile = longNameFile;
    }

    public Task RenameAsync(string newName, bool allowOverwrite, CancellationToken cancellationToken)
    {
        SanitizeName(newName);
        throw new NotImplementedException(); // TODO
    }

    public Task MoveToAsync(
        IVirtualDirectory newParent,
        string newName,
        bool allowOverwrite,
        CancellationToken cancellationToken
    )
    {
        SanitizeName(newName);
        if (newParent is not CryptFsDirectory cryptFsDirectory || cryptFsDirectory.Config != Config)
        {
            throw new NotSupportedException("Can only move files within the same cryptfs volume");
        }
        // Moving cannot be atomic because of .name files.
        // To make sure the filesystem is never in an invalid state where there's a file without a corresponding .name file,
        // a copy of the long name file must be created.
        throw new NotImplementedException(); // TODO
    }

    public async Task DeleteAsync(CancellationToken cancellationToken)
    {
        // Deletion cannot be atomic because of .name files.
        // Deleting the file first, then the .name file is better than the other way around,
        // because then the worst case is leaving a dangling small file on disk, as opposed to
        // leaving a file with no corresponding .name entry.
        await inner.DeleteAsync(cancellationToken).ConfigureAwait(false);
        if (longNameFile != null)
        {
            try
            {
                await longNameFile.DeleteAsync(cancellationToken).ConfigureAwait(false);
            }
            catch (FileNotFoundException) { }
            longNameFile = null;
        }
    }

    public Task<FileAttributes> GetAttributesAsync(CancellationToken cancellationToken)
    {
        return inner.GetAttributesAsync(cancellationToken);
    }

    public Task SetAttributesAsync(FileAttributes attributes, CancellationToken cancellationToken)
    {
        return inner.SetAttributesAsync(attributes, cancellationToken);
    }

    /// <exception cref="ArgumentException">The name was invalid.</exception>
    protected static void SanitizeName(ReadOnlySpan<char> name)
    {
        if (name.Contains(PathParser.DIRECTORY_SEPARATOR_CHAR))
        {
            throw new ArgumentException($"File name '{name}' must not include a directory separator.", nameof(name));
        }
        if (name.IsEmpty)
        {
            throw new ArgumentException("Name cannot be empty", nameof(name));
        }
        if (name == "." || name == "..")
        {
            throw new ArgumentException($"Special directory '{nameof(name)}' is not supported", nameof(name));
        }
    }

    protected async Task<(string shortEncryptedName, IVirtualFile? longNameFile)> EnsureNameAsync(
        string name,
        byte[] tweak,
        CancellationToken cancellationToken
    )
    {
        string encryptedName = Config.FileNameCrypto.Encrypt(name, tweak);
        string? longNameHash = FileNameCrypto.GetLongNameHash(encryptedName, Config.Config.LongNameMax);
        IVirtualFile? longNameFile = null;
        if (longNameHash != null)
        {
            encryptedName = FileNameCrypto.LONGNAME_FILE_PREFIX + longNameHash;
            string nameFileName = encryptedName + FileNameCrypto.LONGNAME_NAME_FILE_SUFFIX;
            longNameFile = ((IVirtualDirectory)inner).GetChildFile(nameFileName);
            if (longNameFile is not IWritable writable)
            {
                throw new InvalidOperationException($"File '{nameFileName}' is not writable");
            }
            await using Stream stream = await writable
                .OpenWriteAsync(FileMode.Create, cancellationToken)
                .ConfigureAwait(false);
            using StreamWriter writer = new(stream, Encoding.UTF8, leaveOpen: true);
            writer.Write(encryptedName);
        }
        return (encryptedName, longNameFile);
    }
}
