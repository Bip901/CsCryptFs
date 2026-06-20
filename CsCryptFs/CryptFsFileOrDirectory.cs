using System;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using FileAbstractions;
using FileAttributes = FileAbstractions.FileAttributes;

namespace CsCryptFs;

public class CryptFsFileOrDirectory : IVirtualFileOrDirectory
{
    public CryptFsConfigWithKeys Config { get; }

    protected readonly IVirtualFileOrDirectory inner;
    protected readonly CryptFsDirectory? parent;
    protected string? fullEncryptedName;
    protected IVirtualFile? longNameFile;

    internal CryptFsFileOrDirectory(
        CryptFsConfigWithKeys config,
        IVirtualFileOrDirectory inner,
        CryptFsDirectory? parent,
        IVirtualFile? longNameFile,
        string? fullEncryptedName
    )
    {
        Config = config;
        this.inner = inner;
        this.parent = parent;
        this.longNameFile = longNameFile;
        this.fullEncryptedName = fullEncryptedName;
    }

    public Task RenameAsync(string newName, bool allowOverwrite, CancellationToken cancellationToken)
    {
        if (parent == null)
        {
            throw new InvalidOperationException("Can't move the root of a cryptfs volume");
        }
        return MoveToAsync(parent, newName, allowOverwrite, cancellationToken);
    }

    public async Task MoveToAsync(
        IVirtualDirectory newParent,
        string newName,
        bool allowOverwrite,
        CancellationToken cancellationToken
    )
    {
        SanitizeName(newName);
        if (newParent is not CryptFsDirectory targetCryptFsDirectory || targetCryptFsDirectory.Config != Config)
        {
            throw new NotSupportedException("Can only move files within the same cryptfs volume");
        }

        // Moving cannot be atomic because of .name files.
        // To make sure the filesystem is never in an invalid state where there's a file without a corresponding .name file,
        // a copy of the long name file must be created first.

        (string newShortEncryptedName, string newFullEncryptedName, IVirtualFile? newLongNameFile) =
            await targetCryptFsDirectory.EnsureNameAsync(newName, cancellationToken).ConfigureAwait(false);

        // If the program halts here, and the new name is long, a dangling .name file is left.

        IVirtualDirectory newParentInner = (IVirtualDirectory)targetCryptFsDirectory.inner;
        await inner
            .MoveToAsync(newParentInner, newShortEncryptedName, allowOverwrite, cancellationToken)
            .ConfigureAwait(false);

        // If the program halts here, and the original name was long, a dangling .name file is left.

        fullEncryptedName = newFullEncryptedName;
        IVirtualFile? originalLongNameFile = longNameFile;
        longNameFile = newLongNameFile;
        await TryDeleteLongNameFileAsync(originalLongNameFile, cancellationToken).ConfigureAwait(false);
    }

    public async Task DeleteAsync(CancellationToken cancellationToken)
    {
        // Deletion cannot be atomic because of .name files.
        // Deleting the file first, then the .name file is better than the other way around,
        // because then the worst case is leaving a dangling small file on disk, as opposed to
        // leaving a file with no corresponding .name entry.
        await inner.DeleteAsync(cancellationToken).ConfigureAwait(false);
        IVirtualFile? originalLongNameFile = longNameFile;
        longNameFile = null;
        await TryDeleteLongNameFileAsync(originalLongNameFile, cancellationToken).ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public virtual Task<FileAttributes> GetAttributesAsync(CancellationToken cancellationToken)
    {
        return inner.GetAttributesAsync(cancellationToken);
    }

    /// <inheritdoc/>
    public virtual Task SetAttributesAsync(FileAttributes attributes, CancellationToken cancellationToken)
    {
        if (attributes.FileSize.HasValue)
        {
            throw new NotSupportedException("Truncating files via SetAttributes is currently not supported.");
        }
        return inner.SetAttributesAsync(attributes, cancellationToken);
    }

    private static Task TryDeleteLongNameFileAsync(IVirtualFile? longNameFile, CancellationToken cancellationToken)
    {
        if (longNameFile == null)
        {
            return Task.CompletedTask;
        }
        try
        {
            return longNameFile.DeleteAsync(cancellationToken);
        }
        catch (FileNotFoundException)
        {
            return Task.CompletedTask;
        }
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
}
