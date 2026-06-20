using System;
using System.IO;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using FileAbstractions;
using FileAbstractions.Implementations;
using Xunit;
using FileAttributes = FileAbstractions.FileAttributes;

namespace CsCryptFs.Tests;

public class EndToEndTests
{
    const string REFERENCE_VOLUME_RELATIVE_PATH = "reference";
    const string REFERENCE_VOLUME_PASSWORD = "1234";

    const string LONG_FILE_NAME =
        "Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long.txt";
    const string SUBDIR_NAME = "Example Directory";
    const string EXAMPLE_FILE_NAME = "Example.bin";
    const string EMPTY_FILE_NAME = "Empty.txt";

    [Fact]
    public async Task ReferenceVolumeWorks()
    {
        LocalDirectory referenceDir = new(Path.Combine(AppContext.BaseDirectory, REFERENCE_VOLUME_RELATIVE_PATH));

        CryptFsDirectory cryptFs = await CryptFsDirectory.OpenExistingAsync(
            referenceDir,
            REFERENCE_VOLUME_PASSWORD,
            cancellationToken: TestContext.Current.CancellationToken
        );

        FileEntry[] fileEntries = await cryptFs
            .ListChildren(TestContext.Current.CancellationToken)
            .ToArrayAsync(TestContext.Current.CancellationToken);
        var fileNames = fileEntries.Select(entry => entry.Name).Order();
        Assert.Equal(fileNames, [EMPTY_FILE_NAME, SUBDIR_NAME, EXAMPLE_FILE_NAME, LONG_FILE_NAME]);

        await Assert.ThrowsAsync<DirectoryNotFoundException>(() =>
            cryptFs.GetChildDir("Non-Existent Directory").GetAttributesAsync(TestContext.Current.CancellationToken)
        );
        FileAttributes subdirAttributes = await cryptFs
            .GetChildDir(SUBDIR_NAME)
            .GetAttributesAsync(TestContext.Current.CancellationToken);
        Assert.True(subdirAttributes.IsDirectory);

        IVirtualFile emptyFile = cryptFs.GetChildFile(EMPTY_FILE_NAME);
        string actualEmptyFileText = await ReadAllTextAsync(emptyFile);
        Assert.Equal(string.Empty, actualEmptyFileText);

        IVirtualFile exampleFile = cryptFs.GetChildFile(EXAMPLE_FILE_NAME);
        byte[] actualExampleFileBytes = await ReadAllBytesAsync(exampleFile, TestContext.Current.CancellationToken);
        Assert.Equal(4096 * 3, actualExampleFileBytes.Length);
        Assert.Equal(Enumerable.Repeat((byte)'A', 4096), actualExampleFileBytes.Take(4096));
        Assert.Equal(Enumerable.Repeat((byte)0, 4096), actualExampleFileBytes.Skip(4096).Take(4096));
        Assert.Equal(Enumerable.Repeat((byte)'C', 4096), actualExampleFileBytes.Skip(4096 * 2).Take(4096));

        IVirtualFile longFile = cryptFs.GetChildFile(LONG_FILE_NAME);
        string actualLongFileText = await ReadAllTextAsync(longFile);
        Assert.Equal("This file has a very long name!", actualLongFileText);

        IVirtualFile innerFile = ((IVirtualDirectory)cryptFs).GetDescendantFile(
            $"{SUBDIR_NAME}{PathParser.DIRECTORY_SEPARATOR_CHAR}Inner.txt"
        );
        string actualInnerFileText = await ReadAllTextAsync(innerFile);
        Assert.Equal("This file is within a directory.\r\n", actualInnerFileText);
    }

    private static Task<string> ReadAllTextAsync(IVirtualFile file)
    {
        return ((IReadable)file).ReadAllTextAsync(FileMode.Open, TestContext.Current.CancellationToken);
    }

    private static async Task<byte[]> ReadAllBytesAsync(IVirtualFile file, CancellationToken cancellationToken)
    {
        await using Stream stream = await ((IReadable)file)
            .OpenReadAsync(FileMode.Open, cancellationToken)
            .ConfigureAwait(false);
        using MemoryStream memoryStream = new();
        await stream.CopyToAsync(memoryStream, cancellationToken);
        return memoryStream.ToArray();
    }
}
