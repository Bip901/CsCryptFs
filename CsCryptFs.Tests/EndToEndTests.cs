using System;
using System.IO;
using System.Linq;
using System.Text;
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
    const string EXAMPLE_FILE_NAME = "Example.txt";

    [Fact]
    public async Task ReferenceVolumeWorks()
    {
        LocalDirectory referenceDir = new(Path.Combine(AppContext.BaseDirectory, REFERENCE_VOLUME_RELATIVE_PATH));

        using CryptFsDirectory cryptFs = await CryptFsDirectory.OpenExistingAsync(
            referenceDir,
            REFERENCE_VOLUME_PASSWORD,
            cancellationToken: TestContext.Current.CancellationToken
        );

        FileEntry[] fileEntries = await cryptFs
            .ListChildren(TestContext.Current.CancellationToken)
            .ToArrayAsync(TestContext.Current.CancellationToken);
        var fileNames = fileEntries.Select(entry => entry.Name).Order();
        Assert.Equal(fileNames, [SUBDIR_NAME, EXAMPLE_FILE_NAME, LONG_FILE_NAME]);

        await Assert.ThrowsAsync<DirectoryNotFoundException>(() =>
            cryptFs.GetChildDir("Non-Existent Directory").GetAttributesAsync(TestContext.Current.CancellationToken)
        );
        FileAttributes subdirAttributes = await cryptFs
            .GetChildDir(SUBDIR_NAME)
            .GetAttributesAsync(TestContext.Current.CancellationToken);
        Assert.True(subdirAttributes.IsDirectory);

        IVirtualFile exampleFile = cryptFs.GetChildFile(EXAMPLE_FILE_NAME);
        string actualExampleFileText = await ReadAllTextAsync(exampleFile);
        Assert.Equal("Hello World", actualExampleFileText);

        IVirtualFile longFile = cryptFs.GetChildFile(LONG_FILE_NAME);
        string actualLongFileText = await ReadAllTextAsync(longFile);
        Assert.Equal("This is a very long file!\r\n", actualLongFileText);

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
}
