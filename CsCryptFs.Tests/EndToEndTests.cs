using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
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
    [Fact]
    public async Task ReferenceVolumeWorks()
    {
        LocalDirectory referenceDir = ReferenceVolume.Get();

        CryptFsDirectory cryptFs = await CryptFsDirectory.OpenExistingAsync(
            referenceDir,
            ReferenceVolume.PASSWORD,
            cancellationToken: TestContext.Current.CancellationToken
        );
        Assert.Equal(ReferenceVolume.ContentKey, cryptFs.Config.ContentKey);

        FileEntry[] fileEntries = await cryptFs
            .ListChildren(TestContext.Current.CancellationToken)
            .ToArrayAsync(TestContext.Current.CancellationToken);
        var fileNames = fileEntries.Select(entry => entry.Name).Order();
        Assert.Equal(
            fileNames,
            [
                ReferenceVolume.EMPTY_FILE_NAME,
                ReferenceVolume.SUBDIR_NAME,
                ReferenceVolume.EXAMPLE_FILE_NAME,
                ReferenceVolume.LONG_FILE_NAME,
            ]
        );

        await Assert.ThrowsAsync<DirectoryNotFoundException>(() =>
            cryptFs.GetChildDir("Non-Existent Directory").GetAttributesAsync(TestContext.Current.CancellationToken)
        );
        FileAttributes subdirAttributes = await cryptFs
            .GetChildDir(ReferenceVolume.SUBDIR_NAME)
            .GetAttributesAsync(TestContext.Current.CancellationToken);
        Assert.True(subdirAttributes.IsDirectory);

        IVirtualFile emptyFile = cryptFs.GetChildFile(ReferenceVolume.EMPTY_FILE_NAME);
        string actualEmptyFileText = await ReadAllTextAsync(emptyFile);
        Assert.Equal(string.Empty, actualEmptyFileText);

        IVirtualFile exampleFile = cryptFs.GetChildFile(ReferenceVolume.EXAMPLE_FILE_NAME);
        const long expectedExampleFileLength = 4096 * 3;
        FileAttributes exampleFileAttributes = await exampleFile.GetAttributesAsync(
            TestContext.Current.CancellationToken
        );
        Assert.Contains(
            exampleFileAttributes,
            fileEntries.Select(entry => entry.Attributes),
            new AccessTimeAgnosticFileAttributesComparer()
        );
        Assert.Equal<ulong>(expectedExampleFileLength, exampleFileAttributes.FileSize.GetValueOrDefault());

        byte[] actualExampleFileBytes = await ReadAllBytesAsync(exampleFile, TestContext.Current.CancellationToken);
        Assert.Equal(ReferenceVolume.GetExampleFilePlaintext(), actualExampleFileBytes);

        IVirtualFile longFile = cryptFs.GetChildFile(ReferenceVolume.LONG_FILE_NAME);
        string actualLongFileText = await ReadAllTextAsync(longFile);
        Assert.Equal("This file has a very long name!", actualLongFileText);

        IVirtualFile innerFile = ((IVirtualDirectory)cryptFs).GetDescendantFile(
            $"{ReferenceVolume.SUBDIR_NAME}{PathParser.DIRECTORY_SEPARATOR_CHAR}Inner.txt"
        );
        string actualInnerFileText = await ReadAllTextAsync(innerFile);
        Assert.Equal("This file is within a directory.\r\n", actualInnerFileText);
    }

    [Fact]
    public async Task CreatingNewVolumeWorks()
    {
        CryptFsConfigWithKeys config = await CryptFsConfigWithKeys.CreateNewAsync("1234");
        DirectoryInfo tempDir = Directory.CreateTempSubdirectory();
        try
        {
            LocalDirectory tempDirAbstracted = new(tempDir.FullName);
            CryptFsDirectory cryptFsDirectory = await CryptFsDirectory.CreateNewAsync(
                tempDirAbstracted,
                config,
                TestContext.Current.CancellationToken
            );
            IVirtualFile exampleFile = cryptFsDirectory.GetChildFile(ReferenceVolume.EXAMPLE_FILE_NAME);
            byte[] expectedContent = ReferenceVolume.GetExampleFilePlaintext().ToArray();
            await WriteAllBytesAsync(exampleFile, expectedContent, TestContext.Current.CancellationToken);
            byte[] readBytes = await ReadAllBytesAsync(exampleFile, TestContext.Current.CancellationToken);
            Assert.Equal(expectedContent, readBytes);
        }
        finally
        {
            tempDir.Delete(recursive: true);
        }
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

    private static async Task WriteAllBytesAsync(
        IVirtualFile file,
        ReadOnlyMemory<byte> memory,
        CancellationToken cancellationToken
    )
    {
        await using Stream stream = await ((IWritable)file)
            .OpenWriteAsync(FileMode.Create, cancellationToken)
            .ConfigureAwait(false);
        await stream.WriteAsync(memory, cancellationToken);
    }

    class AccessTimeAgnosticFileAttributesComparer : IEqualityComparer<FileAttributes>
    {
        public bool Equals(FileAttributes? x, FileAttributes? y)
        {
            if (ReferenceEquals(x, y))
                return true;
            if (x is null || y is null)
                return false;
            return (x with { LastAccessedTime = y.LastAccessedTime }).Equals(y);
        }

        public int GetHashCode([DisallowNull] FileAttributes obj)
        {
            return HashCode.Combine(obj.FileSize, obj.IsDirectory, obj.LastModifiedTime);
        }
    }
}
