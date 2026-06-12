using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using FileAbstractions;
using FileAbstractions.Implementations;
using Xunit;

namespace CsCryptFs.Tests;

public class EndToEndTests
{
    [Fact]
    public async Task OpenReferenceVolumeWorks()
    {
        LocalDirectory referenceDir = new(Path.Combine(AppContext.BaseDirectory, "reference"));

        CryptFsDirectory cryptFs = await CryptFsDirectory.OpenExistingAsync(
            referenceDir,
            "1234",
            cancellationToken: TestContext.Current.CancellationToken
        );

        FileEntry[] fileEntries = await cryptFs
            .ListChildren(TestContext.Current.CancellationToken)
            .ToArrayAsync(TestContext.Current.CancellationToken);
        var fileNames = fileEntries.Select(entry => entry.Name).Order();
        Assert.Equal(
            fileNames,
            [
                "Example Directory",
                "Example.txt",
                "Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long Long.txt",
            ]
        );
    }
}
