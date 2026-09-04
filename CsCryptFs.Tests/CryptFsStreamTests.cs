using System.IO;
using System.Threading.Tasks;
using Xunit;

namespace CsCryptFs.Tests;

public class CryptFsStreamTests
{
    [Fact]
    public async Task SequentialReadWorks()
    {
        byte[] exampleFileCiphertext = ReferenceVolume.GetExampleFileCiphertext();
        using MemoryStream ciphertext = new(exampleFileCiphertext);
        using MemoryStream plaintext = new();
        using CryptFsStream cryptFsStream = new(ciphertext, ReferenceVolume.ContentKey, write: false);
        await cryptFsStream.CopyToAsync(plaintext, TestContext.Current.CancellationToken);

        Assert.Equal(ReferenceVolume.GetExampleFilePlaintext(), plaintext.ToArray());
    }
}
