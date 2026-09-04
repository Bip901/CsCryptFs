using System;
using System.IO;
using System.Linq;
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

    [Fact]
    public async Task RandomReadWorks()
    {
        byte[] exampleFileCiphertext = ReferenceVolume.GetExampleFileCiphertext();
        using MemoryStream ciphertext = new(exampleFileCiphertext);
        using CryptFsStream cryptFsStream = new(ciphertext, ReferenceVolume.ContentKey, write: false);

        byte[] buffer = new byte[10];
        int bytesRead = await cryptFsStream.ReadAtAsync(0, buffer, TestContext.Current.CancellationToken);
        Assert.True(bytesRead > 0);
        Assert.Equal(Enumerable.Repeat((byte)'A', bytesRead).ToArray(), buffer.AsSpan(0, bytesRead));

        bytesRead = await cryptFsStream.ReadAtAsync(4096, buffer, TestContext.Current.CancellationToken);
        Assert.True(bytesRead > 0);
        Assert.Equal(Enumerable.Repeat((byte)0, bytesRead).ToArray(), buffer.AsSpan(0, bytesRead));

        buffer = new byte[5];
        bytesRead = 0;
        while (bytesRead < buffer.Length)
        {
            int currentRead = await cryptFsStream.ReadAtAsync(
                8190 + bytesRead,
                buffer.AsMemory(bytesRead),
                TestContext.Current.CancellationToken
            );
            if (currentRead == 0)
            {
                Assert.Fail("Unexpected end-of-stream");
                break;
            }
            bytesRead += currentRead;
        }
        Assert.Equal(new byte[] { 0, 0, (byte)'C', (byte)'C', (byte)'C' }, buffer.AsSpan(0, bytesRead));
    }
}
