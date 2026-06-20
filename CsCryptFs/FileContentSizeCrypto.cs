using System;

namespace CsCryptFs;

internal static class FileContentSizeCrypto
{
    public const int FileIdLength = 16;
    public const int HeaderSize = sizeof(ushort) + FileIdLength;
    public const int IvSize = 16;
    public const int AuthTagSize = 16;
    public const int PlainBlockSize = 4096;
    public const int BlockOverhead = IvSize + AuthTagSize;
    public const int CipherBlockSize = PlainBlockSize + BlockOverhead;

    /// <summary>
    /// Calculates the plaintext size represented by a gocryptfs encrypted file size.
    /// </summary>
    /// <remarks>
    /// The encrypted file consists of an 18-byte header followed by independently
    /// encrypted blocks. Each block adds a fixed authentication overhead (nonce + tag)
    /// to the plaintext block size. The final block may be partial, and its plaintext
    /// length is inferred from the remaining ciphertext length.
    /// </remarks>
    /// <param name="encryptedSize">The size of the encrypted file in bytes.</param>
    /// <returns>The corresponding plaintext size in bytes.</returns>
    /// <exception cref="ArgumentException">
    /// Thrown when the encrypted size is smaller than the required file header or when
    /// the last block is smaller than the block overhead size.
    /// </exception>
    public static ulong GetPlaintextSize(ulong encryptedSize)
    {
        if (encryptedSize == 0 || encryptedSize == HeaderSize)
        {
            return 0;
        }
        if (encryptedSize < HeaderSize)
        {
            throw new ArgumentException(
                $"Small file size {encryptedSize} indicates a corrupted file",
                nameof(encryptedSize)
            );
        }

        ulong encryptedDataSize = encryptedSize - HeaderSize;
        ulong blockCount = (encryptedDataSize + CipherBlockSize - 1) / CipherBlockSize;

        ulong overhead = blockCount * BlockOverhead;
        if (overhead > encryptedDataSize)
        {
            throw new ArgumentException(
                $"File size {encryptedSize} is invalid because the last block is less than {BlockOverhead} bytes",
                nameof(encryptedSize)
            );
        }

        ulong plaintextSize = encryptedDataSize - overhead;
        return plaintextSize;
    }

    /// <summary>
    /// Calculates the encrypted file size the given plaintext size would produce.
    /// </summary>
    public static ulong GetEncryptedFileSize(ulong plaintextSize)
    {
        if (plaintextSize == 0)
            return 0;
        ulong blockCount = (plaintextSize + PlainBlockSize - 1) / PlainBlockSize;
        return HeaderSize + plaintextSize + blockCount * BlockOverhead;
    }
}
