using System;
using System.Buffers.Binary;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace CsCryptFs;

/// <summary>
/// An object responsible for encrypting/decrypting file content.
/// </summary>
internal class FileContentCrypto
{
    public const int IvSize = 16;
    public const int AuthTagSize = 16;
    public const int PlainBlockSize = 4096;
    public const int BlockOverhead = IvSize + AuthTagSize;
    public const int CipherBlockSize = PlainBlockSize + BlockOverhead;

    private readonly KeyParameter keyParam;
    private readonly GcmBlockCipher cipher;
    private readonly byte[] associatedData;

    public FileContentCrypto(byte[] contentKey)
    {
        keyParam = new KeyParameter(contentKey);
        cipher = new GcmBlockCipher(new AesEngine());
        associatedData = new byte[sizeof(ulong) + FileHeader.FileIdLength]; // 8-byte block number + fileId
    }

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
    public static long GetPlaintextSize(long encryptedSize)
    {
        if (encryptedSize == 0 || encryptedSize == FileHeader.TotalSize)
        {
            return 0;
        }
        if (encryptedSize < FileHeader.TotalSize)
        {
            throw new ArgumentException(
                $"Small file size {encryptedSize} indicates a corrupted file",
                nameof(encryptedSize)
            );
        }

        long encryptedDataSize = encryptedSize - FileHeader.TotalSize;
        long blockCount = (encryptedDataSize + CipherBlockSize - 1) / CipherBlockSize;

        long overhead = blockCount * BlockOverhead;
        if (overhead > encryptedDataSize)
        {
            throw new ArgumentException(
                $"File size {encryptedSize} is invalid because the last block is less than {BlockOverhead} bytes",
                nameof(encryptedSize)
            );
        }

        long plaintextSize = encryptedDataSize - overhead;
        return plaintextSize;
    }

    /// <summary>
    /// Calculates the encrypted file size the given plaintext size would produce.
    /// </summary>
    public static long GetEncryptedFileSize(long plaintextSize)
    {
        if (plaintextSize == 0)
            return 0;
        long blockCount = (plaintextSize + PlainBlockSize - 1) / PlainBlockSize;
        return FileHeader.TotalSize + plaintextSize + blockCount * BlockOverhead;
    }

    public static long PlainOffsetToBlockNumber(long plainOffset)
    {
        return plainOffset / PlainBlockSize;
    }

    public static long CipherOffsetToBlockNumber(long cipherOffset)
    {
        return (cipherOffset - FileHeader.TotalSize) / CipherBlockSize;
    }

    public static long BlockNumberToCipherOffset(long blockNumber)
    {
        return FileHeader.TotalSize + blockNumber * CipherBlockSize;
    }

    public static long BlockNumberToPlainOffset(long blockNumber)
    {
        return blockNumber * PlainBlockSize;
    }

    /// <returns>The plaintext length.</returns>
    /// <exception cref="ArgumentException"/>
    public int DecryptBlock(
        ReadOnlySpan<byte> ciphertext,
        ulong blockNumber,
        ReadOnlySpan<byte> fileId,
        Span<byte> output
    )
    {
        if (ciphertext.Length < BlockOverhead)
        {
            throw new ArgumentException($"Block too small: size {ciphertext.Length}");
        }
        ReadOnlySpan<byte> iv = ciphertext[..IvSize];
        if (ciphertext.Length == CipherBlockSize && !ciphertext.ContainsAnyExcept((byte)0))
        {
            output[..CipherBlockSize].Clear();
            return CipherBlockSize;
        }
        return TransformBlock(false, blockNumber, fileId, iv.ToArray(), ciphertext[IvSize..], output);
    }

    /// <returns>The total encrypted length (IV + ciphertext + auth tag).</returns>
    public int EncryptBlock(
        ReadOnlySpan<byte> plaintext,
        ulong blockNumber,
        ReadOnlySpan<byte> fileId,
        Span<byte> output
    )
    {
        byte[] iv = RandomNumberGenerator.GetBytes(IvSize);
        iv.CopyTo(output);
        return IvSize + TransformBlock(true, blockNumber, fileId, iv, plaintext, output[IvSize..]);
    }

    /// <returns>The transformed length.</returns>
    private int TransformBlock(
        bool encrypt,
        ulong blockNumber,
        ReadOnlySpan<byte> fileId,
        byte[] iv,
        ReadOnlySpan<byte> input,
        Span<byte> output
    )
    {
        SetAssociatedData(blockNumber, fileId);
        AeadParameters parameters = new(keyParam, AuthTagSize * 8, iv, associatedData);
        cipher.Init(encrypt, parameters);
        int offset = cipher.ProcessBytes(input, output);
        return offset + cipher.DoFinal(output[offset..]);
    }

    private void SetAssociatedData(ulong blockNumber, ReadOnlySpan<byte> fileId)
    {
        BinaryPrimitives.WriteUInt64BigEndian(associatedData, blockNumber);
        fileId.CopyTo(associatedData.AsSpan(sizeof(ulong)));
    }
}
