using System;
using System.Buffers.Binary;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace CsCryptFs;

/// <summary>
/// An object responsible for encrypting/decrypting file content.
/// </summary>
internal class FileContentCrypto
{
    private readonly KeyParameter keyParam;
    private readonly GcmBlockCipher cipher;
    private readonly byte[] associatedData;

    internal FileContentCrypto(byte[] contentKey)
    {
        keyParam = new KeyParameter(contentKey);
        cipher = new GcmBlockCipher(new AesEngine());
        associatedData = new byte[sizeof(ulong) + FileContentSizeCrypto.FileIdLength]; // 8-byte block number + fileId
    }

    public void TransformBlock(
        bool encrypt,
        ulong blockNumber,
        ReadOnlySpan<byte> fileId,
        byte[] iv,
        ReadOnlySpan<byte> input,
        Span<byte> output
    )
    {
        SetAssociatedData(blockNumber, fileId);
        AeadParameters parameters = new(keyParam, FileContentSizeCrypto.AuthTagSize * 8, iv, associatedData);
        cipher.Init(encrypt, parameters);
        int offset = cipher.ProcessBytes(input, output);
        cipher.DoFinal(output[offset..]);
    }

    private void SetAssociatedData(ulong blockNumber, ReadOnlySpan<byte> fileId)
    {
        BinaryPrimitives.WriteUInt64BigEndian(associatedData, blockNumber);
        fileId.CopyTo(associatedData.AsSpan(sizeof(ulong)));
    }
}
