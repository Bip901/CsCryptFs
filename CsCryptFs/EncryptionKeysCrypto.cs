using System;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace CsCryptFs;

internal static class EncryptionKeysCrypto
{
    private const string HKDFInfoEMENames = "EME filename encryption";
    private const string HKDFInfoGCMContent = "AES-GCM file content encryption";
    private const int IV_LENGTH = 16;
    private const int AD_LENGTH = 8;
    private const int MAC_SIZE_BITS = 16 * 8; // 128 bits

    public static byte[] EncryptKey(byte[] kek, byte[] masterKey)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(IV_LENGTH);
        GcmBlockCipher cipher = GetGcmBlockCipher(kek, nonce, forEncryption: true);
        byte[] result = new byte[nonce.Length + cipher.GetOutputSize(masterKey.Length)];
        nonce.CopyTo(result);
        int len = cipher.ProcessBytes(masterKey, result.AsSpan(nonce.Length..));
        cipher.DoFinal(result.AsSpan((nonce.Length + len)..));
        return result;
    }

    public static byte[] DecryptKey(byte[] kek, byte[] encryptedMasterKey)
    {
        byte[] nonce = encryptedMasterKey[..IV_LENGTH];
        GcmBlockCipher cipher = GetGcmBlockCipher(kek, nonce, forEncryption: false);
        byte[] result = new byte[cipher.GetOutputSize(encryptedMasterKey.Length - nonce.Length)];
        int len = cipher.ProcessBytes(encryptedMasterKey.AsSpan(nonce.Length), result);
        cipher.DoFinal(result.AsSpan(len));
        return result;
    }

    private static GcmBlockCipher GetGcmBlockCipher(byte[] kek, byte[] nonce, bool forEncryption)
    {
        byte[] aeadKey = GetFileContentEncryptionKey(kek);
        AeadParameters parameters = new(
            new KeyParameter(aeadKey),
            MAC_SIZE_BITS,
            nonce,
            associatedText: new byte[AD_LENGTH]
        );

        GcmBlockCipher cipher = new(new AesEngine());
        cipher.Init(forEncryption, parameters);
        return cipher;
    }

    public static byte[] GetFilenameEncryptionKey(byte[] masterKey)
    {
        return HkdfDerive(masterKey, HKDFInfoEMENames);
    }

    public static byte[] GetFileContentEncryptionKey(byte[] key)
    {
        return HkdfDerive(key, HKDFInfoGCMContent);
    }

    /// <summary>
    /// Derives <paramref name="outLen"/> bytes from <paramref name="key"/> and <paramref name="info"/> using HKDF-SHA256.
    /// </summary>
    private static byte[] HkdfDerive(byte[] key, string info, int outLen = 32)
    {
        byte[] infoBytes = Encoding.UTF8.GetBytes(info);
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, key, outLen, salt: null, info: infoBytes);
    }
}
