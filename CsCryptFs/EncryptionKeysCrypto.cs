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

    public static byte[] EncryptKey(byte[] kek, byte[] masterKey)
    {
        byte[] aeadKey = GetFileContentEncryptionKey(kek);
        try
        {
            GcmBlockCipher cipher = new(new AesEngine());
            byte[] nonce = RandomNumberGenerator.GetBytes(IV_LENGTH);
            AeadParameters parameters = new(new KeyParameter(aeadKey), 128, nonce, associatedText: new byte[AD_LENGTH]);
            cipher.Init(true, parameters);

            byte[] result = new byte[nonce.Length + cipher.GetOutputSize(masterKey.Length)];
            Array.Copy(nonce, result, nonce.Length);
            int len = cipher.ProcessBytes(masterKey, result.AsSpan(nonce.Length..));
            cipher.DoFinal(result.AsSpan((nonce.Length + len)..));
            return result;
        }
        finally
        {
            Array.Clear(aeadKey, 0, aeadKey.Length);
        }
    }

    public static byte[] DecryptKey(byte[] kek, byte[] encryptedMasterKey)
    {
        byte[] aeadKey = GetFileContentEncryptionKey(kek);
        try
        {
            GcmBlockCipher cipher = new(new AesEngine());
            byte[] nonce = encryptedMasterKey[..IV_LENGTH];
            AeadParameters parameters = new(new KeyParameter(aeadKey), 128, nonce, associatedText: new byte[AD_LENGTH]);
            cipher.Init(false, parameters);

            byte[] result = new byte[cipher.GetOutputSize(encryptedMasterKey.Length - nonce.Length)];
            int len = cipher.ProcessBytes(encryptedMasterKey.AsSpan(nonce.Length), result);
            cipher.DoFinal(result.AsSpan(len));
            return result;
        }
        finally
        {
            Array.Clear(aeadKey, 0, aeadKey.Length);
        }
    }

    public static byte[] GetFilenameEncryptionKey(byte[] masterKey)
    {
        return HkdfDerive(masterKey, HKDFInfoEMENames);
    }

    public static byte[] GetFileContentEncryptionKey(byte[] masterKey)
    {
        return HkdfDerive(masterKey, HKDFInfoGCMContent);
    }

    /// <summary>
    /// Derives "outLen" bytes from "masterKey" and "info" using HKDF-SHA256.
    /// </summary>
    /// <exception cref="CryptographicException"/>
    private static byte[] HkdfDerive(byte[] masterKey, string info, int outLen = 32)
    {
        byte[] infoBytes = Encoding.UTF8.GetBytes(info);
        return HKDF.DeriveKey(HashAlgorithmName.SHA256, masterKey, outLen, salt: null, info: infoBytes);
    }
}
