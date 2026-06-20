using System;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Paddings;

namespace CsCryptFs;

public class FileNameCrypto
{
    public const string LONGNAME_FILE_PREFIX = "gocryptfs.longname.";
    public const string LONGNAME_NAME_FILE_SUFFIX = ".name";

    private readonly byte[] key;
    private readonly Pkcs7Padding padding;

    public FileNameCrypto(byte[] key)
    {
        this.key = key;
        padding = new();
    }

    public string Encrypt(string fileName, byte[] tweak)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(fileName);
        byte[] paddedPlaintext = new byte[plaintext.Length + (16 - plaintext.Length % 16)];
        Array.Copy(plaintext, 0, paddedPlaintext, 0, plaintext.Length);
        padding.AddPadding(paddedPlaintext, plaintext.Length);
        byte[] ciphertext;
        using (EMEEngine emeEngine = new(key))
        {
            ciphertext = emeEngine.Encrypt(tweak, paddedPlaintext);
        }
        return Base64Url.EncodeToString(ciphertext);
    }

    public (string shortEncryptedName, string fullEncryptedName) Encrypt(string fileName, byte[] tweak, int longNameMax)
    {
        string fullEncryptedName = Encrypt(fileName, tweak);
        string shortEncryptedName;
        string? longNameHash = GetLongNameHash(fullEncryptedName, longNameMax);
        if (longNameHash == null)
        {
            shortEncryptedName = fullEncryptedName;
        }
        else
        {
            shortEncryptedName = LONGNAME_FILE_PREFIX + longNameHash;
        }
        return (shortEncryptedName, fullEncryptedName);
    }

    public string Decrypt(string fileName, byte[] tweak)
    {
        if (fileName.EndsWith('='))
        {
            // We always assume the Raw64 configuration flag is set
            throw new ArgumentException($"Padding is not allowed in filename '{fileName}'", nameof(fileName));
        }
        byte[] ciphertext = Base64Url.DecodeFromChars(fileName);
        byte[] paddedPlaintext;
        using (EMEEngine emeEngine = new(key))
        {
            paddedPlaintext = emeEngine.Decrypt(tweak, ciphertext);
        }
        return Encoding.UTF8.GetString(paddedPlaintext, 0, paddedPlaintext.Length - padding.PadCount(paddedPlaintext));
    }

    /// <summary>
    /// Returns the long name hash of the given encrypted file name, or null if it's short enough to not require a long name hash.
    /// </summary>
    private static string? GetLongNameHash(string encryptedFileName, int longNameMax)
    {
        if (encryptedFileName.Length <= longNameMax)
        {
            return null;
        }
        byte[] encryptedFileNameHash = SHA256.HashData(Encoding.UTF8.GetBytes(encryptedFileName));
        return Base64Url.EncodeToString(encryptedFileNameHash);
    }
}
