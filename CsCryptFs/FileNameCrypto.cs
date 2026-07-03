using System;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Paddings;

namespace CsCryptFs;

/// <summary>
/// Encrypts and decrypts file and directory names.
/// </summary>
public class FileNameCrypto
{
    internal const string LONGNAME_FILE_PREFIX = "gocryptfs.longname.";
    internal const string LONGNAME_NAME_FILE_SUFFIX = ".name";

    private readonly byte[] key;
    private readonly Pkcs7Padding padding;

    /// <summary>
    /// Creates a new <see cref="FileNameCrypto"/> instance.
    /// </summary>
    /// <param name="key">The AES EME key to use.</param>
    public FileNameCrypto(byte[] key)
    {
        this.key = key;
        padding = new();
    }

    /// <summary>
    /// Returns the encrypted name of the file or directory (in unpadded base64 url string form).
    /// </summary>
    /// <param name="fileName">The plaintext file name.</param>
    /// <param name="tweak">A directory-specific tweak (diriv) to apply.</param>
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

    /// <summary>
    /// Returns both the full encrypted name of the file or directory (in unpadded base64 url string form),
    /// and the short hashed encrypted name which is guaranteed to be &lt;= <paramref name="longNameMax"/> characters long.
    /// </summary>
    /// <param name="fileName">The plaintext file name.</param>
    /// <param name="tweak">A directory-specific tweak (diriv) to apply.</param>
    /// <param name="longNameMax">The maximum amount of characters (post-base64) the filesystem allows.</param>
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

    /// <summary>
    /// Decrypts the given ciphertext name.
    /// </summary>
    /// <param name="fileName">An encrypted file name in unpadded base64 url form.</param>
    /// <param name="tweak">A directory-specific tweak (diriv) to apply.</param>
    /// <exception cref="ArgumentException"/>
    /// <exception cref="FormatException"/>
    /// <exception cref="CryptographicException"/>
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
