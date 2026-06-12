using System;
using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Paddings;

namespace CsCryptFs;

public class FileNameCrypto : IDisposable
{
    public const string LONGNAME_FILE_PREFIX = "gocryptfs.longname.";
    public const string LONGNAME_NAME_FILE_SUFFIX = ".name";

    private readonly EMEEngine emeEngine;
    private readonly byte[] tweak;
    private readonly Pkcs7Padding padding;

    public FileNameCrypto(byte[] key, byte[]? tweak = null)
    {
        emeEngine = new(key);
        this.tweak = tweak ?? new byte[16];
        padding = new();
    }

    public string Encrypt(string fileName)
    {
        byte[] plaintext = Encoding.UTF8.GetBytes(fileName);
        byte[] paddedPlaintext = new byte[plaintext.Length + (16 - plaintext.Length % 16)];
        Array.Copy(plaintext, 0, paddedPlaintext, 0, plaintext.Length);
        padding.AddPadding(paddedPlaintext, plaintext.Length);
        byte[] ciphertext = emeEngine.Encrypt(tweak, paddedPlaintext);
        return Base64Url.EncodeToString(ciphertext);
    }

    public string Encrypt(string fileName, int longNameMax)
    {
        string encryptedFilename = Encrypt(fileName);
        string? longNameHash = GetLongNameHash(encryptedFilename, longNameMax);
        if (longNameHash == null)
        {
            return encryptedFilename;
        }
        return LONGNAME_FILE_PREFIX + longNameHash;
    }

    public string Decrypt(string fileName)
    {
        byte[] ciphertext = Base64Url.DecodeFromChars(fileName);
        byte[] paddedPlaintext = emeEngine.Decrypt(tweak, ciphertext);
        return Encoding.UTF8.GetString(paddedPlaintext, 0, paddedPlaintext.Length - padding.PadCount(paddedPlaintext));
    }

    /// <summary>
    /// Returns the long name hash of the given encrypted file name, or null if it's short enough to not require a long name hash.
    /// </summary>
    public static string? GetLongNameHash(string encryptedFileName, int longNameMax)
    {
        if (encryptedFileName.Length <= longNameMax)
        {
            return null;
        }
        byte[] encryptedFileNameHash = SHA256.HashData(Encoding.UTF8.GetBytes(encryptedFileName));
        return Base64Url.EncodeToString(encryptedFileNameHash);
    }

    public void Dispose()
    {
        GC.SuppressFinalize(this);
        emeEngine.Dispose();
    }
}
