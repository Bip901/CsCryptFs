using System;
using System.Security.Cryptography;
using System.Threading.Tasks;
using Scrypt;

namespace CsCryptFs;

internal static class ScryptUtil
{
    /// <summary>
    /// Derives a key from the given <paramref name="password"/> using <paramref name="scryptParams"/>.
    /// </summary>
    /// <exception cref="ArgumentException"></exception>
    public static Task<byte[]> DeriveKeyAsync(string password, CryptFsConfig.ScryptParams scryptParams)
    {
        return Task.Run(() => DeriveKey(password, scryptParams));
    }

    /// <summary>
    /// Derives a key from the given <paramref name="password"/> using <paramref name="scryptParams"/>.
    /// </summary>
    /// <exception cref="ArgumentException"></exception>
    public static byte[] DeriveKey(string password, CryptFsConfig.ScryptParams scryptParams)
    {
        if (scryptParams.KeyLen != 32)
        {
            throw new ArgumentException($"Unsupported key length {scryptParams.KeyLen} (expected 32).");
        }
        StaticSaltGenerator saltGenerator = new(scryptParams.Salt);
        ScryptEncoder encoder = new(scryptParams.N, scryptParams.R, scryptParams.P, saltGenerator);
        string encodedKey = encoder.Encode(password);
        // Encode returns a string formatted like:
        // $s2$16384$8$1$saltBase64$derivedKeyBase64
        int lastDollar = encodedKey.LastIndexOf('$');
        if (lastDollar == -1)
        {
            throw new FormatException("Failed to parse the generated scrypt hash.");
        }
        byte[] key = Convert.FromBase64String(encodedKey[(lastDollar + 1)..]);
        if (key.Length != scryptParams.KeyLen)
        {
            throw new InvalidOperationException($"Got a {key.Length}-byte key, expected {scryptParams.KeyLen}");
        }
        return key;
    }

    private class StaticSaltGenerator(byte[] salt) : RandomNumberGenerator
    {
        private readonly byte[] salt = salt;

        public override void GetBytes(byte[] data)
        {
            if (salt.Length != data.Length)
            {
                throw new InvalidOperationException(
                    $"Expected caller to request a salt of length {salt.Length}, got {data.Length}"
                );
            }
            Array.Copy(salt, data, salt.Length);
        }
    }
}
