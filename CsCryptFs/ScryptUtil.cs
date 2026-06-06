using System;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using Org.BouncyCastle.Crypto.Generators;

namespace CsCryptFs;

internal static class ScryptUtil
{
    /// <summary>
    /// Creates new <see cref="CryptFsConfig.ScryptParams"/> which are deemed secure.
    /// </summary>
    public static CryptFsConfig.ScryptParams GenerateSecureParams()
    {
        return new CryptFsConfig.ScryptParams()
        {
            Salt = RandomNumberGenerator.GetBytes(32),
            N = 65536,
            R = 8,
            P = 1,
            KeyLen = 32,
        };
    }

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
    public static byte[] DeriveKey(string password, CryptFsConfig.ScryptParams scryptParams)
    {
        return SCrypt.Generate(
            Encoding.UTF8.GetBytes(password),
            scryptParams.Salt,
            scryptParams.N,
            scryptParams.R,
            scryptParams.P,
            scryptParams.KeyLen
        );
    }
}
