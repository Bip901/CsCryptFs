using System.Security.Cryptography;
using System.Threading.Tasks;

namespace CsCryptFs;

/// <param name="Config">Configuration.</param>
/// <param name="KeyEncryptionKey">The KEK is a 32-byte key derived from the master password, used to encrypt/decrypt the <see cref="CryptFsConfig.EncryptedKey"/> property.</param>
/// <param name="ContentKey">The 32-byte key for content encryption, derived from the master key.</param>
/// <param name="FileNameCrypto">An object that encrypts/decrypts file names with a 32-byte key for file name encryption, derived from the master key.</param>
public record CryptFsConfigWithKeys(
    CryptFsConfig Config,
    byte[] KeyEncryptionKey,
    byte[] ContentKey,
    FileNameCrypto FileNameCrypto
)
{
    /// <summary>
    /// Creates a new secure configuration with a key derived from the given password.
    /// </summary>
    public static async Task<CryptFsConfigWithKeys> CreateNewAsync(string password)
    {
        CryptFsConfig.ScryptParams scryptParams = ScryptUtil.GenerateSecureParams();
        byte[] keyEncryptionKey = await ScryptUtil.DeriveKeyAsync(password, scryptParams).ConfigureAwait(false);
        return CreateNew(scryptParams, keyEncryptionKey);
    }

    /// <summary>
    /// Creates a new secure configuration with the given post-derivation key-encryption-key.
    /// </summary>
    public static CryptFsConfigWithKeys CreateNew(byte[] keyEncryptionKey) =>
        CreateNew(ScryptUtil.GenerateSecureParams(), keyEncryptionKey);

    /// <summary>
    /// Creates a new <see cref="CryptFsConfigWithKeys"/> with the given scrypt configuration and post-derivation key-encryption-key.
    /// </summary>
    public static CryptFsConfigWithKeys CreateNew(CryptFsConfig.ScryptParams scryptParams, byte[] keyEncryptionKey)
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        CryptFsConfig config = new()
        {
            Creator = "CsCryptFs " + typeof(CryptFsConfigWithKeys).Assembly.GetName().Version?.ToString(),
            EncryptedKey = EncryptionKeysCrypto.EncryptKey(keyEncryptionKey, masterKey),
            ScryptObject = scryptParams,
            Version = CryptFsConfig.CURRENT_VERSION,
            FeatureFlags = CryptFsConfig.ExpectedFeatureFlags,
        };
        return Load(config, keyEncryptionKey, masterKey);
    }

    /// <summary>
    /// Decrypts the given configuration with a key derived from the given password.
    /// </summary>
    public static async Task<CryptFsConfigWithKeys> LoadAsync(CryptFsConfig config, string password)
    {
        byte[] keyEncryptionKey = await ScryptUtil.DeriveKeyAsync(password, config.ScryptObject).ConfigureAwait(false);
        return Load(config, keyEncryptionKey);
    }

    /// <summary>
    /// Decrypts the given configuration with the given key-encryption-key.
    /// </summary>
    public static CryptFsConfigWithKeys Load(CryptFsConfig config, byte[] keyEncryptionKey)
    {
        byte[] masterKey = EncryptionKeysCrypto.DecryptKey(keyEncryptionKey, config.EncryptedKey);
        return Load(config, keyEncryptionKey, masterKey);
    }

    private static CryptFsConfigWithKeys Load(CryptFsConfig config, byte[] keyEncryptionKey, byte[] masterKey)
    {
        byte[] contentKey = EncryptionKeysCrypto.GetFileContentEncryptionKey(masterKey);
        byte[] fileNameKey = EncryptionKeysCrypto.GetFilenameEncryptionKey(masterKey);
        return new CryptFsConfigWithKeys(config, keyEncryptionKey, contentKey, new FileNameCrypto(fileNameKey));
    }
}
