using System.Security.Cryptography;
using System.Threading.Tasks;

namespace CsCryptFs;

/// <param name="Config">Configuration.</param>
/// <param name="KeyEncryptionKey">The KEK is a 32-byte key derived from the master password, used to encrypt/decrypt the <see cref="CryptFsConfig.EncryptedKey"/> property (<paramref name="MasterKey"/>).</param>
/// <param name="MasterKey">The 32-byte key encrypted with <paramref name="KeyEncryptionKey"/> used for filesystem encryption.</param>
/// <param name="ContentKey">The 32-byte key for content encryption, derived from <paramref name="MasterKey"/>.</param>
/// <param name="FileNameKey">The 32-byte key for file name encryption, derived from <paramref name="MasterKey"/>.</param>
public record CryptFsConfigWithKeys(
    CryptFsConfig Config,
    byte[] KeyEncryptionKey,
    byte[] MasterKey,
    byte[] ContentKey,
    byte[] FileNameKey
)
{
    public static async Task<CryptFsConfigWithKeys> CreateNewAsync(string password)
    {
        CryptFsConfig.ScryptParams scryptParams = ScryptUtil.GenerateSecureParams();
        byte[] keyEncryptionKey = await ScryptUtil.DeriveKeyAsync(password, scryptParams).ConfigureAwait(false);
        return CreateNew(scryptParams, keyEncryptionKey);
    }

    public static CryptFsConfigWithKeys CreateNew(byte[] keyEncryptionKey) =>
        CreateNew(ScryptUtil.GenerateSecureParams(), keyEncryptionKey);

    public static CryptFsConfigWithKeys CreateNew(CryptFsConfig.ScryptParams scryptParams, byte[] keyEncryptionKey)
    {
        byte[] masterKey = RandomNumberGenerator.GetBytes(32);
        CryptFsConfig config = new()
        {
            Creator = "CsCryptFs " + typeof(CryptFsConfigWithKeys).Assembly.GetName().Version?.ToString(),
            EncryptedKey = EncryptionKeysCrypto.EncryptKey(keyEncryptionKey, masterKey),
            ScryptObject = scryptParams,
            Version = CryptFsConfig.SUPPORTED_CONFIG_VERSION,
            FeatureFlags = CryptFsConfig.ExpectedFeatureFlags,
        };
        return Load(config, keyEncryptionKey, masterKey);
    }

    public static async Task<CryptFsConfigWithKeys> LoadAsync(CryptFsConfig config, string password)
    {
        byte[] keyEncryptionKey = await ScryptUtil.DeriveKeyAsync(password, config.ScryptObject).ConfigureAwait(false);
        return Load(config, keyEncryptionKey);
    }

    public static CryptFsConfigWithKeys Load(CryptFsConfig config, byte[] keyEncryptionKey)
    {
        byte[] masterKey = EncryptionKeysCrypto.DecryptKey(keyEncryptionKey, config.EncryptedKey);
        return Load(config, keyEncryptionKey, masterKey);
    }

    private static CryptFsConfigWithKeys Load(CryptFsConfig config, byte[] keyEncryptionKey, byte[] masterKey)
    {
        byte[] contentKey = EncryptionKeysCrypto.GetFileContentEncryptionKey(masterKey);
        byte[] fileNameKey = EncryptionKeysCrypto.GetFilenameEncryptionKey(masterKey);
        return new CryptFsConfigWithKeys(config, keyEncryptionKey, masterKey, contentKey, fileNameKey);
    }
}
