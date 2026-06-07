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
    public static CryptFsConfigWithKeys Derive(CryptFsConfig config, byte[] keyEncryptionKey, byte[]? masterKey = null)
    {
        masterKey ??= EncryptionKeysCrypto.DecryptKey(config.EncryptedKey, keyEncryptionKey);
        byte[] contentKey = EncryptionKeysCrypto.GetFileContentEncryptionKey(masterKey);
        byte[] fileNameKey = EncryptionKeysCrypto.GetFilenameEncryptionKey(masterKey);
        return new CryptFsConfigWithKeys(config, keyEncryptionKey, masterKey, contentKey, fileNameKey);
    }
}
