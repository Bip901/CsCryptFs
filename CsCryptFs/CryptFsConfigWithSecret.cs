namespace CsCryptFs;

/// <param name="Config">Configuration.</param>
/// <param name="MasterKey">The 32-byte key derived from the master password, used to encrypt/decrypt the <see cref="CryptFsConfig.EncryptedKey"/> property.</param>
/// <param name="FsKey">The 32-byte key encrypted with <paramref name="MasterKey"/> used for filesystem encryption.</param>
public record CryptFsConfigWithSecret(CryptFsConfig Config, byte[] MasterKey, byte[] FsKey);
