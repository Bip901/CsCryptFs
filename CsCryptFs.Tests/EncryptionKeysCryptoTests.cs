using Xunit;

namespace CsCryptFs.Tests;

public class EncryptionKeysCryptoTests
{
    [Fact]
    public void EncryptThenDecryptRoundTripsMasterKey()
    {
        byte[] kek = new byte[32];
        for (int i = 0; i < kek.Length; i++)
        {
            kek[i] = (byte)i;
        }

        byte[] masterKey = new byte[32];
        for (int i = 0; i < masterKey.Length; i++)
        {
            masterKey[i] = (byte)(0xFF - i);
        }

        byte[] encrypted = EncryptionKeysCrypto.EncryptKey(kek, masterKey);
        byte[] decrypted = EncryptionKeysCrypto.DecryptKey(kek, encrypted);

        Assert.Equal(masterKey, decrypted);
    }
}
