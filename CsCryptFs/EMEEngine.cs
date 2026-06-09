using System;
using System.Security.Cryptography;

namespace CsCryptFs;

/// <summary>
/// Implementation of AES-EME as described in https://eprint.iacr.org/2003/147.pdf .<br/>
/// See also: <seealso href="https://github.com/rfjakob/eme">EME For Go</seealso>,
/// <seealso href="https://github.com/alexey-lapin/eme-java/blob/master/src/main/java/com/github/alexeylapin/eme/EMEImpl.java">eme-java</seealso> (used as a reference implementation)
/// </summary>
public sealed class EMEEngine : IDisposable
{
    private readonly Aes aes;

    public EMEEngine(byte[] key)
    {
        aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = key;
    }

    public byte[] Encrypt(ReadOnlySpan<byte> tweak, ReadOnlySpan<byte> inputData) => Transform(tweak, inputData, false);

    public byte[] Decrypt(ReadOnlySpan<byte> tweak, ReadOnlySpan<byte> inputData) => Transform(tweak, inputData, true);

    public byte[] Transform(ReadOnlySpan<byte> tweak, ReadOnlySpan<byte> inputData, bool decrypt)
    {
        if (tweak.Length != 16)
        {
            throw new ArgumentException("Tweak must be 16 bytes long.", nameof(tweak));
        }

        if (inputData.Length % 16 != 0)
        {
            throw new ArgumentException("Input data length must be a multiple of 16 bytes.", nameof(inputData));
        }

        int m = inputData.Length / 16;
        if (m < 1 || m > 16 * 8)
        {
            throw new ArgumentException($"Input data block count must be between 1 and {16 * 8}.", nameof(inputData));
        }

        Func<ReadOnlySpan<byte>, Span<byte>, PaddingMode, int> transform = decrypt ? aes.DecryptEcb : aes.EncryptEcb;

        byte[] C = new byte[inputData.Length];

        byte[][] LTable = TabulateL(m);

        byte[] PPj = new byte[16];
        for (int j = 0; j < m; j++)
        {
            inputData.Slice(j * 16, 16).CopyTo(PPj);
            XorInPlace(PPj, LTable[j]);
            transform(PPj, C.AsSpan(j * 16, 16), PaddingMode.None);
        }

        byte[] MP = Clone(C.AsSpan(0, 16));
        XorInPlace(MP, tweak);
        for (int j = 1; j < m; j++)
        {
            XorInPlace(MP, C.AsSpan(j * 16, 16));
        }

        byte[] MC = new byte[16];
        transform(MP, MC, PaddingMode.None);
        byte[] M = Clone(MP);
        XorInPlace(M, MC);

        byte[] CCCj = new byte[M.Length];
        for (int j = 1; j < m; j++)
        {
            MultByTwo(M);
            C.AsSpan(j * 16, 16).CopyTo(CCCj);
            XorInPlace(CCCj, M);
            Array.Copy(CCCj, 0, C, j * 16, 16);
        }

        byte[] CCC1 = Clone(MC);
        XorInPlace(CCC1, tweak);
        for (int j = 1; j < m; j++)
        {
            XorInPlace(CCC1, C.AsSpan(j * 16, 16));
        }
        Array.Copy(CCC1, 0, C, 0, 16);

        byte[] CView = new byte[16];
        for (int j = 0; j < m; j++)
        {
            Array.Copy(C, j * 16, CView, 0, 16);
            transform(CView, C.AsSpan(j * 16, 16), PaddingMode.None);
            Array.Copy(C, j * 16, CView, 0, 16);
            XorInPlace(CView, LTable[j]);
            Array.Copy(CView, 0, C, j * 16, 16);
        }

        return C;
    }

    private static byte[] Clone(ReadOnlySpan<byte> span)
    {
        byte[] result = new byte[span.Length];
        span.CopyTo(result);
        return result;
    }

    private byte[][] TabulateL(int blockCount)
    {
        byte[] eZero = new byte[16];
        byte[] Li = new byte[16];
        aes.EncryptEcb(eZero, Li, PaddingMode.None);
        byte[][] LTable = new byte[blockCount][];

        for (int i = 0; i < blockCount; i++)
        {
            MultByTwo(Li);
            LTable[i] = Clone(Li);
        }

        return LTable;
    }

    private static void XorInPlace(Span<byte> left, ReadOnlySpan<byte> right)
    {
        for (int i = 0; i < left.Length; i++)
        {
            left[i] ^= right[i];
        }
    }

    private static void MultByTwo(byte[] buffer)
    {
        byte carry = (byte)(buffer[0] & 0x80);
        buffer[0] = (byte)(buffer[0] * 2);
        if ((buffer[15] & 0x80) != 0)
        {
            buffer[0] ^= 135;
        }
        for (int j = 1; j < 16; j++)
        {
            byte nextCarry = (byte)(buffer[j] & 0x80);
            buffer[j] = (byte)((buffer[j] << 1) + (carry >> 7));
            carry = nextCarry;
        }
    }

    public void Dispose()
    {
        aes.Dispose();
    }
}
