using System;
using System.Buffers.Binary;
using System.Security.Cryptography;

namespace CsCryptFs;

internal class FileHeader(ushort version, byte[] fileId)
{
    public const int FileIdLength = 16;
    public const int TotalSize = sizeof(ushort) + FileIdLength;

    public ushort version = version;
    public byte[] fileId = fileId;

    public static FileHeader Generate()
    {
        return new FileHeader(CryptFsConfig.CURRENT_VERSION, RandomNumberGenerator.GetBytes(FileIdLength));
    }

    public static FileHeader Parse(ReadOnlySpan<byte> header)
    {
        ushort version = BinaryPrimitives.ReadUInt16BigEndian(header);
        byte[] fileId = header[sizeof(ushort)..].ToArray();
        return new FileHeader(version, fileId);
    }

    public void Write(Span<byte> destination)
    {
        BinaryPrimitives.WriteUInt16BigEndian(destination, version);
        fileId.CopyTo(destination[sizeof(ushort)..]);
    }
}
