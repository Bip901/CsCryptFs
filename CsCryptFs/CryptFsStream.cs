using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

namespace CsCryptFs;

internal sealed class CryptFsStream : Stream
{
    public override bool CanRead => innerStream.CanRead;

    public override bool CanWrite => innerStream.CanWrite;

    public override bool CanSeek => false;

    public override long Length => FileContentCrypto.GetPlaintextSize(innerStream.Length);

    public override long Position
    {
        get => plaintextPosition;
        set => throw new NotSupportedException("Seeking is not currently supported");
    }

    private long plaintextPosition;
    private readonly Stream innerStream;
    private readonly FileContentCrypto crypto;
    private readonly byte[] readBuffer;
    private int readBufferLength;

    private FileHeader? header;

    public CryptFsStream(Stream innerStream, byte[] contentKey)
    {
        this.innerStream = innerStream;
        crypto = new FileContentCrypto(contentKey);
        readBuffer = new byte[FileContentCrypto.PlainBlockSize];
    }

    /// <inheritdoc/>
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        if (buffer.Length == 0)
        {
            return 0;
        }

        if (header == null)
        {
            if (innerStream.Position > FileHeader.TotalSize)
            {
                throw new InvalidOperationException("Seeked past the header but never read it, not supposed to happen");
            }
            if (!await ReadHeaderAsync(cancellationToken).ConfigureAwait(false))
            {
                return 0;
            }
        }
        if (innerStream.Position < FileHeader.TotalSize)
        {
            throw new InvalidOperationException("Read the header but didn't seek past it, not supposed to happen");
        }

        int readBufferPosition = (int)(plaintextPosition % FileContentCrypto.PlainBlockSize);
        if (readBufferPosition >= readBufferLength)
        {
            await ReadBlockAsync(cancellationToken).ConfigureAwait(false);
            if (readBufferLength == 0)
            {
                return 0;
            }
        }

        readBufferPosition = (int)(plaintextPosition % FileContentCrypto.PlainBlockSize);
        int remainingInBuffer = readBufferLength - readBufferPosition;
        int bytesToCopy = Math.Min(remainingInBuffer, buffer.Length);

        readBuffer.AsSpan(readBufferPosition, bytesToCopy).CopyTo(buffer.Span);

        plaintextPosition += bytesToCopy;

        if (readBufferPosition + bytesToCopy >= readBufferLength)
        {
            readBufferLength = 0;
        }

        return bytesToCopy;
    }

    /// <inheritdoc/>
    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken cancellationToken)
    {
        if (!CanWrite)
        {
            throw new NotSupportedException();
        }

        throw new NotImplementedException("TODO"); // TODO
    }

    [MemberNotNullWhen(true, nameof(header))]
    private async Task<bool> ReadHeaderAsync(CancellationToken cancellationToken)
    {
        using IMemoryOwner<byte> headerMemoryOwner = MemoryPool<byte>.Shared.Rent(FileHeader.TotalSize);
        Memory<byte> headerMemory = headerMemoryOwner.Memory[..FileHeader.TotalSize];
        int read = await innerStream.ReadAsync(headerMemory, cancellationToken).ConfigureAwait(false);
        if (read == 0)
        {
            return false;
        }
        if (read < headerMemory.Length)
        {
            throw new InvalidDataException("File too small to contain a valid header");
        }
        header = FileHeader.Parse(headerMemory.Span);
        if (header.version != CryptFsConfig.CURRENT_VERSION)
        {
            throw new InvalidDataException($"Unsupported file content version: {header.version}");
        }
        return true;
    }

    private async Task ReadBlockAsync(CancellationToken cancellationToken)
    {
        // Read a full ciphertext block (or a partial one if reaching the end of the stream)
        using IMemoryOwner<byte> readMemoryOwner = MemoryPool<byte>.Shared.Rent(FileContentCrypto.CipherBlockSize);
        Memory<byte> readMemory = readMemoryOwner.Memory[..FileContentCrypto.CipherBlockSize];
        int totalRead = 0;
        while (totalRead < readMemory.Length)
        {
            int read = await innerStream.ReadAsync(readMemory[totalRead..], cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }
            totalRead += read;
        }
        if (totalRead == 0) // File length is an exact multiple of the cipher block size
        {
            readBufferLength = 0;
            return;
        }
        readMemory = readMemory[..totalRead];

        long currentBlockNumber = FileContentCrypto.PlainOffsetToBlockNumber(plaintextPosition);
        readBufferLength = crypto.DecryptBlock(readMemory.Span, (ulong)currentBlockNumber, header!.fileId, readBuffer);
    }

    /// <inheritdoc/>
    public override int Read(byte[] buffer, int offset, int count)
    {
        return ReadAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return ReadAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    /// <inheritdoc/>
    public override void Write(byte[] buffer, int offset, int count)
    {
        WriteAsync(buffer.AsMemory(offset, count), CancellationToken.None).AsTask().GetAwaiter().GetResult();
    }

    /// <inheritdoc/>
    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken cancellationToken)
    {
        return WriteAsync(buffer.AsMemory(offset, count), cancellationToken).AsTask();
    }

    /// <inheritdoc/>
    public override void Flush() { }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            innerStream.Dispose();
        }
        base.Dispose(disposing);
    }

    /// <inheritdoc/>
    public override async ValueTask DisposeAsync()
    {
        await innerStream.DisposeAsync().ConfigureAwait(false);
        await base.DisposeAsync().ConfigureAwait(false);
    }

    /// <inheritdoc/>
    public override long Seek(long offset, SeekOrigin origin)
    {
        throw new NotSupportedException();
    }

    /// <inheritdoc/>
    public override void SetLength(long value)
    {
        throw new NotSupportedException();
    }
}
