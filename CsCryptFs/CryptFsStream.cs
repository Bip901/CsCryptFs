using System;
using System.Buffers;
using System.Diagnostics.CodeAnalysis;
using System.IO;
using System.Threading;
using System.Threading.Tasks;
using FileAbstractions.Streams;

namespace CsCryptFs;

/// <summary>
/// A read-only or write-only stream that converts a ciphertext stream into a plaintext stream.
/// </summary>
public sealed class CryptFsStream : Stream, IConcurrentReadableStream
{
    /// <inheritdoc/>
    public override bool CanRead => !write && innerStream.CanRead;

    /// <inheritdoc/>
    public override bool CanWrite => write && innerStream.CanWrite;

    /// <inheritdoc/>
    public override bool CanSeek => false;

    /// <inheritdoc/>
    public override long Length => FileContentCrypto.GetPlaintextSize(innerStream.Length);

    /// <inheritdoc/>
    public override long Position
    {
        get => plaintextPosition;
        set => throw new NotSupportedException("Seeking is not currently supported");
    }

    private long plaintextPosition;
    private int CurrentBlockOffset => (int)(plaintextPosition % FileContentCrypto.PlainBlockSize);

    private readonly IConcurrentReadableStream? innerConcurrentStream;
    private readonly SemaphoreSlim concurrencySemaphore;
    private readonly Stream innerStream;
    private readonly FileContentCrypto crypto;
    private readonly byte[] readBuffer;
    private int readBufferLength;
    private readonly byte[] writeBuffer;
    private int writeBufferLength;
    private readonly bool write;

    private FileHeader? header;

    /// <summary>
    /// Creates a new <see cref="CryptFsStream"/> over the given ciphertext stream.
    /// </summary>
    /// <remarks>
    /// If <paramref name="innerStream"/> implements <see cref="IConcurrentReadableStream"/>, it will be used
    /// to implement <see cref="ReadAtAsync"/>. Otherwise, a lock-and-seek method will be used, which requires
    /// the inner stream to support seeking.
    /// <para>This stream does not support seeking.</para>
    /// </remarks>
    /// <param name="innerStream">The ciphertext stream. <see cref="CryptFsStream"/> only buffers the minimum necessary amount (1 ciphertext block, which is 4128 bytes); Callers may wish to wrap this in a <see cref="BufferedStream"/>.</param>
    /// <param name="contentKey">The secret key to use to encrypt/decrypt the content.</param>
    /// <param name="write">Whether to behave in write-only mode (true) or read-only mode (false).</param>
    public CryptFsStream(Stream innerStream, byte[] contentKey, bool write)
    {
        this.innerStream = innerStream;
        this.write = write;
        innerConcurrentStream = innerStream as IConcurrentReadableStream;
        concurrencySemaphore = new SemaphoreSlim(1, 1);
        crypto = new FileContentCrypto(contentKey);
        readBuffer = new byte[FileContentCrypto.PlainBlockSize];
        writeBuffer = readBuffer; // Read-write mode is currently not supported, so an optimization is to avoid an extra allocation by having these point to the same buffer
    }

    /// <inheritdoc/>
    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken cancellationToken)
    {
        if (!CanRead)
        {
            throw new NotSupportedException();
        }
        if (buffer.Length == 0)
        {
            return 0;
        }

        if (header == null)
        {
            if (!await ReadHeaderAsync(cancellationToken).ConfigureAwait(false))
            {
                return 0;
            }
        }

        if (CurrentBlockOffset >= readBufferLength)
        {
            await ReadBlockAsync(cancellationToken).ConfigureAwait(false);
            if (readBufferLength == 0)
            {
                return 0;
            }
        }

        int readBufferPosition = CurrentBlockOffset;
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

        if (buffer.Length == 0)
        {
            return;
        }

        if (header == null)
        {
            header = FileHeader.Generate();
            using IMemoryOwner<byte> headerMemoryOwner = MemoryPool<byte>.Shared.Rent(FileHeader.TotalSize);
            Memory<byte> headerMemory = headerMemoryOwner.Memory[..FileHeader.TotalSize];
            header.Write(headerMemory.Span);
            await innerStream.WriteAsync(headerMemory, cancellationToken).ConfigureAwait(false);
        }

        int offset = 0;
        while (offset < buffer.Length)
        {
            int spaceInWriteBuffer = FileContentCrypto.PlainBlockSize - writeBufferLength;
            int bytesToCopy = Math.Min(spaceInWriteBuffer, buffer.Length - offset);

            buffer.Span.Slice(offset, bytesToCopy).CopyTo(writeBuffer.AsSpan(writeBufferLength));
            offset += bytesToCopy;
            plaintextPosition += bytesToCopy;
            writeBufferLength += bytesToCopy;

            if (spaceInWriteBuffer == bytesToCopy) // Filled the buffer
            {
                await FlushSelfAsync(cancellationToken).ConfigureAwait(false);
            }
        }
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
        int read = await innerStream
            .ReadAtLeastAsync(
                readMemory,
                readMemory.Length,
                throwOnEndOfStream: false,
                cancellationToken: cancellationToken
            )
            .ConfigureAwait(false);
        if (read == 0) // File length is an exact multiple of the cipher block size
        {
            readBufferLength = 0;
            return;
        }
        readMemory = readMemory[..read];

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
    public async ValueTask<int> ReadAtAsync(
        long offset,
        Memory<byte> buffer,
        CancellationToken cancellationToken = default
    )
    {
        ArgumentOutOfRangeException.ThrowIfNegative(offset);

        // Ensure the header is read
        await concurrencySemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
        try
        {
            if (header == null && !await ReadHeaderAsync(cancellationToken).ConfigureAwait(false))
            {
                return 0;
            }
        }
        finally
        {
            concurrencySemaphore.Release();
        }

        long blockNumber = FileContentCrypto.PlainOffsetToBlockNumber(offset);
        int offsetWithinBlock = (int)(offset - (blockNumber * FileContentCrypto.PlainBlockSize));
        long blockStartCipherOffset = FileContentCrypto.BlockNumberToCipherOffset(blockNumber);

        using IMemoryOwner<byte> readMemoryOwner = MemoryPool<byte>.Shared.Rent(FileContentCrypto.CipherBlockSize);
        Memory<byte> readMemory = readMemoryOwner.Memory[..FileContentCrypto.CipherBlockSize];
        int read = await Inner_ReadAt_AtLeast_Async(
                blockStartCipherOffset,
                readMemory,
                readMemory.Length,
                cancellationToken
            )
            .ConfigureAwait(false);
        if (read == 0)
        {
            return 0;
        }
        using IMemoryOwner<byte> plaintextMemoryOwner = MemoryPool<byte>.Shared.Rent(FileContentCrypto.PlainBlockSize);
        Memory<byte> plainMemory = plaintextMemoryOwner.Memory[..FileContentCrypto.PlainBlockSize];
        int plaintextBlockLength = crypto.DecryptBlock(
            readMemory.Span[..read],
            (ulong)blockNumber,
            header!.fileId,
            plainMemory.Span
        );
        if (plaintextBlockLength <= offsetWithinBlock)
        {
            return 0;
        }
        Memory<byte> slicedPlaintext = plainMemory.Slice(
            offsetWithinBlock,
            Math.Min(buffer.Length, plaintextBlockLength - offsetWithinBlock)
        );
        slicedPlaintext.CopyTo(buffer);
        return slicedPlaintext.Length;
    }

    private async Task<int> Inner_ReadAt_AtLeast_Async(
        long offset,
        Memory<byte> buffer,
        int minimumBytes,
        CancellationToken cancellationToken
    )
    {
        if (innerConcurrentStream == null)
        {
            await concurrencySemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);
            try
            {
                innerStream.Seek(offset, SeekOrigin.Begin);
                return await innerStream
                    .ReadAtLeastAsync(
                        buffer,
                        minimumBytes,
                        throwOnEndOfStream: false,
                        cancellationToken: cancellationToken
                    )
                    .ConfigureAwait(false);
            }
            finally
            {
                concurrencySemaphore.Release();
            }
        }
        int totalRead = 0;
        while (totalRead < minimumBytes)
        {
            int bytesRead = await innerConcurrentStream
                .ReadAtAsync(offset + totalRead, buffer[totalRead..], cancellationToken)
                .ConfigureAwait(false);
            if (bytesRead == 0)
            {
                // End of stream
                break;
            }
            totalRead += bytesRead;
        }
        return totalRead;
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

    private async Task FlushSelfAsync(CancellationToken cancellationToken)
    {
        if (writeBufferLength <= 0 || header == null)
        {
            return;
        }
        long blockNumber = FileContentCrypto.PlainOffsetToBlockNumber(plaintextPosition - writeBufferLength);
        using IMemoryOwner<byte> encryptedMemoryOwner = MemoryPool<byte>.Shared.Rent(FileContentCrypto.CipherBlockSize);
        Memory<byte> encryptedMemory = encryptedMemoryOwner.Memory[..FileContentCrypto.CipherBlockSize];
        int encryptedLength = crypto.EncryptBlock(
            writeBuffer.AsSpan(0, writeBufferLength),
            (ulong)blockNumber,
            header.fileId,
            encryptedMemory.Span
        );
        await innerStream.WriteAsync(encryptedMemory[..encryptedLength], cancellationToken).ConfigureAwait(false);
        writeBufferLength = 0;
    }

    /// <inheritdoc/>
    public override void Flush()
    {
        // Only flush the inner stream, not the internal writeBuffer, to prevent block misalignment
        innerStream.Flush();
    }

    /// <inheritdoc/>
    public override Task FlushAsync(CancellationToken cancellationToken)
    {
        // Only flush the inner stream, not the internal writeBuffer, to prevent block misalignment
        return innerStream.FlushAsync(cancellationToken);
    }

    /// <inheritdoc/>
    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            DisposeAsync().AsTask().GetAwaiter().GetResult();
        }
    }

    /// <inheritdoc/>
    public override async ValueTask DisposeAsync()
    {
        await FlushSelfAsync(CancellationToken.None).ConfigureAwait(false);
        await innerStream.DisposeAsync().ConfigureAwait(false);
        concurrencySemaphore.Dispose();
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
