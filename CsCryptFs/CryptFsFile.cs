using System.Threading;
using System.Threading.Tasks;
using FileAbstractions;

namespace CsCryptFs;

public class CryptFsFile : CryptFsFileOrDirectory, IReadableVirtualFile, IReadableWriteable
{
    internal CryptFsFile(
        CryptFsConfigWithKeys config,
        IVirtualFileOrDirectory inner,
        IVirtualDirectory? innerParent,
        IVirtualFile? longNameFile
    )
        : base(config, inner, innerParent, longNameFile) { }

    public Task<System.IO.Stream> OpenReadAsync(System.IO.FileMode fileMode, CancellationToken cancellationToken)
    {
        throw new System.NotImplementedException(); // TODO
    }

    public Task<System.IO.Stream> OpenWriteAsync(System.IO.FileMode fileMode, CancellationToken cancellationToken)
    {
        throw new System.NotImplementedException(); // TODO
    }

    public Task<System.IO.Stream> OpenReadWriteAsync(System.IO.FileMode fileMode, CancellationToken cancellationToken)
    {
        throw new System.NotImplementedException(); // TODO
    }
}
