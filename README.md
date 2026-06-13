# CsCryptFs

CsCryptFs is a C# implementation of the [gocryptfs](https://github.com/rfjakob/gocryptfs) filesystem format as a **shared library**, based on [the gocryptfs specification](https://nuetzlich.net/gocryptfs/forward_mode_crypto/).

Not all features are supported, but the supported features are fully compatible with gocryptfs.

## Design

- Unlike gocryptfs, CsCryptFs's *input* is **not** coupled to the operating system's local filesystem. Instead, the API receives a directory abstraction object from the caller.
  - This means CsCryptFs can be used on remote storage devices without mounting them.
- Likewise, the *output* of CsCryptFs is not a FUSE mount, but rather regular C# objects.
  - This is desired in environments where there are no mounting permissions, e.g. mobile devices.

## Current Limitations

- Reverse mode is not supported, only forward mode is.
- Only one specific combination of configuration flags is supported - see [ExpectedFeatureFlags in CsCryptFs](./CsCryptFs/CryptFsConfig.cs)
  - Specifically, CsCryptFs always assumes `FlagDirIV` is **missing**. i.e. it always runs in `--deterministicnames` mode, and `gocryptfs.diriv` files are not supported.
    - One day I might implement `diriv`, but currently, reading the `diriv` adds a non-negligible round-trip to every directory listing operation in network filesystems, so it's not necessary for my use case.
    - Additionally, `diriv` is not effective against an attacker with write access anyway, see [the gocryptfs threat model](https://nuetzlich.net/gocryptfs/threat_model)
- Moving and deleting are atomic in the sense that they either succeed or fail, and the filesystem is never left in an inconsistent state. **However**, if a move or deletion are interrupted, a small dangling `.name` file may be left on disk, and there's currently no mechanism to clean them up. This only affects disk usage, not the filesystem correctness. See the comments in [CryptFsFileOrDirectory](CsCryptFs/CryptFsFileOrDirectory.cs).
