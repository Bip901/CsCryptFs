# CsCryptFs

CsCryptFs is a C# implementation of the [gocryptfs](https://github.com/rfjakob/gocryptfs) filesystem format as a **shared library**, based on [the gocryptfs specification](https://nuetzlich.net/gocryptfs/forward_mode_crypto/).

Not all features are supported, but the supported features are fully compatible with gocryptfs.

## Design

- Unlike gocryptfs, CsCryptFs is **not** coupled to the local filesystem. Instead, the API receives a directory abstraction object from the caller.
- CsCryptFs does not create any mounts, but is rather used by other C# code to read and write individual files and directories on demand.
- CsCryptFs always assumes `--deterministicnames`: `gocryptfs.diriv` files are not (currently) supported.
  - One day I might implement `diriv`, but currently, reading the `diriv` adds a non-negligible round-trip to every directory listing operation in network filesystems, so it's not necessary for my use case.
