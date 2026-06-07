# CsCryptFs

CsCryptFs is a partial[^1] C# reimplementation of [gocryptfs](https://github.com/rfjakob/gocryptfs) as a **shared library**, based on [the gocryptfs specification](https://nuetzlich.net/gocryptfs/forward_mode_crypto/).

[^1]: Not all features are supported, but those that are, are fully compatible with gocryptfs.

## Design

- CsCryptFs does not create any mounts, but is rather used by other C# code to read and write individual files and directories on demand.
- CsCryptFs always assumes `--deterministicnames`: `gocryptfs.diriv` files are not supported.
- Unlike gocryptfs, CsCryptFs is **not** coupled to the local filesystem. Instead, the API receives a directory abstraction object from the caller that allows dirlisting (this is needed to read `.longname` files) and opening files for reading/writing.

