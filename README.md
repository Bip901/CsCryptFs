# CsCryptFs

CsCryptFs is a partial C# reimplementation of [gocryptfs](https://github.com/rfjakob/gocryptfs) as a library.
It shares some similarity with [gocryptfs-inspect](https://github.com/slackner/gocryptfs-inspect).

## Design

* CsCryptFs does not create any mounts, but is rather used by other C# code to read and write individual files and directories on demand.
* CsCryptFs always assumes `--deterministicnames`: `gocryptfs.diriv` files are not supported.
* Unlike gocryptfs, CsCryptFs is **not** coupled to the local filesystem. Instead, the API receives a directory abstraction object from the caller that allows dirlisting (this is needed to read `.longname` files) and opening files for reading/writing.
