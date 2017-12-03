[![Build Status](https://travis-ci.org/anisse/dmencrypt.svg?branch=master)](https://travis-ci.org/anisse/dmencrypt)
# dmencrypt

Create [dmcrypt](https://gitlab.com/cryptsetup/cryptsetup/wikis/DMCrypt) aes-cbc-essiv:sha256 volumes in userspace.

This tool ciphers a file with a key passed in argument, in the method used by Linux kernel's device-mapper crypt target, in per-sector AES-CBC, with ESSIV IV input (uses the sector number).

If for some reason you decide not to use LUKS, and you know what you're doing, you can use this tool to create dmcrypt volumes in userspace, so you don't need to have a machine with root access lying around, or use libguestfs.

There's only one mode supported, and you can both encrypt and decrypt the file.

It improves over the shell and openssl [dmcrypt.sh implementation by Vadim Penzin](http://www.penzin.net/dmcrypt/) by a factor 1000.

## Usage
```
usage: dmencrypt [-d] password-file input-file output-file
```

## Examples
```
$ dd bs=32 count=1 if=/dev/urandom of=key
1+0 records in
1+0 records out
32 bytes copied, 1.6077e-05 s, 2.0 MB/s
$ dmencrypt key my-filesystem encrypted-filesystem
$ dmencrypt -d key encrypted-filesystem decrypted-filesystem
$ cmp my-filesystem decrypted-filesyste
$ # files are identical
```
