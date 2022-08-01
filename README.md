# binscan

## Description

`binscan` is a command-line application used for analyzing ELF-64 binaries. A variety of different aspects of
an ELF-64 object file are printed, including

1) The SHA-1 checksum of the `.text` section of the binary
2) All unique `x86` instructions utilized in the binary and the frequency of their use 
3) The [Renyi Entropy](https://en.wikipedia.org/wiki/R%C3%A9nyi_entropy) of the ELF-64 object's `.text` section
4) The `SHA-256` checksum of the binary's `.text` section

An analysis result binary file is also created under the same name of the ELF-64 binary analyzed with the `.bin` file extension. The user may later open these bin files with the `-open` option.

## Installation

1) Install the `OpenSSL` and `Capstone` C packages.
2) Clone this repository.
3) Use the `make` command in the main repository directory.
