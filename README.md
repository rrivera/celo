# Celo [![GitHub tag](https://img.shields.io/github/tag/nullrocks/celo.svg)](https://github.com/nullrocks/celo/tree/master)

Celo is a CLI tool to encrypt files from an user-defined secret phrase.

Celo encrypts files using **AES GCM** block cipher that provides both privacy and integrity checks. 
The Nonce used by the cipher is re-generated for **every** encryption, meaning that no nonce is reused.

---

## Key Generation
Celo uses **argon2** for key generation from a phrase with a random salt on every encryption. 
Even when the same phrase is used twice or more, a different key is generated.

## Celo as library
Even though Celo was originally designed to be a command line interface tool,
it makes sense to distribute it as a library hoping it could help other projects with similar needs.

## WARNING! 
Celo is still in early development and it's not recommended to be used in production tasks **yet**.

## CLI Usage

```bash
    $ celo [COMMAND] <FILE|PATTERN> [ARG...]
```

You can get a detailed list o commands and arguments using the `--help` flag.
```bash
    $ celo --help
    $ celo encrypt --help       # $ celo e --help
    $ celo decrypt --help       # $ celo d --help
```


## Encrypting a single file

```bash
    $ celo book_draft.md

    > Enter Phrase:
    > Confirm Phrase:

    > 1 file(s) encrypted. (0 failed)    
    > Encrypted Files:
    >   book_draft.md.celo
```

The book_draft.md file will be encrypted resulting in a new file with the
a similar name, suffixed with the .celo extension.

## Decrypting a single file

```bash
    $ celo d book_draft.md.celo

    > Enter Phrase:

    > 1 file(s) decrypted. (0 failed)    
    > Decrypted Files:
    >   book_draft.md
```

## Working with multiple files

Celo accepts a list of files as well as Glob patterns in both `encryption` and `decryption`.

```bash
    # Encrypt files with .txt extension.
    $ celo *.txt -rm-source # -rm-source flag removes the original files after successful encryption.
    # [...]

    # Encrypt all files except files with .png extension.
    $ celo ./* -exclude="*.png" # $ celo "./*" -exclude="*.png" works too.
    # [...]

    # Decrypting multiple files with the .celo extension.
    $ celo d ./*.celo
    # [...]
```

## Road map
- [ ] Unit tests
- [x] Use standar algorithm to encrypt files
- [ ] Enhance file handling with buffers
- [ ] Improve error messages
- [ ] Packaging

---
MIT - © 2018

