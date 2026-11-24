# rsatoy design

This document describes what rsatoy does, what it protects against, and the choices behind it. Code should follow it; if they disagree, fix one of them in the same change.

## Goals

- Send a short secret (an API key, a password, a token) to one person so that only they can read it, even if the message travels over an untrusted channel.
- Work on Windows and macOS as a single file, with nothing else to install.
- Use only established cryptography libraries. rsatoy writes no cipher, padding, or key-exchange code of its own.
- Be hard to misuse: no options that weaken security, and no secrets left in terminal history, logs, or temp files.

## Non-goals

- Large files. Messages are capped at 64 KiB. Use `age` for files.
- Group messages. One message goes to one public key.
- Signing. The recipient cannot prove who sent a message (see [Threat model](#threat-model)).
- A key server or any network access. rsatoy never connects to the internet.
- Forward secrecy. If a private key leaks later, old messages to it can be read.

## Threat model

**Protected against:**

- Anyone who sees the encrypted message in transit or at rest (email provider, chat service, someone reading over a shared channel). They learn only roughly how long the secret is.
- Tampering with the message. Any change makes decryption fail instead of producing a wrong secret.

**Protected only if users compare fingerprints:**

- Someone who swaps the public key while it travels to the sender. They could then read the secret. rsatoy cannot detect this alone; the two people must compare the fingerprint over a second channel they trust, such as a voice call or in person. The CLI tells them to.

**Not protected against:**

- Malware on either computer, or someone with access to the recipient's unlocked user account.
- Someone pretending to be the sender. Anyone with the recipient's public key can encrypt to it, so the recipient should confirm with the sender that they really sent it.
- The recipient mishandling the secret after decrypting it.

## Cryptography

All primitives come from `golang.org/x/crypto`, maintained by the Go team.

| Purpose | Choice | Library |
| --- | --- | --- |
| Encrypt to a public key | NaCl sealed box: X25519 + XSalsa20-Poly1305 with an ephemeral sender key | `golang.org/x/crypto/nacl/box` (`SealAnonymous`, `OpenAnonymous`) |
| Protect the private key on disk | scrypt (N=2^15, r=8, p=1) to derive a key from a passphrase, then XSalsa20-Poly1305 | `golang.org/x/crypto/scrypt`, `golang.org/x/crypto/nacl/secretbox` |
| Fingerprint | SHA-256 of the 32-byte public key | Go standard library `crypto/sha256` |
| Randomness | Operating system random source | `crypto/rand` |

### Why not RSA

RSA is the idea the project started from, and it would work: RSA-OAEP with SHA-256 and a 3072-bit key can hold a short secret. Sealed boxes are the better fit:

- Keys are 32 bytes instead of about 400, so a public key fits on one line and is easy to paste and compare.
- There are no parameters to choose (key size, padding, hash), so there is nothing to get wrong.
- The library call does the whole job: one function to encrypt, one to decrypt.

If we ever want RSA anyway, it would use Go's `crypto/rsa` with `EncryptOAEP` and `sha256`, never `EncryptPKCS1v15`, and would be a new message version.

## Formats

All text formats are a prefix plus unpadded base64url, so they survive email, chat apps, and copy-paste without breaking.

**Public key:**

```text
rsatoy-pub-1-<base64url of 32-byte X25519 public key>
```

**Fingerprint:** the first 16 bytes of SHA-256 over the raw public key, as 32 lowercase hex characters in groups of four, for example `3f2a 9c41 07be d5e8 1a6c 44f0 9b23 e7d1`. People read it aloud to compare.

**Message:**

```text
-----BEGIN RSATOY MESSAGE-----
<base64url of: version byte 0x01 || sealed box>
-----END RSATOY MESSAGE-----
```

The body is wrapped at 64 characters so it pastes cleanly. On decrypt, rsatoy ignores whitespace and anything outside the BEGIN and END lines, so a message pasted with surrounding email text still works.

The version byte lets a future format be added without breaking old messages. An unknown version is an error, never a guess.

**Private key file:**

```text
rsatoy-key-1
<base64url of: 16-byte scrypt salt || 24-byte nonce || secretbox(32-byte private key || 32-byte public key)>
```

## Key storage

| System | Folder |
| --- | --- |
| Windows | `%APPDATA%\rsatoy\` |
| macOS | `~/Library/Application Support/rsatoy/` |
| Linux | `$XDG_CONFIG_HOME/rsatoy/` or `~/.config/rsatoy/` |

Go's `os.UserConfigDir()` returns the right base folder on each. The folder holds one file, `key`.

- The private key is always encrypted with a passphrase. `init` asks for it twice and refuses an empty one.
- On macOS and Linux the folder is created with mode `0700` and the file with `0600`. On Windows, files in the user's profile folder are already readable only by that user and administrators; rsatoy does not change ACLs.
- `init` refuses to overwrite an existing key unless given `--force`, and then it asks again before deleting.
- The `--key <path>` flag uses a different key file, for testing or for more than one identity.

## Commands

### `rsatoy init`

Makes a key pair, asks for a passphrase twice, saves the encrypted private key, and prints:

```text
Your public key (send this to the person who will send you a secret):

  rsatoy-pub-1-...

Fingerprint: 3f2a 9c41 07be d5e8 1a6c 44f0 9b23 e7d1
Read this fingerprint to them over a call or in person, and check it matches what they see.
```

### `rsatoy pubkey`

Prints the public key and fingerprint again. It reads the public key part of the key file, so it still asks for the passphrase (the file is encrypted as a whole).

### `rsatoy encrypt <pubkey>`

1. Parses the public key and prints its fingerprint, then asks "Does this match what your friend told you? [y/N]". Anything but `y` stops. `--yes` skips the question for scripts, and the docs say not to use it the first time.
2. Reads the secret from a hidden prompt (no echo). If standard input is not a terminal, reads it from standard input instead, so `rsatoy encrypt <key> < secret.txt` works.
3. Prints the message block to standard output.

The secret is never accepted as a command-line argument, because arguments show up in shell history and process lists.

### `rsatoy decrypt`

1. Reads the message from standard input until the END line, or from `--in <file>`.
2. Asks for the passphrase and decrypts.
3. Copies the secret to the clipboard and says so. It does not print the secret unless `--print` is given.
4. With `--clear-after <seconds>` (default 60, `0` turns it off), clears the clipboard after that many seconds if it still holds the secret. rsatoy stays running in the foreground until then and says so.

### Errors

Every failure prints one plain sentence and exits with a non-zero code. Decryption failures do not say why (wrong key, damaged message, or tampering), because the library cannot tell them apart and guessing would mislead.

## Handling secrets in memory

- Read secrets and passphrases into byte slices, never strings, and overwrite them with zeros when done. Go's garbage collector can still leave copies, so this is a best effort, not a guarantee.
- Never log, print, or write a secret or private key to a temp file.
- Error messages never include secret material.

## Dependencies

| Module | Use |
| --- | --- |
| `golang.org/x/crypto` | Sealed box, secretbox, scrypt |
| `golang.org/x/term` | Hidden passphrase and secret prompts |
| `github.com/atotto/clipboard` | Clipboard on Windows and macOS |

The command-line parsing uses the standard library `flag` package. No other dependencies.

## Project layout

```text
cmd/rsatoy/        main package: commands, prompts, output
internal/keys/     key generation, key file encode and decode, storage paths
internal/message/  message encode and decode, armoring
internal/fpr/      fingerprints
docs/              this document
```

## Testing

- Unit tests for every format: round trips, and rejection of bad prefixes, bad versions, truncated data, and changed bytes.
- A test that a message for one key fails to decrypt with another key.
- A test that decrypt finds the message inside surrounding text.
- CI runs `go vet` and `go test` on Windows and macOS runners.
- Before each release, a manual check on a real Windows machine and a real Mac: init, encrypt on one, decrypt on the other, clipboard works.

## Releases

GitHub Actions builds the Windows (amd64) and macOS (arm64 and amd64) files on each version tag and attaches them to a GitHub release with a `SHA256SUMS` file. The files are not code-signed at first; see the Install section of the README for the warnings this causes.

## Open questions

1. **Passphrase required?** The design always encrypts the private key. Dropping that would make it easier to use but leave the key readable by anything running as the user.
2. **Clipboard timer.** Is a default 60-second auto-clear worth keeping the process running, or should it be off by default?
3. **Name.** Keep `rsatoy`, even though the default is not RSA?
4. **Windows on ARM.** Add a build for it, or wait until someone needs it?
