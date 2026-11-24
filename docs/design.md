# rsatoy design

This document describes what rsatoy does, what it protects against, and the choices behind it. Code should follow it; if they disagree, fix one of them in the same change.

## Goals

- Send a short secret (an API key, a password, a token) to one person so that only they can read it, even if the message travels over an untrusted channel.
- Let the recipient choose their RSA key length.
- Work on Windows and macOS as a single file, with nothing else to install.
- Use only established cryptography libraries. rsatoy writes no cipher, padding, or key-exchange code of its own.
- Be hard to misuse: no options that weaken security, and no secrets left in terminal history, logs, or temp files.

## Non-goals

- Large files. Messages are capped at 64 KiB. Use `age` for files.
- Group messages. One message goes to one public key.
- Signing. The recipient cannot prove who sent a message (see [Threat model](#threat-model)).
- A key server or any network access. rsatoy never connects to the internet.
- Forward secrecy. If a private key leaks later, old messages to it can be read.

## The exchange step by step

The recipient is the friend who will receive the secret. The sender is the person who has it. An **untrusted channel** is any way of sending text where someone else might read or change it: email, a chat app, a pastebin. A **trusted channel** is one where each person knows they are really talking to the other: a voice or video call, or in person.

```mermaid
sequenceDiagram
    autonumber
    actor R as Recipient (friend)
    participant U as Untrusted channel<br/>(email, chat)
    participant T as Trusted channel<br/>(call, in person)
    actor S as Sender (you)

    Note over R: rsatoy init --bits 3072<br/>Makes key pair, locks private key<br/>with a passphrase, saves it locally
    R->>U: Public key block
    U->>S: Public key block
    Note over S: rsatoy encrypt friend.pub<br/>Shows the key's fingerprint
    R->>T: Reads fingerprint aloud
    T->>S: Fingerprint
    Note over S: Confirms it matches, types the secret<br/>at a hidden prompt, gets a message block
    S->>U: Message block
    U->>R: Message block
    Note over R: rsatoy decrypt<br/>Enters passphrase, secret is<br/>copied to the clipboard
    R->>T: "Got it, did you send this?"
    T->>S: Confirmation
```

What crosses each channel:

| Step | What | From | To | Channel | Secret? |
| --- | --- | --- | --- | --- | --- |
| 1–2 | Public key block | Recipient | Sender | Untrusted | No. Anyone may see it, but if someone swaps it, step 3–4 catches that. |
| 3–4 | Fingerprint | Recipient | Sender | Trusted | No. It only proves the public key is the recipient's. |
| 5–6 | Message block | Sender | Recipient | Untrusted | Encrypted. Only the recipient's private key opens it. |
| 7–8 | Confirmation | Recipient | Sender | Trusted | No. Guards against someone else encrypting a fake secret to the same public key. |

The private key and the passphrase never leave the recipient's computer. The plain secret never leaves the sender's computer except inside the message block.

## Threat model

**Protected against:**

- Anyone who sees the message block in transit or at rest (email provider, chat service, someone reading a shared channel). They learn only roughly how long the secret is.
- Tampering with the message. Any change makes decryption fail instead of producing a wrong secret.

**Protected only if people compare fingerprints (steps 3–4):**

- Someone who swaps the public key while it travels to the sender. They could then read the secret. rsatoy cannot detect this alone, so `encrypt` shows the fingerprint and will not continue until the sender confirms it matches.

**Not protected against:**

- Malware on either computer, or someone with access to the recipient's unlocked user account.
- Someone pretending to be the sender. Anyone with the recipient's public key can encrypt to it, which is why step 7–8 exists.
- The recipient mishandling the secret after decrypting it.

## Cryptography

RSA cannot encrypt more than a few hundred bytes directly, and it is slow, so rsatoy uses the standard hybrid scheme: a fresh random key encrypts the secret with AES, and RSA encrypts only that random key. This is how PGP, S/MIME, and TLS's old RSA mode work.

| Purpose | Choice | Library |
| --- | --- | --- |
| Key pair | RSA, size chosen by the recipient (see [Key sizes](#key-sizes)), public exponent 65537 | Go standard library `crypto/rsa` (`GenerateKey`) |
| Encrypt the random key | RSA-OAEP with SHA-256 for both the hash and MGF1, label `rsatoy-1` | `crypto/rsa` (`EncryptOAEP`, `DecryptOAEP`) |
| Encrypt the secret | AES-256-GCM with a 32-byte random key and 12-byte random nonce | `crypto/aes`, `crypto/cipher` |
| Protect the private key on disk | scrypt (N=2^15, r=8, p=1) derives a 32-byte key from the passphrase, then AES-256-GCM | `golang.org/x/crypto/scrypt`, `crypto/cipher` |
| Fingerprint | SHA-256 of the public key's DER encoding | `crypto/sha256` |
| Randomness | Operating system random source | `crypto/rand` |

rsatoy never uses `EncryptPKCS1v15`, raw RSA, or a key size below 2048.

A fresh AES key is made for every message, and each key is used once, so a random 12-byte nonce is safe.

### Key sizes

The recipient picks the size with `rsatoy init --bits <n>`.

| Bits | Use | Key generation time (rough) |
| --- | --- | --- |
| 2048 | Smallest allowed. Fine today, but has the least margin. | Well under a second |
| 3072 | **Default.** Comparable to 128-bit security, recommended for use past 2030. | About a second |
| 4096 | More margin, larger keys and messages. | A few seconds |
| 8192 | Allowed for those who want it. Slow to make, and the public key block is long. | Up to a minute |

Only these four values are accepted. Anything else, including other multiples of 1024, is refused with a message listing the allowed sizes. Fixed choices keep test coverage complete and stop typos like `--bits 307`.

The sender does not choose anything: `encrypt` reads the size from the public key and uses it. The size shows in `rsatoy pubkey` output and next to the fingerprint during `encrypt`.

## Formats

All binary data is base64 (standard alphabet, with padding) and wrapped at 64 characters per line, so it survives email, chat apps, and copy-paste. On reading, rsatoy ignores whitespace and anything outside the BEGIN and END lines, so a block pasted with surrounding email text still works.

**Public key:**

```text
-----BEGIN RSATOY PUBLIC KEY-----
<base64 of PKIX DER-encoded RSA public key>
-----END RSATOY PUBLIC KEY-----
```

This is the same DER as a normal `PUBLIC KEY` PEM file, with a different label so it cannot be mixed up with other keys. A 3072-bit key is about 9 lines.

**Fingerprint:** the first 16 bytes of SHA-256 over the DER bytes, as 32 lowercase hex characters in groups of four, followed by the key size, for example `3f2a 9c41 07be d5e8 1a6c 44f0 9b23 e7d1 (RSA 3072)`. People read the hex aloud to compare.

**Message:**

```text
-----BEGIN RSATOY MESSAGE-----
<base64 of the bytes below>
-----END RSATOY MESSAGE-----
```

| Field | Size | Content |
| --- | --- | --- |
| Version | 1 byte | `0x01` |
| Wrapped key length | 2 bytes, big-endian | Length of the next field, equal to the RSA key size in bytes |
| Wrapped key | 256, 384, 512, or 1024 bytes | RSA-OAEP encryption of the 32-byte AES key |
| Nonce | 12 bytes | AES-GCM nonce |
| Ciphertext | secret length + 16 bytes | AES-256-GCM encryption of the secret, with the version byte and wrapped key as additional data |

Using the header as additional data means changing any part of it makes decryption fail. An unknown version is an error, never a guess.

**Private key file:**

```text
-----BEGIN RSATOY PRIVATE KEY-----
<base64 of: version 0x01 || 16-byte scrypt salt || 12-byte nonce || AES-256-GCM(PKCS#8 DER private key)>
-----END RSATOY PRIVATE KEY-----
```

## Key storage

| System | Folder |
| --- | --- |
| Windows | `%APPDATA%\rsatoy\` |
| macOS | `~/Library/Application Support/rsatoy/` |
| Linux | `$XDG_CONFIG_HOME/rsatoy/` or `~/.config/rsatoy/` |

Go's `os.UserConfigDir()` returns the right base folder on each. The folder holds two files: `key` (the encrypted private key) and `key.pub` (the public key block, not secret).

- The private key is always encrypted with a passphrase. `init` asks for it twice and refuses an empty one.
- On macOS and Linux the folder is created with mode `0700` and `key` with `0600`. On Windows, files in the user's profile folder are already readable only by that user and administrators; rsatoy does not change ACLs.
- `init` refuses to overwrite an existing key unless given `--force`, and then it asks again before deleting.
- The `--key <path>` flag uses a different key file, for testing or for more than one identity. The public key is then read from `<path>.pub`.

## Commands

### `rsatoy init [--bits 2048|3072|4096|8192]`

Makes a key pair of the chosen size (default 3072), asks for a passphrase twice, saves both files, and prints:

```text
Your public key (send this to the person who will send you a secret):

-----BEGIN RSATOY PUBLIC KEY-----
...
-----END RSATOY PUBLIC KEY-----

Fingerprint: 3f2a 9c41 07be d5e8 1a6c 44f0 9b23 e7d1 (RSA 3072)
Read this fingerprint to them over a call or in person, and check it matches what they see.
```

For 4096 and 8192 it prints "Making a 4096-bit key, this can take a few seconds..." first.

### `rsatoy pubkey`

Prints the public key block and fingerprint again, from `key.pub`. No passphrase needed.

### `rsatoy encrypt <pubkey file>`

1. Reads the public key block from the file, or from standard input if the argument is `-`. Refuses keys under 2048 bits.
2. Prints the fingerprint and key size, then asks "Does this match what your friend told you? [y/N]". Anything but `y` stops. `--yes` skips the question for scripts, and the docs say not to use it the first time.
3. Reads the secret from a hidden prompt (no echo). If standard input is not a terminal and the key came from a file, reads the secret from standard input instead, so `rsatoy encrypt friend.pub < secret.txt` works.
4. Prints the message block to standard output.

The secret is never accepted as a command-line argument, because arguments show up in shell history and process lists.

### `rsatoy decrypt`

1. Reads the message block from standard input until the END line, or from `--in <file>`.
2. Asks for the passphrase and decrypts.
3. Copies the secret to the clipboard and says so. It does not print the secret unless `--print` is given.
4. With `--clear-after <seconds>` (default 60, `0` turns it off), clears the clipboard after that many seconds if it still holds the secret. rsatoy stays running in the foreground until then and says so.
5. Reminds the recipient to confirm with the sender that they sent it (step 7–8).

### Errors

Every failure prints one plain sentence and exits with a non-zero code. Decryption failures do not say why (wrong key, damaged message, or tampering), because telling them apart can leak information and guessing would mislead.

## Handling secrets in memory

- Read secrets and passphrases into byte slices, never strings, and overwrite them with zeros when done. Go's garbage collector can still leave copies, so this is a best effort, not a guarantee.
- Never log, print, or write a secret or private key to a temp file.
- Error messages never include secret material.

## Dependencies

| Module | Use |
| --- | --- |
| Go standard library | RSA, AES-GCM, SHA-256, randomness, flag parsing |
| `golang.org/x/crypto` | scrypt |
| `golang.org/x/term` | Hidden passphrase and secret prompts |
| `github.com/atotto/clipboard` | Clipboard on Windows and macOS |

No other dependencies.

## Project layout

```text
cmd/rsatoy/        main package: commands, prompts, output
internal/keys/     key generation, size checks, key file encode and decode, storage paths
internal/message/  hybrid encrypt and decrypt, message format
internal/armor/    BEGIN/END blocks and base64 wrapping
internal/fpr/      fingerprints
docs/              this document
```

## Testing

- Unit tests for every format: round trips, and rejection of bad labels, bad versions, wrong wrapped-key lengths, truncated data, and changed bytes in each field.
- Round trips at every allowed key size. 8192-bit tests use a key made once and stored as a test fixture, so the suite stays fast.
- A test that a key size outside the allowed list is refused, both at `init` and when `encrypt` reads a public key.
- A test that a message for one key fails to decrypt with another key.
- A test that blocks are found inside surrounding text.
- CI runs `go vet` and `go test` on Windows and macOS runners.
- Before each release, a manual check on a real Windows machine and a real Mac: init, encrypt on one, decrypt on the other, clipboard works.

## Releases

GitHub Actions builds the Windows (amd64) and macOS (arm64 and amd64) files on each version tag and attaches them to a GitHub release with a `SHA256SUMS` file. The files are not code-signed at first; see the Install section of the README for the warnings this causes.

## Open questions

1. **Passphrase required?** The design always encrypts the private key. Dropping that would make it easier to use but leave the key readable by anything running as the user.
2. **Clipboard timer.** Is a default 60-second auto-clear worth keeping the process running, or should it be off by default?
3. **Key sizes.** Is the fixed list 2048, 3072, 4096, 8192 flexible enough, or do you want any multiple of 1024 in that range?
4. **Windows on ARM.** Add a build for it, or wait until someone needs it?
