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

The diagram is a swimlane: time runs left to right in six steps, and each person has a lane, with a middle lane for what passes between them. The card above each step says which command runs, which channel the step needs, and whether anything secret is sent. Colors show the risk of the step: gray steps send nothing, green steps are low risk and can use any channel, and red steps need care because they must use a trusted channel. Solid green arrows go over an untrusted channel, dashed red arrows over a trusted one.

![Swimlane of the six steps of an rsatoy exchange between the recipient and the sender](exchange.svg)

The private key and the passphrase never leave the recipient's computer. The plain secret never leaves the sender's computer except inside the message block.

Step 5 comes before step 6 on purpose: the recipient checks that the message is really the sender's before decrypting it, so a fake secret never reaches their clipboard. If they decrypt first, the one rule is not to use the secret until the message ID has been confirmed.

## Threat model

**Protected against:**

- Anyone who sees the message block in transit or at rest (email provider, chat service, someone reading a shared channel). They learn only roughly how long the secret is.
- Tampering with the message. Any change makes decryption fail instead of producing a wrong secret.

**Protected only if people compare fingerprints (step 3):**

- Someone who swaps the public key while it travels to the sender. They could then read the secret. rsatoy cannot detect this alone, so `encrypt` shows the fingerprint and will not continue until the sender confirms it matches.

**Protected only if people compare message IDs (step 5):**

- Someone who swaps the message block for one of their own. Anyone with the recipient's public key can encrypt to it, so they could replace the real secret with, say, an API key for an account they control and see everything the recipient sends to it. They cannot read the real secret. A plain "did you send this?" does not catch this, because the sender would say yes thinking of their own message. Comparing the message ID does, because a different block has a different ID. `decrypt` shows the ID and will not ask for the passphrase until the recipient confirms it matches.

**Not protected against:**

- Malware on either computer, or someone with access to the recipient's unlocked user account.
- The recipient mishandling the secret after decrypting it.

## Cryptography

RSA cannot encrypt more than a few hundred bytes directly, and it is slow, so rsatoy uses the standard hybrid scheme: a fresh random key encrypts the secret with AES, and RSA encrypts only that random key. This is how PGP, S/MIME, and TLS's old RSA mode work.

| Purpose | Choice | Library |
| --- | --- | --- |
| Key pair | RSA, size chosen by the recipient (see [Key sizes](#key-sizes)), public exponent 65537 | Go standard library `crypto/rsa` (`GenerateKey`) |
| Encrypt the random key | RSA-OAEP with SHA-256 for both the hash and MGF1, label `rsatoy-1` | `crypto/rsa` (`EncryptOAEP`, `DecryptOAEP`) |
| Encrypt the secret | AES-256-GCM with a 32-byte random key and 12-byte random nonce | `crypto/aes`, `crypto/cipher` |
| Protect the private key on disk | scrypt (N=2^15, r=8, p=1) derives a 32-byte key from the passphrase, then AES-256-GCM | `golang.org/x/crypto/scrypt`, `crypto/cipher` |
| Fingerprint and message ID | SHA-256 of the public key's DER encoding, or of the message bytes | `crypto/sha256` |
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
| Ciphertext | secret length + 16 bytes | AES-256-GCM encryption of the secret, with the version, wrapped key length, and wrapped key as additional data |

Using the header as additional data means changing any part of it makes decryption fail. An unknown version is an error, never a guess.

**Message ID:** the first 8 bytes of SHA-256 over the decoded message bytes (not the base64 text, so line breaks and surrounding text do not change it), as 16 lowercase hex characters in groups of four, for example `7c1e 94ab 2f03 d8e6`. It is shorter than the key fingerprint because it is read aloud once per message. To fake it, someone would have to make a different message with the same 64-bit ID before the two people compare, which takes far too much work to be practical.

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
4. Prints the message block to standard output, and its message ID to standard error, with a reminder that the recipient will read this ID back in step 5.

The secret is never accepted as a command-line argument, because arguments show up in shell history and process lists.

### `rsatoy decrypt`

1. Reads the message block from standard input until the END line, or from `--in <file>`.
2. Prints the message ID and asks "Read this to the sender over a call. Does it match theirs? [y/N]". Anything but `y` stops before the passphrase is asked for. `--yes` skips the question for scripts.
3. Asks for the passphrase and decrypts.
4. Copies the secret to the clipboard and says so. It does not print the secret unless `--print` is given.
5. With `--clear-after <seconds>` (default 60, `0` turns it off), clears the clipboard after that many seconds if it still holds the secret. rsatoy stays running in the foreground until then and says so.

### `rsatoy guide`

Prints the exchange chart and a short numbered list of the steps, then exits. It is the terminal version of the [diagram above](#the-exchange-step-by-step), turned on its side so it fits in 80 columns: steps run down the page, and the three lanes are columns.

```text
       RECIPIENT (friend)       BETWEEN YOU           SENDER (you)
       ----------------------   --------------------  --------------------
  [1]  rsatoy init
       make key pair
  [2]  rsatoy pubkey            -- public key ----->  save as friend.pub
  [3]  read fingerprint aloud   == fingerprint ====>  rsatoy encrypt
                                                      check it matches
  [4]  receive message          <----- message -----  type secret,
                                                      note message ID
  [5]  rsatoy decrypt           == message ID =====>  check it matches
       read ID aloud
  [6]  enter passphrase,
       secret to clipboard

  ---->  any channel is fine, low risk (green)
  ====>  trusted channel only, call or in person (red)
```

Under the chart it prints the steps in plain words, one line each, for example "5. Run rsatoy decrypt. Read the message ID to the sender over a call. Only go on if it matches."

The chart uses ASCII only, so it shows correctly in any Windows or macOS terminal. When standard output is a terminal and `NO_COLOR` is not set, arrows and step numbers are colored like the diagram: green for low-risk steps, red for trusted-channel steps, gray for steps that send nothing. On Windows, rsatoy turns on the console's color support at startup, and falls back to no color if that fails.

### Guided mode: `rsatoy` with no arguments

Running `rsatoy` with no arguments, or double-clicking the file in Explorer or Finder, starts a step-by-step walk through the exchange, in the system language (see [Languages in the guide](#languages-in-the-guide)). This is the main way people who do not use a terminal are expected to use it.

1. Asks "Are you receiving a secret or sending one? [r/s]".
2. Before each step, clears the screen (if it is a terminal), prints the chart with the current step marked by `>` and the other steps dimmed, and says in one or two sentences what to do and over which channel.
3. Runs that step using the same code as the commands, so the prompts and checks are identical. It waits for Enter before moving on, so people can switch to their call or chat.
4. At the end, says what happened and waits for Enter before exiting, so a window opened by double-clicking does not vanish.

What each role does at each step:

| Step | Recipient | Sender |
| --- | --- | --- |
| 1 | Makes a key pair, as `init` does. Skipped if a key already exists, with a note saying so. | Not shown. The sender starts at step 2. |
| 2 | Shows the public key block and says to send it by email or chat. Offers to copy it to the clipboard. | Asks the sender to paste the public key block, or a path to a file holding it, and saves it as `friend.pub` in the current folder. |
| 3 | Shows the fingerprint and says to read it to the sender on a call. | Shows the fingerprint and asks whether it matches what the recipient read out, as `encrypt` does. |
| 4 | Says to wait for the message block. | Reads the secret at a hidden prompt, then shows the message block and message ID and offers to copy the block to the clipboard. |
| 5 | Asks the recipient to paste the message block, shows its message ID, says to read it to the sender, and asks whether the sender confirmed it. | Says to listen for the ID and check it matches the one shown in step 4. |
| 6 | Asks for the passphrase and copies the secret to the clipboard, as `decrypt` does. | Says the exchange is done. |

Pressing Ctrl+C or answering no to any check stops the guide without doing anything further. Guided mode adds no new cryptography or file formats; it only calls the same functions as the commands.

### Languages in the guide

Guided mode and `rsatoy guide` speak English or Traditional Chinese (zh-Hant), picked from the system language. The other commands stay in English only, so their output is stable for scripts and for searching error messages.

**Picking the language.** The first of these that gives an answer wins:

1. The `--lang en` or `--lang zh-Hant` flag.
2. The `RSATOY_LANG` environment variable, with the same values.
3. The `LC_ALL`, `LC_MESSAGES`, or `LANG` environment variable, in that order, ignoring `C` and `POSIX`.
4. The system's preferred UI languages: on Windows from `GetUserPreferredUILanguages`, and on macOS from `defaults read -g AppleLanguages`. macOS needs this step because a program started by double-clicking may get no `LANG`.
5. English.

The answer is parsed with `golang.org/x/text/language`. It means Traditional Chinese only when the language is Chinese and its script, given or most likely, is Traditional (`Hant`):

| System language | Guide language |
| --- | --- |
| `zh-Hant`, `zh-TW`, `zh-HK`, `zh-MO` | Traditional Chinese |
| `zh-Hans`, `zh-CN`, `zh-SG`, plain `zh` | English (see [open questions](#open-questions)) |
| `en-*` and every other language | English |

An unknown value in `--lang` or `RSATOY_LANG` is an error that lists the two allowed values.

**What is translated.** Every sentence rsatoy writes in guided mode and `rsatoy guide`, including the chart, the step explanations, prompts, confirmations, and error messages. Prompts that guided mode borrows from the commands (the fingerprint and message ID checks, passphrase prompts) take the language as a parameter, and the plain commands pass English.

**What is not translated.** Command names and flags (`rsatoy decrypt`), file names, the public key and message blocks, fingerprints, and message IDs. Yes or no answers are always `y` or `n`, shown as `[y/N]` in both languages.

**Message catalog.** Strings live in `internal/i18n/en.json` and `internal/i18n/zh-Hant.json`, embedded in the binary with `embed`. Each string has an ID, and code looks strings up by ID. Tests make sure both files have exactly the same IDs and the same `fmt` verbs in each string.

**Terms.** Traditional Chinese uses the terms common in Taiwan:

| English | zh-Hant |
| --- | --- |
| recipient / sender | 收件人 / 寄件人 |
| public key / private key | 公開金鑰 / 私密金鑰 |
| key pair | 金鑰對 |
| passphrase | 密碼片語 |
| fingerprint | 指紋 |
| message block / message ID | 訊息 / 訊息 ID |
| secret | 秘密 |
| trusted channel / untrusted channel | 可信任的管道 / 不可信任的管道 |
| clipboard | 剪貼簿 |

**The chart in Traditional Chinese.** Chinese characters take two columns in a terminal, so the chart pads columns by display width, using `golang.org/x/text/width`, not by number of characters. It still fits in 80 columns:

```text
       收件人（朋友）           兩人之間              寄件人（你）
       ----------------------   --------------------  --------------------
  [1]  rsatoy init
       產生金鑰對
  [2]  rsatoy pubkey            -- 公開金鑰 ------->  存成 friend.pub
  [3]  唸出指紋                 == 指紋 ===========>  rsatoy encrypt
                                                      確認相符
  [4]  收到訊息                 <------- 訊息 ------  輸入秘密，
                                                      記下訊息 ID
  [5]  rsatoy decrypt           == 訊息 ID ========>  確認相符
       唸出訊息 ID
  [6]  輸入密碼片語，
       秘密複製到剪貼簿

  ---->  任何管道都可以，低風險（綠色）
  ====>  只能用可信任的管道：通話或當面（紅色）
```

**Windows console.** At startup rsatoy sets the console output code page to UTF-8 (`SetConsoleOutputCP(65001)`), so Chinese text shows correctly in the old console window as well as in Windows Terminal.

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
| `golang.org/x/sys` | Windows console color and UTF-8 output, and the Windows UI language |
| `golang.org/x/text` | Language matching, and character widths for the chart |

No other dependencies.

## Project layout

```text
cmd/rsatoy/        main package: commands, flags, console setup
internal/app/      the steps shared by commands and guided mode: prompts, checks, encrypt, decrypt
internal/keys/     key generation, size checks, key file encode and decode, storage paths
internal/message/  hybrid encrypt and decrypt, message format
internal/armor/    BEGIN/END blocks and base64 wrapping
internal/fpr/      key fingerprints and message IDs
internal/guide/    the exchange chart, colors, and guided mode
internal/i18n/     language detection and the en and zh-Hant message catalogs
docs/              this document
```

## Testing

- Unit tests for every format: round trips, and rejection of bad labels, bad versions, wrong wrapped-key lengths, truncated data, and changed bytes in each field.
- Round trips at every allowed key size. 8192-bit tests use a key made once and stored as a test fixture, so the suite stays fast.
- A test that a key size outside the allowed list is refused, both at `init` and when `encrypt` reads a public key.
- A test that a message for one key fails to decrypt with another key.
- A test that blocks are found inside surrounding text.
- A test that the message ID is the same whether the block is wrapped, unwrapped, or surrounded by other text, and differs for two messages with the same secret.
- A golden-file test for the chart printed by `rsatoy guide`, with and without color, so changes to it are deliberate. When the steps change, `docs/exchange.svg` and this chart are updated in the same change.
- Tests that both message catalogs have the same IDs and the same `fmt` verbs.
- Tests for language picking: each row of the table above, the order of the sources, and rejection of unknown `--lang` values.
- A golden-file test for the Traditional Chinese chart, and a test that every chart line in both languages is at most 80 columns wide by display width.
- Guided-mode tests for both roles that feed answers through standard input and check each step's output, including stopping when a check is answered no.
- CI runs `go vet` and `go test` on Windows and macOS runners.
- Before each release, a manual check on a real Windows machine and a real Mac: init, encrypt on one, decrypt on the other, clipboard works, and a full guided exchange started by double-clicking the file, once with the system set to English and once to Traditional Chinese.

## Releases

GitHub Actions (`.github/workflows/release.yml`) builds the Windows (amd64) and macOS (arm64 and amd64) files on each version tag and attaches them to a GitHub release with a `SHA256SUMS` file. The files are bare binaries with no archive: `rsatoy-windows-amd64.exe`, `rsatoy-macos-arm64`, and `rsatoy-macos-amd64`. The tag's version, without the leading `v`, is built in as the one `rsatoy version` shows. The files are not code-signed at first; see the Install section of the README for the warnings this causes.

## Open questions

1. **Passphrase required?** The design always encrypts the private key. Dropping that would make it easier to use but leave the key readable by anything running as the user.
2. **Clipboard timer.** Is a default 60-second auto-clear worth keeping the process running, or should it be off by default?
3. **Key sizes.** Is the fixed list 2048, 3072, 4096, 8192 flexible enough, or do you want any multiple of 1024 in that range?
4. **Windows on ARM.** Add a build for it, or wait until someone needs it?
5. **Simplified Chinese.** Should `zh-Hans` and `zh-CN` systems get English, as designed, or Traditional Chinese, which most Simplified Chinese readers can follow?
6. **Plain commands.** Should `init`, `encrypt`, and `decrypt` also follow the system language, or stay English only as designed?
