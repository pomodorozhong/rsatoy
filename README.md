# rsatoy

A small command-line tool for sending a secret, such as an API key, to a friend over any channel (email, chat, a pastebin) so that only they can read it.

rsatoy is only the app layer. All cryptography comes from established, audited libraries; rsatoy never implements a cipher itself. See [docs/design.md](docs/design.md) for how it works and why.

> Status: early version, not released yet. There are no downloads on a releases page yet; build it from source for now.

## How it works

1. Your friend runs `rsatoy init` once, choosing an RSA key size if they want (2048, 3072, 4096, or 8192 bits; 3072 by default). It makes a key pair, keeps the private key on their computer locked with a passphrase, and prints their public key and its fingerprint.
2. Your friend sends you the public key. You both compare the fingerprint over a different channel, such as a call.
3. You save the key to a file, run `rsatoy encrypt friend.pub`, type the secret at a hidden prompt, and get back a block of text and a short message ID.
4. You send that text any way you like. Only your friend's private key can open it.
5. Your friend runs `rsatoy decrypt` and pastes the text. It shows a short message ID, which your friend reads to you over the call so you can check it matches the one `encrypt` showed you. That proves the message really came from you.
6. Your friend enters their passphrase, and the secret is copied to their clipboard.

There is a diagram of who sends what to whom, step by step, in [docs/design.md](docs/design.md#the-exchange-step-by-step).

The easiest way to use it is to run `rsatoy` with no arguments, or double-click it. It asks whether you are sending or receiving, then walks you through each step, showing where you are on a chart. `rsatoy guide` prints the same chart without doing anything. Both speak English or Traditional Chinese (繁體中文), following your system language; use `--lang en` or `--lang zh-Hant` to choose.

## Platforms

Windows and macOS are the main targets. Linux should work but is not a priority. rsatoy is a single file with nothing else to install.

## Usage

```text
rsatoy                      Walk through the whole exchange step by step
rsatoy guide                Show the exchange chart and the steps
rsatoy init [--bits N]      Make your key pair and show your public key
rsatoy pubkey               Show your public key and fingerprint again
rsatoy encrypt <file>       Encrypt a secret for the owner of the public key in <file>
rsatoy decrypt              Decrypt a message sent to you
```

Full details are in [docs/design.md](docs/design.md#commands).

## Install

Download the file for your system from the [releases page](https://github.com/pomodorozhong/rsatoy/releases).

- **Windows:** download `rsatoy-windows-amd64.exe` and double-click it.
- **macOS:** download `rsatoy-macos-arm64` for Apple silicon or `rsatoy-macos-amd64` for Intel Macs, rename it to `rsatoy`, and run `chmod +x rsatoy` once.

`SHA256SUMS` on the same page lists each file's checksum, so you can check the download.

The files are not signed yet, so the first run shows a warning:

- **macOS:** the first run may show an "unidentified developer" warning, because the file is not signed. Right-click it and choose Open, or run `xattr -d com.apple.quarantine rsatoy` once.
- **Windows:** SmartScreen may show "Windows protected your PC". Choose More info, then Run anyway.

## Building

Needs Go 1.26 or newer.

```bash
go build -o rsatoy ./cmd/rsatoy
```

Run the tests:

```bash
go test ./...
```

Cross-builds from any machine:

```bash
GOOS=windows GOARCH=amd64 go build -o dist/rsatoy-windows-amd64.exe ./cmd/rsatoy
GOOS=darwin  GOARCH=arm64 go build -o dist/rsatoy-macos-arm64 ./cmd/rsatoy
GOOS=darwin  GOARCH=amd64 go build -o dist/rsatoy-macos-amd64 ./cmd/rsatoy
```

## Making a release

Push a version tag, and GitHub Actions builds the files and publishes the release:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Do the manual check in [docs/design.md](docs/design.md#testing) first.

## Cryptography

rsatoy uses RSA-OAEP (SHA-256) to protect a one-time AES-256-GCM key, and AES-GCM to encrypt the secret itself. Everything comes from Go's standard library, plus scrypt from `golang.org/x/crypto` for the passphrase. See [docs/design.md](docs/design.md#cryptography).
