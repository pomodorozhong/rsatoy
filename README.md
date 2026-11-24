# rsatoy

A small command-line tool for sending a secret, such as an API key, to a friend over any channel (email, chat, a pastebin) so that only they can read it.

rsatoy is only the app layer. All cryptography comes from established, audited libraries; rsatoy never implements a cipher itself. See [docs/design.md](docs/design.md) for how it works and why.

> Status: design stage. Nothing is built yet.

## How it works

1. Your friend runs `rsatoy init` once. It makes a key pair, keeps the private key on their computer, and prints their public key and its fingerprint.
2. Your friend sends you the public key. You both compare the fingerprint over a different channel, such as a call.
3. You run `rsatoy encrypt <their public key>`, type the secret at a hidden prompt, and get back a block of text.
4. You send that text any way you like. Only your friend's private key can open it.
5. Your friend runs `rsatoy decrypt`, pastes the text, and the secret is copied to their clipboard.

## Platforms

Windows and macOS are the main targets. Linux should work but is not a priority. rsatoy is a single file with nothing else to install.

## Usage

```text
rsatoy init                 Make your key pair and show your public key
rsatoy pubkey               Show your public key and fingerprint again
rsatoy encrypt <pubkey>     Encrypt a secret for the owner of <pubkey>
rsatoy decrypt              Decrypt a message sent to you
```

Full details are in [docs/design.md](docs/design.md#commands).

## Install

Download the file for your system from the releases page and run it from a terminal.

- **macOS:** the first run may show an "unidentified developer" warning, because the file is not signed. Right-click it and choose Open, or run `xattr -d com.apple.quarantine rsatoy` once.
- **Windows:** SmartScreen may show "Windows protected your PC". Choose More info, then Run anyway.

## Building

Needs Go 1.24 or newer.

```bash
go build -o rsatoy ./cmd/rsatoy
```

Cross-builds from any machine:

```bash
GOOS=windows GOARCH=amd64 go build -o dist/rsatoy-windows-amd64.exe ./cmd/rsatoy
GOOS=darwin  GOARCH=arm64 go build -o dist/rsatoy-macos-arm64 ./cmd/rsatoy
GOOS=darwin  GOARCH=amd64 go build -o dist/rsatoy-macos-amd64 ./cmd/rsatoy
```

## About the name

Despite the name, rsatoy does not use RSA by default. It uses X25519 sealed boxes, which are smaller, faster, and have fewer ways to go wrong. The name stuck from the original idea. See [docs/design.md](docs/design.md#why-not-rsa).
