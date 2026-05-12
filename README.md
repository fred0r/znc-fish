# 🔐 ZNC FiSH Module

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![ZNC Version](https://img.shields.io/badge/ZNC-1.11.x-green.svg)](https://znc.in/)
[![OpenSSL](https://img.shields.io/badge/OpenSSL-3%2F4-red.svg)](https://www.openssl.org/)

## Description

FiSH encryption module for ZNC, providing cryptographic protection for IRC communications via ECB and CBC modes with full OpenSSL 3/4 support and DH1080 key exchange.

### Benefits

- ✅ **Enhanced security** : End-to-end encryption of IRC messages (channels and private messages)
- ✅ **Broad compatibility** : ECB (legacy clients) and CBC (modern standard) support
- ✅ **Automatic exchange** : DH1080 protocol for secure key negotiation
- ✅ **OpenSSL 3 & 4 / LibreSSL** : Works with ZNC 1.11.x, OpenSSL 1.1.1+, 3.x, 4.x, and LibreSSL 3.x+
- ✅ **Flexibility** : Per-channel, per-user configuration, topic encryption
- ✅ **Interoperability** : Compatible with WeeChat FiSH, FiSH-irssi, mIRC FiSH10 — wire-compatible ECB, CBC, and DH1080

---

## Installation

### Prerequisites

- **ZNC** version 1.11.x or later
- **OpenSSL** version 3.x or 4.x
- **CMake** version 3.15 or later
- C++ compiler with C++17 support

### Installation steps

1. **Clone the repository**
   ```bash
   git clone https://github.com/ZarTek-Creole/znc-fish.git
   cd znc-fish
   ```

2. **Build the module**

   Using **CMake** (recommended):
   ```bash
   mkdir build && cd build
   cmake ..
   make
   ```

   Using **znc-buildmod** (quick alternative):
   ```bash
   znc-buildmod fish.cpp
   ```

3. **Install the module**
   ```bash
   make install
   ```
   Or manually copy `fish.so` to `~/.znc/modules/`

4. **Load the module in ZNC**
   ```irc
   /msg *status LoadMod fish
   ```

5. **Restart ZNC** after replacing the module to unload any previous version.

---

## Configuration

### Basic configuration

#### Setting an encryption key

- **CBC mode (default, recommended)** :
  ```irc
  /msg *fish SetKey #channel CBC:mySecretKey
  ```

- **ECB mode (for legacy clients)** :
  ```irc
  /msg *fish SetKey nick ECB:legacyKey
  ```

#### Key management

- **List keys** :
  ```irc
  /msg *fish ListKeys
  ```
  Add `full` to display complete keys: `/msg *fish ListKeys full`

- **Show a specific key** :
  ```irc
  /msg *fish ShowKey #channel
  /msg *fish ShowKey nick
  ```

- **Delete a key** :
  ```irc
  /msg *fish DelKey #channel
  ```

- **Copy a key** :
  ```irc
  /msg *fish SetKeyFrom <destination> <source>
  ```

### DH1080 key exchange

The DH1080 protocol enables secure key exchange without direct transmission.

- **With a user** :
  ```irc
  /msg *fish KeyX nick [ecb|cbc]
  ```

- **With a user for a channel** :
  ```irc
  /msg *fish KeyXChan #channel nick [ecb|cbc]
  ```

- **Broadcast to all channel users** :
  ```irc
  /msg *fish KeyXChanAll #channel [ecb|cbc]
  ```

- **Automatic exchange** (on first PM without a key) :
  ```irc
  /msg *fish AutoKeyX on|off
  ```

The module accepts `DH1080_INIT` and `DH1080_INIT_CBC`, and sends/accepts FiSH10 public keys with `A` suffix.

### Advanced options

#### Topic encryption

- **Per channel** :
  ```irc
  /msg *fish EncryptTopic #channel on|off|status
  ```

- **Global** :
  ```irc
  /msg *fish EncryptGlobalTopic on|off|status
  ```

#### Disable encryption for a target

```irc
/msg *fish DisableTarget <#channel|nick> on|off
```

#### Cleartext prefix

To send a message in cleartext despite an active key, prepend `-e` (built-in) or configure a custom prefix:
```irc
/msg *fish PlainPrefix <prefix>
/msg *fish PlainPrefix off
```

#### Message processing

- **Incoming/Outgoing messages** :
  ```irc
  /msg *fish ProcessIncoming on|off
  /msg *fish ProcessOutgoing on|off
  ```

- **Notices and actions** :
  ```irc
  /msg *fish EncryptNotice on|off
  /msg *fish EncryptAction on|off
  ```

#### Message marking (local only)

- **Mark decrypted messages** :
  ```irc
  /msg *fish MarkIncoming on|off
  /msg *fish MarkIncomingTarget <target> on|off
  ```

- **Marker position** :
  ```irc
  /msg *fish MarkPos prefix|suffix
  ```

- **Marker text** :
  ```irc
  /msg *fish MarkStr dec|enc|plain <text>
  ```

- **Mark corrupted messages** :
  ```irc
  /msg *fish MarkBroken on|off
  ```

---

## Usage

### Quick start

1. **Set a key for a channel** :
   ```irc
   /msg *fish SetKey #mychannel CBC:superSecret123
   ```

2. **Join the channel and communicate** :
   - All messages will be automatically encrypted/decrypted
   - Other users must have the same key

3. **Verify configuration** :
   ```irc
   /msg *fish ListKeys
   ```

### Encryption modes

#### CBC (Cipher Block Chaining) - Recommended

- Format: `+OK *<base64>` (IV + ciphertext, MIME standard base64)
- More secure, modern standard
- Each message has a unique initialization vector

#### ECB (Electronic Codebook) - Legacy

- Format: `+OK <fish64>` or `mcps <fish64>` (FiSH base64 `./0-9a-zA-Z` in 12-character blocks)
- Compatible with older FiSH clients
- Less secure but necessary for interoperability

### Detection and compatibility

- **Automatic fallback**: The module tries the configured mode first, then the other mode on failure
- **Automatic learning**: The stored mode can be updated upon successful decryption (unless disabled)
- **Mode switching**:
  ```irc
  /msg *fish SetMode <target> ecb|cbc
  /msg *fish GetMode <target>
  ```

### Key storage

Keys are stored in ZNC NV with the format:
- `CBC:<key>` or `ECB:<key>`
- Defaults to ECB if no prefix
- Values are AES-256-CBC encrypted on disk using the ZNC user password

### Tests and diagnostics

#### Local tests (roundtrip)

```irc
/msg *fish SelfTest ecb MyKey hello
/msg *fish SelfTest cbc MyKey hello
```

These commands encrypt then decrypt the text to verify correct operation.

#### Interoperability tests

To test with FiSH/irssi or mIRC FiSH10:

1. **Private messages**:
   - Each side: `/msg *fish KeyX <nick>`
   - Send a short message like `!df`

2. **Channel**:
   - Set the same CBC key on all clients
   - Verify that `+OK *...` messages are decrypted correctly

---

## Command reference

### Key management

- `SetKey <#channel|Nick> [CBC:|ECB:]<key>` — Set a key
- `DelKey <#channel|Nick>` — Delete a key
- `ShowKey <#channel|Nick>` — Show a key
- `ListKeys [full]` — List all keys
- `SetKeyFrom <dest> <source>` — Copy a key
- `SetMode <target> ecb|cbc` — Set the mode
- `GetMode <target>` — Get the current mode

### Key exchange

- `KeyX <nick> [ecb|cbc]` — Exchange a key with a user
- `KeyXChan <#channel> <nick> [ecb|cbc]` — Exchange for a channel
- `KeyXChanAll <#channel> [ecb|cbc]` — Broadcast to all users
- `AutoKeyX on|off` — Automatic exchange on first PM

### Message processing

- `ProcessIncoming on|off` — Process incoming messages
- `ProcessOutgoing on|off` — Process outgoing messages
- `EncryptNotice on|off` — Encrypt notices
- `EncryptAction on|off` — Encrypt actions (/me)

### Topics

- `EncryptTopic <#channel> on|off|status` — Encrypt a channel's topic
- `EncryptGlobalTopic on|off|status` — Global setting for all channels

### Marking (local)

- `MarkIncoming on|off` — Mark decrypted messages
- `MarkIncomingTarget <target> on|off` — Per target
- `MarkPos prefix|suffix` — Marker position
- `MarkStr dec|enc|plain <text>` — Marker text
- `MarkBroken on|off` — Mark corrupted messages (adds `&` for truncated FiSH blocks)

### Utilities

- `PlainPrefix <prefix|off>` — Set a custom prefix to skip encryption (built-in `-e` always works)
- `DisableTarget <#channel|nick> on|off` — Disable encryption for a target
- `SelfTest <ecb|cbc> <key> <text>` — Roundtrip encryption test
- `SetConfig <name> [value]` — Set a config option
- `ListConfig` — List all config options
- `Help` — Show this help (auto-generated from registered commands)
- `Version` — Show module version

---

## License

This project is distributed under the **Apache License 2.0**. See the [LICENSE](LICENSE) file for details.

### Technical implementation

- Blowfish ECB with FiSH custom base64, CBC with standard base64 (Mircryption-compatible)
- DH1080 key exchange using the same 1080-bit Sophie Germain prime, generator g=2, and SHA-256 secret derivation as all FiSH variants
- OpenSSL 3/4 deprecation warnings are suppressed in code via GCC pragmas; LibreSSL is also supported
- Wire-protocol compatible with WeeChat fish.py, FiSH-irssi, and mIRC FiSH10 (verified against reference implementations)

---

## Useful links

- [ZNC Documentation](https://wiki.znc.in/)
- [OpenSSL Documentation](https://www.openssl.org/docs/)
- [FiSH Protocol References](https://github.com/falsovsky/FiSH-irssi)
- [WeeChat FiSH](https://github.com/freshprince/weechat-fish)
- [mIRC FiSH10](https://github.com/flakes/mirc_fish_10)
- [Code of Conduct](CODE_OF_CONDUCT.md)
- [Contribution Guide](CONTRIBUTING.md)
- [Security Policy](SECURITY.md)
- [Changelog](CHANGELOG.md)

---

## Contact & Support

- **Author**: [ZarTek-Creole](https://github.com/ZarTek-Creole)
- **Issues**: [Report a bug or request a feature](https://github.com/ZarTek-Creole/znc-fish/issues)
- **Discussions**: [Join the discussions](https://github.com/ZarTek-Creole/znc-fish/discussions)
- **Pull Requests**: Contributions are welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

---

## Acknowledgements

Thanks to all contributors and the ZNC community for their ongoing support.

---

**Note**: Restart ZNC after installing or updating the module to ensure the latest version is loaded.
