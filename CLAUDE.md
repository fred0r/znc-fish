# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

ZNC FiSH Module is a ZNC (IRC bouncer) encryption module providing end-to-end message encryption for IRC channels and private messages. It implements Blowfish cryptography with both ECB (legacy FiSH compatibility) and CBC (modern Mircryption) modes, plus DH1080 key exchange protocol.

- **Language**: C++ (C++17)
- **Version**: 1.1.0
- **Main Source**: `fish.cpp` (~1500 lines)
- **Build System**: CMake 3.15+

## Development Setup

### Prerequisites

```bash
# Ubuntu/Debian
sudo apt-get install znc-dev libssl-dev libicu-dev pkg-config cmake g++ make

# Or use znc-buildmod directly
znc-buildmod fish.cpp
```

### Building

```bash
# Standard build with CMake
mkdir build && cd build
cmake ..
make

# Output: build/fish.so (the loadable module)
```

### Installation

```bash
# Option 1: make install (uses CMake install defaults)
make install

# Option 2: Manual copy to ZNC modules directory
cp fish.so ~/.znc/modules/

# Load in ZNC
/msg *status LoadMod fish
```

## Code Architecture

### Core Module Structure (fish.cpp)

**Encryption/Decryption Layers:**
- **ECB Mode**: Original FiSH protocol using Blowfish ECB with custom base64 encoding (`./0-9a-zA-Z` alphabet)
  - Output format: `+OK <fish64>` or `mcps <fish64>`
  - 12-character blocks (6 bits per char × 2 chars per 32-bit word)
  - Used for backward compatibility with legacy FiSH clients

- **CBC Mode**: Modern Mircryption standard using Blowfish CBC
  - Output format: `+OK *<standard-base64>` (IV + ciphertext)
  - Each message has unique IV for security
  - Default mode; more secure than ECB

- **Key Derivation**: MD5 for password → 128-bit key (fish_derive_key_md5)

**Key Storage:**
- Stored in ZNC's NV (non-volatile) storage with format `CBC:<key>` or `ECB:<key>`
- Per-channel and per-nick keys
- Disabled/enabled state tracked separately
- Topic encryption flags

**Message Processing Pipeline:**
1. Incoming messages: Detect `+OK` prefix, attempt decryption with configured mode, fallback to alternate mode
2. Outgoing messages: Auto-detect if key exists, encrypt with configured mode
3. Notices/Actions: Optional separate encryption flags
4. Topics: Optional encryption with per-channel/global toggles

**DH1080 Key Exchange:**
- Implements DH1080 protocol for secure key negotiation without direct transmission
- Handles `DH1080_INIT` and `DH1080_INIT_CBC` messages
- FiSH10-compatible: public keys suffixed with `A`
- Can exchange with single user, all channel users, or with auto-exchange on first PM

### Important Helper Functions

- **FiSH Base64**: `encrypts_fish()`, `decrypts_fish()`, `base64dec_fish()`, `IsFishB64Char()`
- **Blowfish**: Uses OpenSSL low-level API (`BF_set_key`, `BF_ecb_encrypt`)
- **Key Derivation**: `fish_derive_key_md5()` (EVP_Digest with MD5)

## Building, Testing, and Common Commands

### Build Commands

```bash
# Full rebuild
rm -rf build && mkdir build && cd build && cmake .. && make

# Rebuild only (if CMakeCache exists)
cd build && make

# Verbose output
cd build && make VERBOSE=1
```

### Testing

**Self-Tests (in-game IRC commands):**
```irc
/msg *fish SelfTest ecb MyKey "hello world"
/msg *fish SelfTest cbc MyKey "hello world"
```
These perform roundtrip encryption/decryption verification. Output will show `OK` or error messages.

**Interoperability Testing:**
- Test with FiSH/irssi or mIRC FiSH10 clients
- Verify channel messages with `/msg *fish ListKeys` to confirm key exists
- Check `/msg *fish GetMode <target>` to verify correct mode (ecb/cbc)

**Manual Verification:**
```irc
/msg *fish SetKey #test CBC:testkey123
/msg *fish ShowKey #test
/msg *fish SelfTest cbc testkey123 "test message"
```

## Key Patterns and Conventions

### OpenSSL 3 Compatibility

The module uses deprecated Blowfish functions (BF_set_key, BF_ecb_encrypt) for backward compatibility. Deprecation warnings are suppressed with pragmas:
```cpp
#pragma GCC diagnostic ignored "-Wdeprecated-declarations"
```
This is intentional—modern OpenSSL EVP API lacks low-level ECB access needed for legacy FiSH compatibility.

### Mode Detection and Fallback

The module attempts to auto-detect encryption mode:
1. Try primary configured mode
2. If decryption fails, attempt alternate mode
3. Update stored mode on success (unless "learning" disabled)
4. Handles mixed ECB/CBC in same conversation gracefully

### Memory Safety

- Manual malloc/free used in C-style crypto functions (`encrypts_fish`, `decrypts_fish`)
- Sensitive data (keys, plaintext) zeroed after use with `memset()`
- Proper cleanup on error paths

### NV Storage Keys

- `key_<target>` → Key material (format: `[CBC:|ECB:]<hex-encoded-key>`)
- `disabled_<target>` → Disable flag for target
- `topic_encrypt_<channel>` → Per-channel topic encryption
- `global_topic_encrypt` → Global topic encryption setting

## Important Notes for Contributors

### Before Modifying Code

1. Understand the dual-mode nature (ECB vs CBC)—changes affect compatibility
2. Test both modes with `SelfTest` commands after modifications
3. Verify interop with actual FiSH/irssi and mIRC clients if changing encryption logic
4. Check SECURITY.md for security-related changes

### Code Style & Guidelines

- Follow CONTRIBUTING.md (clear C++, early error handling, minimal scope)
- Use feature/fix branch naming (`feature/...`, `fix/...`)
- Commit messages: prefix with `feat/fix/docs/ci/refactor/chore` + imperative mood
- Update README.md and CHANGELOG.md for user-facing changes
- Keep changes focused; avoid refactoring outside PR scope

### Common Debugging Scenarios

- **Messages not decrypting**: Check `ListKeys` for target, verify `GetMode` matches client mode
- **Garbled output**: Likely mode mismatch or key corruption—test with `SelfTest`
- **ECB block truncation**: FiSH requires 12-char blocks; partial blocks show as corruption (use `MarkBroken on`)
- **Build failures**: Ensure `znc-dev`, `libssl-dev` headers installed; check `CMakeLists.txt` for ZNC include paths

## Documentation Files

- **README.md** — Full user guide with commands and configuration examples
- **docs/COMMANDS.md** — Quick command reference
- **docs/TROUBLESHOOTING.md** — Common issues and solutions
- **CONTRIBUTING.md** — Contribution guidelines
- **SECURITY.md** — Security reporting policy
- **CHANGELOG.md** — Version history
