# Changelog
All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.2.0] - 2026-05-12
### Added
- CBC/ECB Blowfish encryption with Mircryption-compatible CBC
- Raw password bytes (no MD5) for full FiSH interop with existing clients
- Zero-padding with NUL/CR/LF stripping on decrypt (remove_bad_chars)
- CBC base64 lenient decode (accepts unpadded input from other clients)
- Auto-mode detection with fallback between ECB and CBC
- Mode-aware NV key storage with CBC:/ECB: prefix detection
- AES-256-CBC key encryption on disk via EncryptValue/DecryptValue wrappers
- DH1080 key exchange with CBC suffix negotiation and FiSH10 compatibility
  Uses DH1080_INIT (not INIT_CBC) for Blow.tcl/pzs-ng compatibility
- Stale key exchange cleanup after timeout
- Full command set (30+ commands): SetKey, DelKey, ShowKey, ListKeys,
  SetKeyFrom, SetMode, GetMode, KeyX, KeyXChan, KeyXChanAll, AutoKeyX,
  EncryptTopic, EncryptGlobalTopic, DisableTarget, ProcessIncoming,
  ProcessOutgoing, EncryptNotice, EncryptAction, MarkIncoming,
  MarkIncomingTarget, MarkPos, MarkStr, MarkBroken, PlainPrefix,
  SelfTest, SetConfig, ListConfig, Version, Debug, GetNickPrefix,
  SetNickPrefix
- Auto-generated help via AddHelpCommand()
- Topic encryption (per-channel and global toggles)
- Message marking system (prefix/suffix, customizable text, per-target)
- PlainPrefix support to send cleartext despite active key
- -e prefix and PlainPrefix skip on all outgoing handlers (PRIVMSG/NOTICE/ACTION)
- DisableTarget to selectively disable encryption
- OpenSSL 4.0 compatibility (verified APIs still present)
- LibreSSL compatibility (never deprecated BF_*/DH_*/BN_*)
- ZNC's own SHA256 implementation (<znc/SHA256.h>)
- Modern CMessage-based API for all hooks
- README.md translated to English with OpenSSL 3/4 badges
- znc-buildmod build instructions in README.md
- CONTRIBUTING.md updated for OpenSSL 4 support

### Changed
- DH1080_INIT_CBC -> DH1080_INIT for Blow.tcl bind pattern compatibility
- ParseKey default mode from ModeCBC to ModeECB (Blow.tcl treats bare keys as ECB)
- SendEncryptedChunks now falls back to plaintext when no key is configured
- Refactored outgoing handlers: extracted CheckSkipEncryption and
  TryDecryptClientEncrypted helpers eliminating duplicated code blocks
- Modern ZNC module layout: public (ctor, overrides), private (helpers, members)
- Removed 31 redundant forward declarations conflicting with inline definitions
- Moved #pragma GCC diagnostic pop to end of file (zero warnings)
- NULL -> nullptr throughout
- m_pNetwork -> GetNetwork() accessor consistency
- C-style casts -> static_cast
- Includes reordered: standard -> ZNC -> OpenSSL
- Full override specifiers on all virtual method hooks

### Fixed
- Brace imbalance in +OK/mcps passthrough blocks (3 extra braces prevented build)
- DH1080_gen: null pointer guard for m_pDH before DH_set0_pqg
- DH1080_comp: null pointer guards for b_HisPubkey and key malloc
- BN memory leaks in DH1080_gen and DH1080_comp on early return
- Stale mode_ NV entries overriding explicit KeyX ecb|cbc choice
- Outgoing messages silently dropped when no key existed for target
- No override specifiers on 6 incoming handlers (OnPrivTextMessage etc.)
- -e prefix handling in OnUserMsg (was removing 3 chars from 2-char prefix)
- htob64 null termination (d[k] &= 0 -> d[k] = '\0')
- b64toh false-positive on value 0 character
- Missing OpenSSL includes (sha.h, evp.h, bn.h, dh.h, err.h, rand.h)
- Build compatibility with GNU ld 2.41+ (added -z undefs)
- Malloc null checks throughout crypto functions
- NUL/CR/LF not stripped from decrypted output (remove_bad_chars compat)

## [1.1.0] - 2025-08-10
### Added
- ZNC 1.11.x + OpenSSL 3 migration
- ECB (FiSH) + CBC (Mircryption) with fallback and AutoMode
- DH1080 improvements (FiSH10 trailing 'A' compatibility)
- Rich command set, marking, topics, SelfTest, AutoKeyX

## [1.0.0] - 2023-04-01
### Added
- Initial import (ECB/CBC basics)

[Unreleased]: https://github.com/ZarTek-Creole/znc-fish/compare/v1.2.0...HEAD
[1.2.0]: https://github.com/ZarTek-Creole/znc-fish/releases/tag/v1.2.0
[1.1.0]: https://github.com/ZarTek-Creole/znc-fish/releases/tag/v1.1.0
