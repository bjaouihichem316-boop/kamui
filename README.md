# 🥷 KAMUI (カムイ)

## Untouchable Serverless Communication over I2P Network

[![Flutter](https://img.shields.io/badge/Flutter-3.29-02569B?logo=flutter&logoColor=white)](https://flutter.dev)
[![Dart](https://img.shields.io/badge/Dart-3.12-0175C2?logo=dart&logoColor=white)](https://dart.dev)
[![I2P SAM](https://img.shields.io/badge/Protocol-I2P_SAM_v3.3-6B46C1?logo=tor-project&logoColor=white)](https://geti2p.net)
[![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-00F0FF)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![License](https://img.shields.io/badge/License-MIT-00FF88)](LICENSE)

*An end-to-end encrypted, serverless, dark-futuristic HUD messaging application operating over Invisible Internet Project (I2P) garlic routing tunnels.*

---

## 🌌 Overview

**Kamui** is a zero-trust, serverless communication client designed for high-assurance anonymity and privacy. By pairing hardware-backed **AES-256-GCM symmetric encryption** with **I2P SAM v3.3 garlic routing**, Kamui eliminates central relays, third-party metadata harvesting, and IP address exposure.

The application features a dark-futuristic **Cyberpunk HUD aesthetic**, custom particle canvas animators, biometric locks, duress coercion protection, and self-destructing messages.

---

## ⚡ Key Features

- 🛡️ **Zero-Trust Garlic Transport**: Transmits encrypted byte payloads through multi-hop anonymous I2P garlic tunnels via SAM v3.3.
- 🔐 **AES-256-GCM Cryptography**: Per-message hardware-backed random 96-bit nonce encryption. Keys are persisted safely in platform Keychains (`flutter_secure_storage`).
- 💣 **Self-Destruct Messages (TTL)**: Configurable message expiration timers (30s, 5m, 1h, 24h) with shrinking visual countdown progress bars and automated SQLite purges.
- 🚨 **Duress Panic Mode**: Primary PIN unlocks Kamui; entering a secret **Duress PIN** triggers defense-in-depth local storage & key wipe, then opens a harmless disguised news feed.
- 🎭 **Multi-Identity Persona Switcher**: Switch between distinct anonymous personas (*Ghost Persona*, *Work Relay*, *Anonymous Gateway*) dynamically.
- 🎨 **Neon Theme Switcher**: 4 HUD accent themes (*Cyber Orange*, *Matrix Green*, *Void Purple*, *Electric Cyan*) persisted via `SharedPreferences`.
- 📡 **Dynamic QR Key Exchange**: Render Cyberpunk QR codes of destination keys and scan peer codes using the camera scanner (`mobile_scanner`).
- 🔔 **Native Local Notifications**: System notifications triggered on incoming peer garlic messages via `flutter_local_notifications`.

---

## 🏗️ Architecture

```text
                       ┌───────────────────────────────┐
                       │     Kamui Flutter Client      │
                       └───────────────┬───────────────┘
                                       │
                    AES-256-GCM Encrypted Payloads (PointyCastle)
                                       │
                                       ▼
                       ┌───────────────────────────────┐
                       │    SAM Service (v3.3 STREAM)  │
                       │     TCP 127.0.0.1:7656        │
                       └───────────────┬───────────────┘
                                       │
                        I2P Garlic Tunnels (3 Hops)
                                       │
                                       ▼
                       ┌───────────────────────────────┐
                       │    Destination Peer (I2P)     │
                       └───────────────────────────────┘
```

### Local Storage Security

Messages and contacts are persisted using SQLite (`sqflite`). Message bodies are encrypted with **AES-256-GCM ciphertext** before disk insertion.

---

## 🛡️ Implementation Status Matrix

This table provides full transparency on what is currently implemented in the codebase versus what is planned for a future roadmap. We believe clarity here is a prerequisite for security credibility.

| Feature / Property | Status | Implementation Notes |
| :--- | :---: | :--- |
| **AES-256-GCM message encryption** (`CryptoService`) | ✅ Implemented | `lib/services/crypto_service.dart` — PointyCastle, per-message random nonce |
| **X25519 Long-Term Identity Keypair** (`IdentityKeyService`) | ✅ Implemented | `lib/services/identity_key_service.dart` — stored in `flutter_secure_storage` |
| **Session Key Derivation (X25519 + SHA-256 domain label)** | ✅ Implemented | `lib/services/session_manager.dart` — `Kamui-Session-v2` domain separation |
| **Ratcheted Message Keys (4-byte counter)** | ✅ Implemented | `SessionState.getNextSendKey()` / `peekReceiveKey()` — overflow-safe 32-bit LE |
| **Fail-Closed Encryption (no silent downgrade)** | ✅ Implemented | `encryptMessage()` throws `SessionUnavailableException` — no fallback path |
| **I2P SAM v3.3 STREAM Transport** | ✅ Implemented | `lib/services/sam_service.dart` — TCP socket to `127.0.0.1:7656` |
| **OS Notification Metadata Isolation** | ✅ Implemented | `lib/services/notification_service.dart` — generic title/body only |
| **QR Code v2 Handshake Payload** (`id_pub` field) | ✅ Implemented | `lib/widgets/qr_share_dialog.dart` — JSON `{v:2, dest, id_pub}` |
| **Self-Destruct TTL Messages** | ✅ Implemented | `lib/models/message.dart` — configurable expiry + DB purge |
| **Duress PIN → Defense-in-depth local storage & key wipe** | ✅ Implemented | DB + secure storage wipe on duress PIN entry |
| **Biometric / PIN Lock Gate** | ✅ Implemented | Platform local auth on app resume |
| **Full X3DH Key Agreement (DH1–DH4 + HKDF)** | 🗺️ Planned | Roadmap v3 — current session uses single X25519 DH + SHA-256 KDF |
| **Double Ratchet (DH + Symmetric chain, Signal-spec)** | 🗺️ Planned | Roadmap v3 — current ratchet is symmetric-only (counter-based) |
| **Prekey Bundle Infrastructure (SPK, OPK pool)** | 🗺️ Planned | Roadmap v3 — requires server-side or DHT prekey registry |
| **Out-of-Order Message Key Caching** | 🗺️ Planned | Roadmap v3 — skipped key store with 7-day TTL |
| **Ed25519 Message Signatures** | 🗺️ Planned | Roadmap v3 — `sig` field defined in spec, not yet validated |
| **Binary Envelope Wire Format (version byte + flags)** | 🗺️ Planned | Roadmap v3 — current wire is `kamui_v2:nonce_b64:ct_b64` text prefix |

> **Legend**: ✅ Implemented = verifiable in current `main` branch source code. 🗺️ Planned = documented in `KAMUI_PROTOCOL_SPEC.md` as a design target for a future release.

---

## 📸 Screenshots

| Splash Launch | Cyberpunk Chat List | E2E Chat Room |
| :---: | :---: | :---: |
| *(Add Screenshot)* | *(Add Screenshot)* | *(Add Screenshot)* |

| Node Settings & QR | Biometric Shield Gate | Decoy Duress Feed |
| :---: | :---: | :---: |
| *(Add Screenshot)* | *(Add Screenshot)* | *(Add Screenshot)* |

---

## 🚀 Getting Started

### Prerequisites

- **Flutter SDK**: `>=3.12.2`
- **I2P Router Daemon**: `i2pd` or Java I2P router running locally with SAM enabled (`127.0.0.1:7656`).

### Installation

1. **Clone the repository**:

   ```bash
   git clone https://github.com/bjaouihichem316-boop/kamui.git
   cd kamui
   ```

2. **Install dependencies**:

   ```bash
   flutter pub get
   ```

3. **Verify project health**:

   ```bash
   flutter analyze
   ```

4. **Run application**:

   ```bash
   flutter run
   ```

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for details.

---

*Built with ❤️ for privacy and decentralization.*
