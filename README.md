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
| **AES-256-GCM message encryption** (`CryptoService`) | ✅ Implemented | `lib/services/crypto_service.dart` — PointyCastle & Cryptography, per-message random nonce |
| **X25519 & Ed25519 Identity Keyset** (`IdentityKeyService`) | ✅ Implemented | `lib/services/identity_key_service.dart` — stored in `flutter_secure_storage` (IK_ed, IK_dh, SPK, OPK) |
| **Full X3DH Key Agreement (DH1–DH4 + HKDF-SHA256)** | ✅ Implemented (Live) | `lib/services/x3dh_service.dart` — Mutual auth with Ed25519 SPK verification & forward secrecy |
| **Identity Binding & Transactional OPK Consumption** | ✅ Implemented (Live) | `lib/services/x3dh_service.dart` & `lib/services/session_manager.dart` — mandatory Ed25519 `ik_sig` binding IK_ed↔IK_dh in `HandshakeInitEnvelope` (fail-closed verification), OPK consumed only after first-message AEAD validation on a candidate session (anti-OPK-exhaustion DoS), four-state OPK consistency validation. Verified by `test/security_findings_v4_test.dart` |
| **Double Ratchet Engine (DH + Symmetric Ratchet)** | ✅ Implemented (Live) | `lib/services/double_ratchet.dart` — Transactional candidate state & rollback on MAC failure |
| **Prekey Bundle Infrastructure & QR Handshake** | ✅ Implemented (Live) | `lib/services/identity_key_service.dart` & `lib/widgets/qr_share_dialog.dart` — v3 PreKeyBundle payload |
| **Out-of-Order Skipped Keys Caching (Anti-DoS)** | ✅ Implemented (Live) | `lib/services/double_ratchet.dart` — Peek ➔ Authenticate ➔ Consume pattern with TTL & max skip bounds |
| **Fail-Closed E2EE Encryption (no silent downgrade)** | ✅ Implemented (Live) | `SessionManager.encryptV4()` & `chat_room_screen.dart` — Throws `SessionUnavailableException` on failure |
| **Live v4 Wire Transport & Decryption** | ✅ Implemented (Live) | **Bidirectional** — `kamui_v4:<headerB64>:<nonceB64>:<ciphertextB64>` streamed outbound via SAM STREAM CONNECT and received live via the inbound listener, with stream decryption in `providers.dart`. |
| **Inbound Transport (live receive)** | ✅ Implemented (Live) | `lib/services/sam_service.dart` — SAM STREAM FORWARD on `127.0.0.1:7657` (`SILENT=false`, sender routed from `FROM` line), STREAM ACCEPT fallback mode, newline-delimited payload framing, exponential reconnect backoff (2s → 60s cap, ±20% jitter). |
| **I2P SAM v3.3 STREAM Transport** | ✅ Implemented | `lib/services/sam_service.dart` — TCP socket to `127.0.0.1:7656`; socket layer abstracted behind `sam_channel.dart` for test injection |
| **OS Notification Metadata Isolation** | ✅ Implemented | `lib/services/notification_service.dart` — generic title/body only |
| **Self-Destruct TTL Messages** | ✅ Implemented | `lib/models/message.dart` — configurable expiry + DB purge |
| **Duress PIN → Defense-in-depth local storage & key wipe** | ✅ Implemented | DB + secure storage wipe on duress PIN entry |
| **Biometric / PIN Lock Gate** | ✅ Implemented | Platform local auth on app resume — **not yet enforced at startup** |

> **Legend**: ✅ Implemented = verifiable in current `main` branch source code. All v4 (X3DH + Double Ratchet) components are active and live.

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
