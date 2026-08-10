<div align="center">

# 🥷 KAMUI (カムイ)
### Untouchable Serverless Communication over I2P Network

[![Flutter](https://img.shields.io/badge/Flutter-3.29-02569B?logo=flutter&logoColor=white)](https://flutter.dev)
[![Dart](https://img.shields.io/badge/Dart-3.12-0175C2?logo=dart&logoColor=white)](https://dart.dev)
[![I2P SAM](https://img.shields.io/badge/Protocol-I2P_SAM_v3.3-6B46C1?logo=tor-project&logoColor=white)](https://geti2p.net)
[![Encryption](https://img.shields.io/badge/Encryption-AES--256--GCM-00F0FF)](https://en.wikipedia.org/wiki/Galois/Counter_Mode)
[![License](https://img.shields.io/badge/License-MIT-00FF88)](LICENSE)

*An end-to-end encrypted, serverless, dark-futuristic HUD messaging application operating over Invisible Internet Project (I2P) garlic routing tunnels.*

---

</div>

## 🌌 Overview

**Kamui** is a zero-trust, serverless communication client designed for high-assurance anonymity and privacy. By pairing hardware-backed **AES-256-GCM symmetric encryption** with **I2P SAM v3.3 garlic routing**, Kamui eliminates central relays, third-party metadata harvesting, and IP address exposure.

The application features a dark-futuristic **Cyberpunk HUD aesthetic**, custom particle canvas animators, biometric locks, duress coercion protection, and self-destructing messages.

---

## ⚡ Key Features

- 🛡️ **Zero-Trust Garlic Transport**: Transmits encrypted byte payloads through multi-hop anonymous I2P garlic tunnels via SAM v3.3.
- 🔐 **AES-256-GCM Cryptography**: Per-message hardware-backed random 96-bit nonce encryption. Keys are persisted safely in platform Keychains (`flutter_secure_storage`).
- 💣 **Self-Destruct Messages (TTL)**: Configurable message expiration timers (30s, 5m, 1h, 24h) with shrinking visual countdown progress bars and automated SQLite purges.
- 🚨 **Duress Panic Mode**: Primary PIN unlocks Kamui; entering a secret **Duress PIN** instantly & silently nukes all local databases and keys, opening a harmless disguised news feed.
- 🎭 **Multi-Identity Persona Switcher**: Switch between distinct anonymous personas (*Ghost Persona*, *Work Relay*, *Anonymous Gateway*) dynamically.
- 🎨 **Neon Theme Switcher**: 4 HUD accent themes (*Cyber Orange*, *Matrix Green*, *Void Purple*, *Electric Cyan*) persisted via `SharedPreferences`.
- 📡 **Dynamic QR Key Exchange**: Render Cyberpunk QR codes of destination keys and scan peer codes using the camera scanner (`mobile_scanner`).
- 🔔 **Native Local Notifications**: System notifications triggered on incoming peer garlic messages via `flutter_local_notifications`.

---

## 🏗️ Architecture

```
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

<div align="center">
  <sub>Built with ❤️ for privacy and decentralization.</sub>
</div>
