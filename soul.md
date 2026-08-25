# 📜 Kamui: The Sovereign Communication Manifesto (SOUL.md)

> "Kamui: Enter the Untouchable Dimension."

## 1. The Core Purpose
Kamui is an untouchable, serverless communication layer built on top of the I2P network and Flutter. It speaks the I2P SAM v3.3 protocol as a client — it does not embed a router; an external `i2pd` (or Java I2P) router running at `127.0.0.1:7656` provides the garlic-routing tunnels.

## 2. Non-Negotiable Pillars *(shipped today)*
- Zero-Server Architecture (No users table, no central IPs).
- Garlic Routing Over I2P via the SAM v3.3 client protocol (outbound STREAM CONNECT + inbound FORWARD/ACCEPT listener).
- End-to-End Encryption by Default: X3DH key agreement, Double Ratchet sessions, AES-256-GCM at every layer — fail-closed, no silent downgrades.
- Honesty Over Hype: this document describes only what exists in `main`. Aspirations live in §5.

## 3. Tech Stack & Architecture *(as shipped)*
- UI / Frontend: Flutter (Dart) with Dark OLED Theme (#000000).
- Transport: I2P SAM v3.3 client (`lib/services/sam_service.dart`) — requires an external i2pd router at `127.0.0.1:7656`. No FFI, no native router embedding.
- Local Storage: SQLite (`sqflite`) with AES-256-GCM field-level encryption for message bodies, ratchet session state, and outbox payloads.
- Key Material: platform Keychain / Keystore via `flutter_secure_storage`.

## 4. Brand ID
- Accent Color: Vortex Orange (#FF4500).
- Primary Background: Dimension Black (#000000).
- Tone: Cyberpunk, sharp, authoritative, and stealthy.

---

## 5. Roadmap *(NOT shipped — explicitly aspirational)*

The following are vision items. They are **not implemented** in the current codebase and must not be presented as working features:

- **Embedded i2pd router**: bundling the router inside the app so Kamui works without an external daemon. Today an external router is required.
- **Zero-Knowledge Monetization**: offline cryptographic verification via Monero / Lightning payments. Not started; no payment code exists in the repository.

When a roadmap item ships, it graduates into §2/§3 with tests and documentation — never before.
