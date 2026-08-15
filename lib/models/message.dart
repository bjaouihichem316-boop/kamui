import 'package:flutter/foundation.dart';

/// Delivery status for outgoing messages.
enum MessageStatus { sending, sent, delivered, failed }

/// A single chat message in a Kamui conversation.
@immutable
class Message {
  final String id;
  final String conversationId;

  /// The persisted payload string (wire ciphertext or stored encrypted value).
  /// SECURITY INVARIANT: For network messages, this holds the wire payload.
  final String text;

  /// Transient, in-memory decrypted plaintext (NEVER persisted to disk directly).
  final String? decryptedText;

  final DateTime timestamp;

  /// true = sent by us, false = received from peer.
  final bool isSent;

  /// Whether E2E encryption was applied.
  final bool isEncrypted;

  final MessageStatus status;

  /// Time-To-Live duration in seconds (Self-Destruct / Disappearing Messages).
  final int? ttlSeconds;

  /// Absolute expiration timestamp.
  final DateTime? expiresAt;

  const Message({
    required this.id,
    required this.conversationId,
    required this.text,
    this.decryptedText,
    required this.timestamp,
    required this.isSent,
    this.isEncrypted = true,
    this.status      = MessageStatus.sent,
    this.ttlSeconds,
    this.expiresAt,
  });

  /// The text to display in the UI — prefers transient [decryptedText] when available,
  /// falling back to [text].
  String get displayText => decryptedText ?? text;

  /// Whether the message has passed its TTL expiration timestamp.
  bool get isExpired =>
      expiresAt != null && DateTime.now().isAfter(expiresAt!);

  /// Remaining TTL fraction from 1.0 (new) to 0.0 (expired).
  double get remainingFraction {
    if (expiresAt == null || ttlSeconds == null || ttlSeconds == 0) return 1.0;
    final totalMs     = ttlSeconds! * 1000;
    final remainingMs = expiresAt!.difference(DateTime.now()).inMilliseconds;
    if (remainingMs <= 0) return 0.0;
    return (remainingMs / totalMs).clamp(0.0, 1.0);
  }

  /// Returns HH:MM formatted timestamp.
  String get formattedTime {
    final h = timestamp.hour.toString().padLeft(2, '0');
    final m = timestamp.minute.toString().padLeft(2, '0');
    return '$h:$m';
  }

  Message copyWith({
    String? id,
    String? conversationId,
    String? text,
    String? decryptedText,
    DateTime? timestamp,
    bool? isSent,
    bool? isEncrypted,
    MessageStatus? status,
    int? ttlSeconds,
    DateTime? expiresAt,
  }) {
    return Message(
      id:             id ?? this.id,
      conversationId: conversationId ?? this.conversationId,
      text:           text ?? this.text,
      decryptedText:  decryptedText ?? this.decryptedText,
      timestamp:      timestamp ?? this.timestamp,
      isSent:         isSent ?? this.isSent,
      isEncrypted:    isEncrypted ?? this.isEncrypted,
      status:         status ?? this.status,
      ttlSeconds:     ttlSeconds ?? this.ttlSeconds,
      expiresAt:      expiresAt ?? this.expiresAt,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Message && runtimeType == other.runtimeType && id == other.id;

  @override
  int get hashCode => id.hashCode;
}
