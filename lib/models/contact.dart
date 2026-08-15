import 'package:flutter/foundation.dart';

/// Represents the connection status of a contact in the I2P network.
enum ContactStatus { active, building, offline }

/// Extension to provide UI helpers for [ContactStatus].
extension ContactStatusX on ContactStatus {
  String get label {
    switch (this) {
      case ContactStatus.active:   return 'TUNNEL ACTIVE';
      case ContactStatus.building: return 'BUILDING';
      case ContactStatus.offline:  return 'OFFLINE';
    }
  }
}

/// An I2P contact / peer in the Kamui network.
@immutable
class Contact {
  final String id;
  final String name;

  /// Full I2P base64 destination key (516+ characters).
  final String destination;

  /// Optional X25519 identity public key (Base64) for E2EE session agreement.
  final String? identityPublicKey;

  /// Optional PreKeyBundle JSON string for v4 X3DH + Double Ratchet session agreement.
  final String? preKeyBundleJson;

  /// Single character initial for the avatar display.
  final String avatarInitial;

  final ContactStatus status;
  final DateTime? lastSeen;

  const Contact({
    required this.id,
    required this.name,
    required this.destination,
    this.identityPublicKey,
    this.preKeyBundleJson,
    required this.avatarInitial,
    this.status = ContactStatus.offline,
    this.lastSeen,
  });

  /// Returns the first 8 and last 4 characters of the destination
  /// separated by "..." — safe for display in UI.
  String get truncatedDestination {
    if (destination.length <= 14) return destination;
    return '${destination.substring(0, 8)}...${destination.substring(destination.length - 4)}';
  }

  Contact copyWith({
    String? id,
    String? name,
    String? destination,
    String? identityPublicKey,
    String? preKeyBundleJson,
    String? avatarInitial,
    ContactStatus? status,
    DateTime? lastSeen,
  }) {
    return Contact(
      id: id ?? this.id,
      name: name ?? this.name,
      destination: destination ?? this.destination,
      identityPublicKey: identityPublicKey ?? this.identityPublicKey,
      preKeyBundleJson: preKeyBundleJson ?? this.preKeyBundleJson,
      avatarInitial: avatarInitial ?? this.avatarInitial,
      status: status ?? this.status,
      lastSeen: lastSeen ?? this.lastSeen,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) || other is Contact && runtimeType == other.runtimeType && id == other.id;

  @override
  int get hashCode => id.hashCode;
}
