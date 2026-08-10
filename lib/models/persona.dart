import 'package:flutter/foundation.dart';

/// A distinct identity persona in Kamui (Multi-Identity Support).
@immutable
class Persona {
  final String id;
  final String name;
  final String destinationKey;
  final String avatarInitial;
  final String tag;

  const Persona({
    required this.id,
    required this.name,
    required this.destinationKey,
    required this.avatarInitial,
    required this.tag,
  });

  /// Short truncated preview of the persona's destination.
  String get truncatedDestination {
    if (destinationKey.length <= 14) return destinationKey;
    return '${destinationKey.substring(0, 6)}…${destinationKey.substring(destinationKey.length - 4)}';
  }

  Persona copyWith({
    String? id,
    String? name,
    String? destinationKey,
    String? avatarInitial,
    String? tag,
  }) {
    return Persona(
      id:             id ?? this.id,
      name:           name ?? this.name,
      destinationKey: destinationKey ?? this.destinationKey,
      avatarInitial: avatarInitial ?? this.avatarInitial,
      tag:            tag ?? this.tag,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Persona && runtimeType == other.runtimeType && id == other.id;

  @override
  int get hashCode => id.hashCode;
}
