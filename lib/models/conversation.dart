import 'package:flutter/foundation.dart';
import 'contact.dart';
import 'message.dart';

/// A conversation thread between the local user and a [Contact].
@immutable
class Conversation {
  final String id;
  final Contact contact;
  final Message? lastMessage;
  final int unreadCount;

  const Conversation({
    required this.id,
    required this.contact,
    this.lastMessage,
    this.unreadCount = 0,
  });

  /// Human-readable relative time for the last message.
  String get lastMessageTimeAgo {
    if (lastMessage == null) return '';
    final diff = DateTime.now().difference(lastMessage!.timestamp);
    if (diff.inSeconds < 60)  return 'just now';
    if (diff.inMinutes < 60)  return '${diff.inMinutes}m ago';
    if (diff.inHours < 24)    return '${diff.inHours}h ago';
    return '${diff.inDays}d ago';
  }

  Conversation copyWith({
    String? id,
    Contact? contact,
    Message? lastMessage,
    int? unreadCount,
  }) {
    return Conversation(
      id: id ?? this.id,
      contact: contact ?? this.contact,
      lastMessage: lastMessage ?? this.lastMessage,
      unreadCount: unreadCount ?? this.unreadCount,
    );
  }

  @override
  bool operator ==(Object other) =>
      identical(this, other) ||
      other is Conversation && runtimeType == other.runtimeType && id == other.id;

  @override
  int get hashCode => id.hashCode;
}
