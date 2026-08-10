import '../models/message.dart';

/// Abstract repository interface for [Message] persistence.
///
/// Phase 2: implement with SQLCipher via [MessageRepositoryImpl].
abstract class MessageRepository {
  /// Fetch all messages for a conversation, ordered by timestamp ascending.
  Future<List<Message>> getByConversation(String conversationId);

  /// Persist a new message.
  Future<void> save(Message message);

  /// Permanently erase all messages in a conversation (VOID ALL).
  Future<void> deleteAll(String conversationId);

  /// Update a message's delivery status.
  Future<void> updateStatus(String messageId, MessageStatus status);
}
