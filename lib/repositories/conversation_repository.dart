import '../models/conversation.dart';

/// Abstract repository interface for [Conversation] persistence.
///
/// Phase 2: implement with SQLCipher via [ConversationRepositoryImpl].
abstract class ConversationRepository {
  /// Fetch all conversations ordered by last message timestamp (descending).
  Future<List<Conversation>> getAll();

  /// Persist or update a conversation.
  Future<void> save(Conversation conversation);

  /// Delete a conversation and all its messages.
  Future<void> delete(String id);

  /// Mark all messages in a conversation as read.
  Future<void> markRead(String conversationId);
}
