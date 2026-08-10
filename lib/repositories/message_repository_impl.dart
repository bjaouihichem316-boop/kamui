import 'package:sqflite/sqflite.dart';
import '../models/message.dart';
import '../repositories/message_repository.dart';
import '../services/database_service.dart';
import '../services/crypto_service.dart';

/// Concrete [MessageRepository] backed by SQLite + AES-256-GCM.
/// Supports Self-Destructing (TTL) messages.
class MessageRepositoryImpl implements MessageRepository {
  final DatabaseService _db;
  final CryptoService   _crypto;

  const MessageRepositoryImpl(this._db, this._crypto);

  @override
  Future<List<Message>> getByConversation(String conversationId) async {
    // Purge expired before returning
    await _db.deleteExpiredMessages();

    final database = await _db.db;
    final rows = await database.query(
      'messages',
      where:   'conversation_id = ?',
      whereArgs: [conversationId],
      orderBy:   'timestamp ASC',
    );

    return rows.map(_rowToMessage).where((m) => !m.isExpired).toList();
  }

  @override
  Future<void> save(Message message) async {
    final database = await _db.db;
    final encrypted = _crypto.encrypt(message.text);

    await database.insert(
      'messages',
      {
        'id':              message.id,
        'conversation_id': message.conversationId,
        'encrypted_text':  encrypted,
        'timestamp':       message.timestamp.millisecondsSinceEpoch,
        'is_sent':         message.isSent ? 1 : 0,
        'is_encrypted':    message.isEncrypted ? 1 : 0,
        'status':          message.status.name,
        'ttl_seconds':     message.ttlSeconds,
        'expires_at':      message.expiresAt?.millisecondsSinceEpoch,
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );

    await database.update(
      'conversations',
      {
        'updated_at':  message.timestamp.millisecondsSinceEpoch,
        'unread_count': message.isSent ? 0 : 1,
      },
      where:     'id = ?',
      whereArgs: [message.conversationId],
    );
  }

  @override
  Future<void> deleteAll(String conversationId) async {
    final database = await _db.db;
    await database.delete(
      'messages',
      where:     'conversation_id = ?',
      whereArgs: [conversationId],
    );
    await database.update(
      'conversations',
      {'unread_count': 0},
      where:     'id = ?',
      whereArgs: [conversationId],
    );
  }

  @override
  Future<void> updateStatus(String messageId, MessageStatus status) async {
    final database = await _db.db;
    await database.update(
      'messages',
      {'status': status.name},
      where:     'id = ?',
      whereArgs: [messageId],
    );
  }

  /// Purges all expired TTL messages from SQLite.
  Future<int> purgeExpired() async {
    return await _db.deleteExpiredMessages();
  }

  // ── Helper ────────────────────────────────────────────────────────────────

  Message _rowToMessage(Map<String, Object?> row) {
    final encrypted = row['encrypted_text'] as String;
    final plain     = _crypto.decrypt(encrypted) ?? '[encrypted]';

    return Message(
      id:             row['id']             as String,
      conversationId: row['conversation_id'] as String,
      text:           plain,
      timestamp:      DateTime.fromMillisecondsSinceEpoch(row['timestamp']! as int),
      isSent:         (row['is_sent']      as int) == 1,
      isEncrypted:    (row['is_encrypted'] as int) == 1,
      status:         MessageStatus.values.firstWhere(
        (e) => e.name == (row['status'] as String? ?? 'sent'),
        orElse: () => MessageStatus.sent,
      ),
      ttlSeconds: row['ttl_seconds'] as int?,
      expiresAt:  row['expires_at'] != null
          ? DateTime.fromMillisecondsSinceEpoch(row['expires_at']! as int)
          : null,
    );
  }
}
