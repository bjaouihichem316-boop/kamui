import 'package:sqflite/sqflite.dart';
import '../models/contact.dart';
import '../models/conversation.dart';
import '../models/message.dart';
import '../repositories/conversation_repository.dart';
import '../services/database_service.dart';
import '../services/crypto_service.dart';

/// Concrete [ConversationRepository] backed by SQLite + AES-256-GCM.
///
/// Each row in `conversations` is joined with its contact. The last
/// message is fetched with a correlated sub-select for efficiency.
class ConversationRepositoryImpl implements ConversationRepository {
  final DatabaseService _db;
  final CryptoService   _crypto;

  const ConversationRepositoryImpl(this._db, this._crypto);

  @override
  Future<List<Conversation>> getAll() async {
    final database = await _db.db;

    // Fetch all conversations ordered by updated_at desc.
    final rows = await database.rawQuery('''
      SELECT
        c.id             AS conv_id,
        c.unread_count,
        c.updated_at,
        ct.id            AS contact_id,
        ct.name,
        ct.destination,
        ct.avatar_initial,
        ct.status,
        ct.last_seen,
        m.id             AS msg_id,
        m.encrypted_text,
        m.timestamp      AS msg_ts,
        m.is_sent,
        m.is_encrypted,
        m.status         AS msg_status
      FROM conversations c
      JOIN contacts ct ON ct.id = c.contact_id
      LEFT JOIN messages m ON m.id = (
        SELECT id FROM messages
        WHERE conversation_id = c.id
        ORDER BY timestamp DESC
        LIMIT 1
      )
      ORDER BY c.updated_at DESC
    ''');

    return rows.map(_rowToConversation).toList();
  }

  @override
  Future<void> save(Conversation conversation) async {
    final database = await _db.db;
    final now = DateTime.now().millisecondsSinceEpoch;

    // Upsert contact
    await database.insert(
      'contacts',
      {
        'id':            conversation.contact.id,
        'name':          conversation.contact.name,
        'destination':   conversation.contact.destination,
        'avatar_initial': conversation.contact.avatarInitial,
        'status':        conversation.contact.status.name,
        'last_seen':     conversation.contact.lastSeen?.millisecondsSinceEpoch,
        'created_at':    now,
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );

    // Upsert conversation
    await database.insert(
      'conversations',
      {
        'id':          conversation.id,
        'contact_id':  conversation.contact.id,
        'unread_count': conversation.unreadCount,
        'created_at':  now,
        'updated_at':  now,
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  @override
  Future<void> delete(String id) async {
    final database = await _db.db;
    await database.delete('conversations', where: 'id = ?', whereArgs: [id]);
  }

  @override
  Future<void> markRead(String conversationId) async {
    final database = await _db.db;
    await database.update(
      'conversations',
      {'unread_count': 0, 'updated_at': DateTime.now().millisecondsSinceEpoch},
      where: 'id = ?',
      whereArgs: [conversationId],
    );
  }

  // ── Helpers ──────────────────────────────────────────────────────────────

  Conversation _rowToConversation(Map<String, Object?> row) {
    final contact = Contact(
      id:            row['contact_id'] as String,
      name:          row['name']       as String,
      destination:   row['destination'] as String,
      avatarInitial: row['avatar_initial'] as String,
      status: ContactStatus.values.firstWhere(
        (e) => e.name == (row['status'] as String? ?? 'offline'),
        orElse: () => ContactStatus.offline,
      ),
      lastSeen: row['last_seen'] != null
          ? DateTime.fromMillisecondsSinceEpoch(row['last_seen']! as int)
          : null,
    );

    Message? lastMsg;
    if (row['msg_id'] != null) {
      // Decrypt the stored ciphertext to recover the preview text.
      final encrypted = row['encrypted_text'] as String;
      final plain     = _crypto.decrypt(encrypted) ?? '[encrypted]';

      lastMsg = Message(
        id:             row['msg_id'] as String,
        conversationId: row['conv_id'] as String,
        text:           plain,
        timestamp:      DateTime.fromMillisecondsSinceEpoch(row['msg_ts']! as int),
        isSent:         (row['is_sent'] as int) == 1,
        isEncrypted:    (row['is_encrypted'] as int) == 1,
        status:         MessageStatus.values.firstWhere(
          (e) => e.name == (row['msg_status'] as String? ?? 'sent'),
          orElse: () => MessageStatus.sent,
        ),
      );
    }

    return Conversation(
      id:           row['conv_id'] as String,
      contact:      contact,
      lastMessage:  lastMsg,
      unreadCount:  (row['unread_count'] as int?) ?? 0,
    );
  }
}
