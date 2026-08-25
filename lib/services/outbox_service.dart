import 'package:sqflite/sqflite.dart';

import '../core/app_logger.dart';
import 'crypto_service.dart';
import 'database_service.dart';

// ══════════════════════════════════════════════════════════════════════════════
// Outbox — durable queue for failed SAM transmissions
// ══════════════════════════════════════════════════════════════════════════════

/// A queued wire payload that failed to leave the device.
class OutboxEntry {
  final String id;
  final String conversationId;

  /// Peer I2P destination key.
  final String destination;

  /// The E2E wire payload (`kamui_v4:...` / handshake envelope JSON), stored
  /// AES-256-GCM encrypted at rest — decrypted only for a retry attempt.
  final String encryptedPayload;
  final DateTime createdAt;
  final int retryCount;

  const OutboxEntry({
    required this.id,
    required this.conversationId,
    required this.destination,
    required this.encryptedPayload,
    required this.createdAt,
    required this.retryCount,
  });
}

/// Minimal send-outbox making the "stored locally & queued" contract real.
///
/// Flow: [SamService.sendRawMessage] fails → caller marks the message
/// `MessageStatus.failed` and calls [enqueue]. On the next SAM reconnect the
/// provider layer triggers [retryAll]; each pending entry is attempted exactly
/// once per pass. Manual long-press retries go through [retryOne].
///
/// Note: retries re-send the ORIGINAL wire ciphertext. If the peer's session
/// was re-established in the meantime, the stale ciphertext is rejected by the
/// receiver's ratchet (fail-closed) — at-most-once delivery semantics.
class OutboxService {
  static const _log = AppLogger('Outbox');

  // ─── Singleton ─────────────────────────────────────────────────────────────
  static final OutboxService _instance = OutboxService._internal();
  factory OutboxService() => _instance;

  final DatabaseService _db;
  final CryptoService _crypto;

  /// Non-reentrant guard so an auto-retry pass and a manual retry never
  /// double-send the same payload concurrently.
  bool _isRetrying = false;

  OutboxService._internal()
      : _db = DatabaseService(),
        _crypto = CryptoService();

  /// Factory for isolated instances in tests.
  factory OutboxService.isolated({
    required DatabaseService databaseService,
    required CryptoService cryptoService,
  }) {
    return OutboxService._forTest(databaseService, cryptoService);
  }

  OutboxService._forTest(this._db, this._crypto);

  // ─── Public API ────────────────────────────────────────────────────────────

  /// Queues [encryptedPayload] for later delivery. [id] MUST equal the local
  /// message id so UI retry affordances can address the entry.
  Future<void> enqueue({
    required String id,
    required String conversationId,
    required String destination,
    required String encryptedPayload,
  }) async {
    final database = await _db.db;
    await database.insert(
      'outbox',
      {
        'id':                id,
        'conversation_id':   conversationId,
        'destination':       destination,
        'encrypted_payload': _crypto.encrypt(encryptedPayload),
        'created_at':        DateTime.now().millisecondsSinceEpoch,
        'retry_count':       0,
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  /// Returns all queued entries, oldest first.
  Future<List<OutboxEntry>> pending() async {
    final database = await _db.db;
    try {
      final rows = await database.query('outbox', orderBy: 'created_at ASC');
      return rows.map(_rowToEntry).toList();
    } catch (_) {
      // Table missing pre-migration → no pending entries.
      return const [];
    }
  }

  /// Removes [id] from the outbox after successful delivery.
  Future<void> markSent(String id) async {
    final database = await _db.db;
    try {
      await database.delete('outbox', where: 'id = ?', whereArgs: [id]);
    } catch (_) {
      _log.e('Failed to dequeue outbox entry $id after delivery — '
          'a retry pass may re-send it');
    }
  }

  /// Attempts to deliver the entry with [id] via [send]. Returns `true` when
  /// delivered (entry removed) — `false` leaves it queued with bumped counter.
  Future<bool> retryOne(
    String id,
    Future<bool> Function(OutboxEntry entry) send,
  ) async {
    if (_isRetrying) return false;
    _isRetrying = true;
    try {
      final entry = await _get(id);
      if (entry == null) return false;
      return await _attempt(entry, send);
    } finally {
      _isRetrying = false;
    }
  }

  /// Retries every pending entry once, oldest first. Returns the number of
  /// entries delivered. Safe against concurrent invocation via [_isRetrying].
  Future<int> retryAll(Future<bool> Function(OutboxEntry entry) send) async {
    if (_isRetrying) return 0;
    _isRetrying = true;
    var delivered = 0;
    try {
      for (final entry in await pending()) {
        if (await _attempt(entry, send)) delivered++;
      }
    } finally {
      _isRetrying = false;
    }
    return delivered;
  }

  // ─── Internal helpers ──────────────────────────────────────────────────────

  Future<OutboxEntry?> _get(String id) async {
    try {
      final database = await _db.db;
      final rows = await database.query(
        'outbox',
        where: 'id = ?',
        whereArgs: [id],
        limit: 1,
      );
      if (rows.isEmpty) return null;
      return _rowToEntry(rows.first);
    } catch (_) {
      return null;
    }
  }

  /// One delivery attempt for [entry]: on success dequeue, on failure bump
  /// the retry counter and keep the entry queued.
  Future<bool> _attempt(
    OutboxEntry entry,
    Future<bool> Function(OutboxEntry entry) send,
  ) async {
    bool ok;
    try {
      ok = await send(entry);
    } catch (_) {
      ok = false;
    }
    if (ok) {
      await markSent(entry.id);
      return true;
    }
    final database = await _db.db;
    try {
      await database.rawUpdate(
        'UPDATE outbox SET retry_count = retry_count + 1 WHERE id = ?',
        [entry.id],
      );
    } catch (_) {
      _log.w('Failed to bump retry counter for outbox entry ${entry.id}');
    }
    return false;
  }

  OutboxEntry _rowToEntry(Map<String, Object?> row) {
    return OutboxEntry(
      id:               row['id'] as String,
      conversationId:   row['conversation_id'] as String,
      destination:      row['destination'] as String,
      encryptedPayload: _crypto.decrypt(row['encrypted_payload'] as String) ?? '',
      createdAt: DateTime.fromMillisecondsSinceEpoch(row['created_at']! as int),
      retryCount: (row['retry_count'] as int?) ?? 0,
    );
  }
}
