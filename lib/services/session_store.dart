import 'package:sqflite/sqflite.dart';

import 'crypto_service.dart';
import 'database_service.dart';

// ══════════════════════════════════════════════════════════════════════════════
// Session Store — encrypted-at-rest persistence for Double Ratchet sessions
// ══════════════════════════════════════════════════════════════════════════════

/// Persistence boundary for serialized Double Ratchet sessions.
///
/// Implementations store an ALREADY-ENCRYPTED blob (AES-256-GCM via
/// [CryptoService]) keyed by conversation id. Abstraction exists so tests can
/// inject an in-memory store without platform channels.
abstract class SessionStore {
  /// Loads the encrypted state blob for [conversationId], or `null` when absent
  /// or undecryptable. Corrupt blobs are discarded by the store itself —
  /// a corrupt blob must NEVER crash the app or poison the session layer.
  Future<String?> loadEncryptedState(String conversationId);

  /// Persists [encryptedState] for [conversationId] (upsert).
  Future<void> saveEncryptedState(String conversationId, String encryptedState);

  /// Deletes the persisted state for [conversationId].
  Future<void> delete(String conversationId);

  /// Deletes ALL persisted states (duress wipe / key rotation).
  Future<void> deleteAll();
}

/// SQLite-backed [SessionStore]. Blobs are AES-256-GCM encrypted with the
/// local [CryptoService] key before insert (`sessions` table, schema v3).
class SqliteSessionStore implements SessionStore {
  final DatabaseService _dbService;
  final CryptoService _crypto;

  SqliteSessionStore(this._dbService, this._crypto);

  @override
  Future<String?> loadEncryptedState(String conversationId) async {
    try {
      final database = await _dbService.db;
      final rows = await database.query(
        'sessions',
        columns: ['encrypted_state'],
        where: 'conversation_id = ?',
        whereArgs: [conversationId],
        limit: 1,
      );
      if (rows.isEmpty) return null;

      final stored = rows.first['encrypted_state'] as String;
      final decrypted = _crypto.decrypt(stored);
      if (decrypted == null) {
        // Corrupt / undecryptable blob → discard (session re-established via
        // fresh X3DH). Never crash, never fail-wrong.
        await delete(conversationId);
        return null;
      }
      return decrypted;
    } catch (_) {
      // Storage unavailable / schema missing → behave as "no saved session".
      return null;
    }
  }

  @override
  Future<void> saveEncryptedState(String conversationId, String encryptedState) async {
    final database = await _dbService.db;
    await database.insert(
      'sessions',
      {
        'conversation_id': conversationId,
        'encrypted_state': _crypto.encrypt(encryptedState),
        'updated_at': DateTime.now().millisecondsSinceEpoch,
      },
      conflictAlgorithm: ConflictAlgorithm.replace,
    );
  }

  @override
  Future<void> delete(String conversationId) async {
    try {
      final database = await _dbService.db;
      await database.delete(
        'sessions',
        where: 'conversation_id = ?',
        whereArgs: [conversationId],
      );
    } catch (_) {
      // Table may not exist pre-migration — nothing to delete.
    }
  }

  @override
  Future<void> deleteAll() async {
    try {
      final database = await _dbService.db;
      await database.delete('sessions');
    } catch (_) {
      // Table may not exist pre-migration — nothing to delete.
    }
  }
}

/// In-memory [SessionStore] for tests and multi-identity isolation.
class InMemorySessionStore implements SessionStore {
  final Map<String, String> _states = {};

  @override
  Future<String?> loadEncryptedState(String conversationId) async =>
      _states[conversationId];

  @override
  Future<void> saveEncryptedState(String conversationId, String encryptedState) async {
    _states[conversationId] = encryptedState;
  }

  @override
  Future<void> delete(String conversationId) async => _states.remove(conversationId);

  @override
  Future<void> deleteAll() async => _states.clear();
}
