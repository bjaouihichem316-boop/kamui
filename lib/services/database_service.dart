import 'dart:async';
import 'package:flutter_secure_storage/flutter_secure_storage.dart';
import 'package:path/path.dart';
import 'package:path_provider/path_provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:sqflite/sqflite.dart';

import '../core/constants.dart';
import 'identity_key_service.dart';
import 'notification_service.dart';
import 'session_manager.dart';

/// Manages the SQLite database lifecycle for Kamui.
///
/// Features:
///   • Contacts, Conversations, and Messages tables
///   • Automatic deletion of self-destructed / TTL expired messages
///   • Complete nuke / purge capability for Panic / Duress Mode
class DatabaseService {
  // ─── Singleton ───────────────────────────────────────────────────────────
  static final DatabaseService _instance = DatabaseService._internal();
  factory DatabaseService() => _instance;
  DatabaseService._internal();

  static const _dbName    = 'kamui.db';
  static const _dbVersion = 3;

  Database? _db;

  /// Returns the open database, initializing it on first access.
  Future<Database> get db async {
    _db ??= await _init();
    return _db!;
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // SCHEMA
  // ═══════════════════════════════════════════════════════════════════════════

  Future<Database> _init() async {
    final dbPath = join(await getDatabasesPath(), _dbName);
    return openDatabase(
      dbPath,
      version:   _dbVersion,
      onCreate:  _onCreate,
      onUpgrade: _onUpgrade,
    );
  }

  Future<void> _onCreate(Database db, int version) async {
    await db.execute('''
      CREATE TABLE contacts (
        id                   TEXT PRIMARY KEY,
        name                 TEXT NOT NULL,
        destination          TEXT NOT NULL UNIQUE,
        avatar_initial       TEXT NOT NULL DEFAULT '?',
        status               TEXT NOT NULL DEFAULT 'offline',
        last_seen            INTEGER,
        identity_public_key  TEXT,
        pre_key_bundle_json  TEXT,
        created_at           INTEGER NOT NULL
      )
    ''');

    await db.execute('''
      CREATE TABLE conversations (
        id              TEXT PRIMARY KEY,
        contact_id      TEXT NOT NULL,
        unread_count    INTEGER NOT NULL DEFAULT 0,
        created_at      INTEGER NOT NULL,
        updated_at      INTEGER NOT NULL,
        FOREIGN KEY (contact_id) REFERENCES contacts (id) ON DELETE CASCADE
      )
    ''');

    await db.execute('''
      CREATE TABLE messages (
        id                TEXT PRIMARY KEY,
        conversation_id   TEXT NOT NULL,
        encrypted_text    TEXT NOT NULL,
        timestamp         INTEGER NOT NULL,
        is_sent           INTEGER NOT NULL DEFAULT 1,
        is_encrypted      INTEGER NOT NULL DEFAULT 1,
        status            TEXT NOT NULL DEFAULT 'sent',
        ttl_seconds       INTEGER,
        expires_at        INTEGER,
        FOREIGN KEY (conversation_id) REFERENCES conversations (id) ON DELETE CASCADE
      )
    ''');

    await db.execute('CREATE INDEX idx_messages_conv ON messages (conversation_id, timestamp)');
    await db.execute('CREATE INDEX idx_messages_expires ON messages (expires_at)');
    await db.execute('CREATE INDEX idx_convs_updated ON conversations (updated_at DESC)');

    await _createV3Tables(db);
  }

  /// Tables introduced in schema v3: encrypted Double Ratchet session store
  /// and the failed-send outbox. Shared by [_onCreate] and [_onUpgrade].
  Future<void> _createV3Tables(Database db) async {
    await db.execute('''
      CREATE TABLE IF NOT EXISTS sessions (
        conversation_id  TEXT PRIMARY KEY,
        encrypted_state  TEXT NOT NULL,
        updated_at       INTEGER NOT NULL
      )
    ''');

    await db.execute('''
      CREATE TABLE outbox (
        id                TEXT PRIMARY KEY,
        conversation_id   TEXT NOT NULL,
        destination       TEXT NOT NULL,
        encrypted_payload TEXT NOT NULL,
        created_at        INTEGER NOT NULL,
        retry_count       INTEGER NOT NULL DEFAULT 0
      )
    ''');
    await db.execute('CREATE INDEX IF NOT EXISTS idx_outbox_created ON outbox (created_at)');
  }

  Future<void> _onUpgrade(Database db, int oldVersion, int newVersion) async {
    if (oldVersion < 2) {
      await db.execute('ALTER TABLE messages ADD COLUMN ttl_seconds INTEGER');
      await db.execute('ALTER TABLE messages ADD COLUMN expires_at INTEGER');
      await db.execute('CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages (expires_at)');
    }
    if (oldVersion < 3) {
      // Persisted peer identity keys + PreKeyBundles (v4 sessions survive restart).
      await db.execute('ALTER TABLE contacts ADD COLUMN identity_public_key TEXT');
      await db.execute('ALTER TABLE contacts ADD COLUMN pre_key_bundle_json TEXT');
      await _createV3Tables(db);
    }
  }

  /// Purges messages whose TTL expiration timestamp has passed.
  Future<int> deleteExpiredMessages() async {
    final database = await db;
    final nowMs = DateTime.now().millisecondsSinceEpoch;
    return await database.delete(
      'messages',
      where:     'expires_at IS NOT NULL AND expires_at <= ?',
      whereArgs: [nowMs],
    );
  }

  /// Complete Panic / Duress Nuke: purges SQLite DB, SecureStorage, OS notifications, cache files, and in-memory key sessions.
  Future<void> nuke() async {
    // 1. Close & delete SQLite database
    final path = join(await getDatabasesPath(), _dbName);
    await close();
    await deleteDatabase(path);

    // 2. Delete all secure keys from FlutterSecureStorage
    try {
      const storage = FlutterSecureStorage(
        aOptions: AndroidOptions(encryptedSharedPreferences: true),
        iOptions: IOSOptions(accessibility: KeychainAccessibility.first_unlock),
      );
      await storage.deleteAll();
    } catch (_) {}

    // 3. Cancel all active OS notifications
    await NotificationService().cancelAllNotifications();

    // 4. Reset in-memory cryptographic sessions & identity keys.
    //    reset() also deletes persisted ratchet state; the whole DB file is
    //    already gone (step 1), so `sessions`/`outbox` die with it either way.
    await SessionManager().reset();
    await IdentityKeyService().clearKeys();

    // 5. Clear application cache directory
    try {
      final tempDir = await getTemporaryDirectory();
      if (await tempDir.exists()) {
        await tempDir.delete(recursive: true);
      }
    } catch (_) {}

    // 6. Clear persisted UI preferences — no theme residue may survive a wipe.
    try {
      final prefs = await SharedPreferences.getInstance();
      await prefs.remove(KamuiConstants.themePrefsKey);
    } catch (_) {}
  }

  /// Closes the database connection.
  Future<void> close() async {
    await _db?.close();
    _db = null;
  }
}
