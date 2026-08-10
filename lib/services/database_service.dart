import 'dart:async';
import 'package:path/path.dart';
import 'package:sqflite/sqflite.dart';

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
  static const _dbVersion = 2;

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
        id              TEXT PRIMARY KEY,
        name            TEXT NOT NULL,
        destination     TEXT NOT NULL UNIQUE,
        avatar_initial  TEXT NOT NULL DEFAULT '?',
        status          TEXT NOT NULL DEFAULT 'offline',
        last_seen       INTEGER,
        created_at      INTEGER NOT NULL
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
  }

  Future<void> _onUpgrade(Database db, int oldVersion, int newVersion) async {
    if (oldVersion < 2) {
      await db.execute('ALTER TABLE messages ADD COLUMN ttl_seconds INTEGER');
      await db.execute('ALTER TABLE messages ADD COLUMN expires_at INTEGER');
      await db.execute('CREATE INDEX IF NOT EXISTS idx_messages_expires ON messages (expires_at)');
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

  /// Deletes and reinitializes the database (Panic / Duress wipe).
  Future<void> nuke() async {
    final path = join(await getDatabasesPath(), _dbName);
    await close();
    await deleteDatabase(path);
  }

  /// Closes the database connection.
  Future<void> close() async {
    await _db?.close();
    _db = null;
  }
}
