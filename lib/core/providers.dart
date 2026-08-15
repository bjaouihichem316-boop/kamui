import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:shared_preferences/shared_preferences.dart';

import '../core/theme.dart';
import '../models/contact.dart';
import '../models/conversation.dart';
import '../models/message.dart';
import '../models/persona.dart';
import '../repositories/conversation_repository.dart';
import '../repositories/conversation_repository_impl.dart';
import '../repositories/message_repository.dart';
import '../repositories/message_repository_impl.dart';
import '../services/crypto_service.dart';
import '../services/database_service.dart';
import '../services/identity_key_service.dart';
import '../services/notification_service.dart';
import '../services/sam_service.dart';
import '../services/session_manager.dart';

// ═══════════════════════════════════════════════════════════════════════════
// INFRASTRUCTURE PROVIDERS
// ═══════════════════════════════════════════════════════════════════════════

/// Singleton [CryptoService]. Must be initialized in main() before use.
final cryptoServiceProvider = Provider<CryptoService>((ref) {
  return CryptoService();
});

/// Singleton [IdentityKeyService].
final identityKeyServiceProvider = Provider<IdentityKeyService>((ref) {
  return IdentityKeyService();
});

/// Singleton [SessionManager].
final sessionManagerProvider = Provider<SessionManager>((ref) {
  return SessionManager();
});

/// Singleton [DatabaseService].
final databaseServiceProvider = Provider<DatabaseService>((ref) {
  final db = DatabaseService();
  ref.onDispose(db.close);
  return db;
});

/// Concrete [ConversationRepository] backed by SQLite + AES-256-GCM.
final conversationRepositoryProvider = Provider<ConversationRepository>((ref) {
  return ConversationRepositoryImpl(
    ref.watch(databaseServiceProvider),
    ref.watch(cryptoServiceProvider),
  );
});

/// Concrete [MessageRepository] backed by SQLite + AES-256-GCM.
final messageRepositoryProvider = Provider<MessageRepository>((ref) {
  return MessageRepositoryImpl(
    ref.watch(databaseServiceProvider),
    ref.watch(cryptoServiceProvider),
  );
});

// ═══════════════════════════════════════════════════════════════════════════
// MULTI-IDENTITY PERSONA PROVIDER (Feature 5.4)
// ═══════════════════════════════════════════════════════════════════════════

class PersonaNotifier extends Notifier<Persona> {
  static const _mockPersonas = [
    Persona(
      id:             'p1',
      name:           'Ghost Persona',
      destinationKey: 'k8x9mQ3pAzRfT7vWsL2nJhDcYbXuE5oP1gKiNqVmBw4j6F8d0eCrZlOyH3m2p',
      avatarInitial:  'G',
      tag:            'Primary Stealth',
    ),
    Persona(
      id:             'p2',
      name:           'Work Channel',
      destinationKey: 'w9y0nR4qBzSgU8xXtM3oKiEdZcYvF6pQ2hLjOrWnCx5k7G9e1fDsAmPzI4n3q',
      avatarInitial:  'W',
      tag:            'Encrypted Work',
    ),
    Persona(
      id:             'p3',
      name:           'Anonymous Gateway',
      destinationKey: 'd4e2pNsJqVmT8bXoRfK7wCuZlYgH0A1iLjWxB5n9M6eFQrhDvPkOy3s7h8q',
      avatarInitial:  'A',
      tag:            'Zero-Trace Portal',
    ),
  ];

  @override
  Persona build() => _mockPersonas.first;

  List<Persona> get availablePersonas => _mockPersonas;

  Future<void> selectPersona(Persona persona) async {
    state = persona;
    final sam = ref.read(samServiceProvider);
    sam.localDestinationKey = persona.destinationKey;
    await sam.switchPersonaSession(persona.id);
  }
}

final personaNotifierProvider = NotifierProvider<PersonaNotifier, Persona>(
  PersonaNotifier.new,
);

// ═══════════════════════════════════════════════════════════════════════════
// THEME PROVIDER
// ═══════════════════════════════════════════════════════════════════════════

class NeonThemeNotifier extends Notifier<NeonTheme> {
  static const _prefKey = 'kamui_neon_theme_index';

  @override
  NeonTheme build() {
    _loadFromPrefs();
    return NeonTheme.cyberOrange;
  }

  Future<void> _loadFromPrefs() async {
    final prefs = await SharedPreferences.getInstance();
    final idx   = prefs.getInt(_prefKey) ?? 0;
    state = NeonTheme.values[idx % NeonTheme.values.length];
  }

  Future<void> selectTheme(NeonTheme theme) async {
    state = theme;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setInt(_prefKey, theme.index);
  }

  Future<void> setTheme(NeonTheme theme) => selectTheme(theme);
}

final neonThemeNotifierProvider =
    NotifierProvider<NeonThemeNotifier, NeonTheme>(
  NeonThemeNotifier.new,
);

// ═══════════════════════════════════════════════════════════════════════════
// SAM SERVICE PROVIDERS
// ═══════════════════════════════════════════════════════════════════════════

/// Singleton [SamService] provider.
final samServiceProvider = Provider<SamService>((ref) {
  final service = SamService();
  ref.onDispose(service.dispose);
  return service;
});

/// Stream of SAM status updates.
final samStatusProvider = StreamProvider<Map<String, dynamic>>((ref) {
  return ref.watch(samServiceProvider).statusStream;
});

/// Stream of SAM log entries.
final samLogProvider = StreamProvider<Map<String, dynamic>>((ref) {
  return ref.watch(samServiceProvider).logStream;
});

/// Stream of incoming peer encrypted messages over SAM.
final samIncomingStreamProvider = StreamProvider<Map<String, String>>((ref) {
  return ref.watch(samServiceProvider).incomingMessageStream;
});

/// Background listener for incoming peer messages with Native Notification.
final incomingMessageListenerProvider = Provider<void>((ref) {
  // Messages are stored encrypted at rest — decryption happens at display time.
  // CryptoService is intentionally not called here to avoid plaintext in memory.

  ref.listen<AsyncValue<Map<String, String>>>(
    samIncomingStreamProvider,
    (previous, next) async {
      final data = next.valueOrNull;
      if (data == null) return;

      final senderDest       = data['from'] ?? '';
      final encryptedPayload = data['payload'] ?? '';
      // decryptedText intentionally not computed here — notifications are masked,
      // and messages are stored encrypted at rest (decrypted on display).

      final conversations = ref.read(conversationsProvider).valueOrNull ?? [];
      Conversation? targetConv;

      for (final conv in conversations) {
        if (conv.contact.destination == senderDest) {
          targetConv = conv;
          break;
        }
      }

      if (targetConv == null) {
        final contactId   = 'c_${DateTime.now().millisecondsSinceEpoch}';
        final convId      = 'conv_$contactId';
        final initialName = senderDest.length > 8 ? senderDest.substring(0, 6) : senderDest;

        final newContact = Contact(
          id:            contactId,
          name:          'Peer_$initialName',
          destination:   senderDest,
          avatarInitial: 'P',
          status:        ContactStatus.active,
        );

        targetConv = Conversation(
          id:          convId,
          contact:     newContact,
          unreadCount: 1,
        );

        await ref.read(conversationsProvider.notifier).addAndPersist(targetConv);
      }

      // Route payload through v4 Double Ratchet decryption (or legacy v2 fallback)
      String? decryptedPlaintext;
      if (encryptedPayload.startsWith('kamui_v4:')) {
        try {
          decryptedPlaintext = await ref.read(sessionManagerProvider).decryptV4(
            targetConv.id,
            encryptedPayload,
            peerPreKeyBundleJson: targetConv.contact.preKeyBundleJson,
          );
        } catch (_) {
          // If session is not yet synchronized, retain payload for out-of-order recovery
        }
      } else if (encryptedPayload.startsWith('kamui_v2:')) {
        try {
          final dec = await ref.read(sessionManagerProvider).decryptMessage(
            targetConv.id,
            encryptedPayload,
            peerIdentityPublicKeyB64: targetConv.contact.identityPublicKey,
            peerPreKeyBundleJson: targetConv.contact.preKeyBundleJson,
          );
          if (dec != null) {
            decryptedPlaintext = dec;
          }
        } catch (_) {}
      }

      // SECURITY INVARIANT: Message.text MUST ALWAYS store the wire encrypted payload.
      // decryptedText is transient and kept in memory only for UI display.
      final incomingMsg = Message(
        id:             'msg_in_${DateTime.now().millisecondsSinceEpoch}',
        conversationId: targetConv.id,
        text:           encryptedPayload,  // Encrypted wire payload persisted to SQLite
        decryptedText:  decryptedPlaintext, // In-memory only
        timestamp:      DateTime.now(),
        isSent:         false,
        isEncrypted:    true,
      );

      await ref
          .read(messagesProvider(targetConv.id).notifier)
          .addAndPersist(incomingMsg);

      await NotificationService().showMessageNotification(
        title: 'Encrypted Message Received',
        body:  'New Secure Payload',
      );
    },
  );
});

// ═══════════════════════════════════════════════════════════════════════════
// CONVERSATIONS PROVIDER — persisted to SQLite
// ═══════════════════════════════════════════════════════════════════════════

class ConversationsNotifier extends AsyncNotifier<List<Conversation>> {
  @override
  Future<List<Conversation>> build() async {
    try {
      final repo  = ref.watch(conversationRepositoryProvider);
      final saved = await repo.getAll();
      if (saved.isNotEmpty) return saved;
    } catch (_) {}
    return _buildMockConversations();
  }

  /// Adds and persists a new conversation.
  Future<void> addAndPersist(Conversation conv) async {
    final repo = ref.read(conversationRepositoryProvider);
    await repo.save(conv);
    state = AsyncData([conv, ...state.valueOrNull ?? []]);
  }

  /// Removes a conversation from state and DB.
  Future<void> removeAndDelete(String id) async {
    final repo = ref.read(conversationRepositoryProvider);
    await repo.delete(id);
    state = AsyncData(
      (state.valueOrNull ?? []).where((c) => c.id != id).toList(),
    );
  }

  /// Updates a conversation's last message after sending.
  void updateLastMessage(String convId, Message message) {
    final list = state.valueOrNull ?? [];
    final updated = list.map((c) {
      if (c.id != convId) return c;
      return c.copyWith(lastMessage: message);
    }).toList();
    state = AsyncData(updated);
  }

  // ── Mock seed data ────────────────────────────────────────────────────────
  static List<Conversation> _buildMockConversations() {
    final now = DateTime.now();
    return [
      Conversation(
        id: 'conv_1',
        contact: const Contact(
          id: 'c1',
          name: 'Malek',
          destination:
              'k8x9mQ3pAzRfT7vWsL2nJhDcYbXuE5oP1gKiNqVmBw4j6F8d0eCrZlOyH...3m2p',
          avatarInitial: 'M',
          status: ContactStatus.active,
        ),
        lastMessage: Message(
          id: 'm1',
          conversationId: 'conv_1',
          text: 'Tunnel confirmed. Ready on your end?',
          timestamp: now.subtract(const Duration(minutes: 2)),
          isSent: false,
        ),
        unreadCount: 1,
      ),
      Conversation(
        id: 'conv_2',
        contact: const Contact(
          id: 'c2',
          name: 'Obito_Node',
          destination:
              'a7f3kRxMpLsW9nZqTvYcBdUeHoJi2gN4FmXwV6K8jD0P1rAyCbE5lQ...9c1k',
          avatarInitial: 'O',
          status: ContactStatus.building,
        ),
        lastMessage: Message(
          id: 'm2',
          conversationId: 'conv_2',
          text: 'Sending file via garlic routing...',
          timestamp: now.subtract(const Duration(minutes: 15)),
          isSent: false,
        ),
      ),
      Conversation(
        id: 'conv_3',
        contact: const Contact(
          id: 'c3',
          name: 'Kuro',
          destination:
              'd4e2pNsJqVmT8bXoRfK7wCuZlYgH0A1iLjWxB5n9M6eFQrhDvPkOy3s...7h8q',
          avatarInitial: 'K',
          status: ContactStatus.active,
        ),
        lastMessage: Message(
          id: 'm3',
          conversationId: 'conv_3',
          text: 'Session key rotated successfully.',
          timestamp: now.subtract(const Duration(hours: 1)),
          isSent: true,
        ),
      ),
      Conversation(
        id: 'conv_4',
        contact: const Contact(
          id: 'c4',
          name: 'Zero_Cool',
          destination:
              'f9b1nYcLkRzPqAoVwXs3J7Tg2HeKmDu6iF4Bj8N0WvMlOe5CrQh...2x5p',
          avatarInitial: 'Z',
          status: ContactStatus.offline,
        ),
        lastMessage: Message(
          id: 'm4',
          conversationId: 'conv_4',
          text: 'Payload encrypted. Sending through 3 hops.',
          timestamp: now.subtract(const Duration(hours: 3)),
          isSent: false,
        ),
      ),
      Conversation(
        id: 'conv_5',
        contact: const Contact(
          id: 'c5',
          name: 'Rin_Relay',
          destination:
              'c6d7wAmTsXpLvRqBkNjY9FoH3iGe2nZu8KdCb4J0MlWh5OyV...4n9m',
          avatarInitial: 'R',
          status: ContactStatus.active,
        ),
        lastMessage: Message(
          id: 'm5',
          conversationId: 'conv_5',
          text: 'Relay bridge stable. NAT traversal OK.',
          timestamp: now.subtract(const Duration(days: 1)),
          isSent: false,
        ),
      ),
    ];
  }
}

final conversationsProvider =
    AsyncNotifierProvider<ConversationsNotifier, List<Conversation>>(
  ConversationsNotifier.new,
);

// ═══════════════════════════════════════════════════════════════════════════
// MESSAGES PROVIDER — persisted to SQLite, encrypted at rest
// ═══════════════════════════════════════════════════════════════════════════

class MessagesNotifier extends FamilyAsyncNotifier<List<Message>, String> {
  @override
  Future<List<Message>> build(String conversationId) async {
    try {
      final repo  = ref.watch(messageRepositoryProvider);
      final saved = await repo.getByConversation(conversationId);
      if (saved.isNotEmpty) return saved;
    } catch (_) {}
    return _mockMessages[conversationId] ?? [];
  }

  /// Encrypts [text] via [CryptoService], saves to DB, updates UI state.
  Future<void> addAndPersist(Message message) async {
    final repo = ref.read(messageRepositoryProvider);
    await repo.save(message);

    final current = state.valueOrNull ?? [];
    state = AsyncData([...current, message]);

    ref
        .read(conversationsProvider.notifier)
        .updateLastMessage(message.conversationId, message);
  }

  /// Erases all messages from DB and clears state.
  Future<void> voidAll() async {
    final repo = ref.read(messageRepositoryProvider);
    await repo.deleteAll(arg);
    state = const AsyncData([]);
  }

  // ── Mock seed ─────────────────────────────────────────────────────────────
  static final Map<String, List<Message>> _mockMessages = {
    'conv_1': [
      Message(id: 'cm1', conversationId: 'conv_1', text: 'Tunnel established. Handshake complete.', timestamp: _t(9, 42), isSent: false),
      Message(id: 'cm2', conversationId: 'conv_1', text: 'Session key: AETHER-7X9K-3M2P rotated.', timestamp: _t(9, 43), isSent: true),
      Message(id: 'cm3', conversationId: 'conv_1', text: 'Good. Inbound tunnel stable on my end.', timestamp: _t(9, 45), isSent: false),
      Message(id: 'cm4', conversationId: 'conv_1', text: 'Sending file via garlic routing through 3 hops...', timestamp: _t(9, 47), isSent: true),
      Message(id: 'cm5', conversationId: 'conv_1', text: 'Transfer confirmed. All layers encrypted.', timestamp: _t(9, 52), isSent: true),
      Message(id: 'cm6', conversationId: 'conv_1', text: 'Payload received. Decrypting now.', timestamp: _t(9, 54), isSent: false),
      Message(id: 'cm7', conversationId: 'conv_1', text: '🔐 File verified. Zero-trust check passed.', timestamp: _t(9, 55), isSent: false),
      Message(id: 'cm8', conversationId: 'conv_1', text: 'Tunnel confirmed. Ready on your end?', timestamp: _t(9, 58), isSent: false),
    ],
    'conv_2': [
      Message(id: 'cm9',  conversationId: 'conv_2', text: 'Node bridging established. 4 relay hops.', timestamp: _t(10, 00), isSent: false),
      Message(id: 'cm10', conversationId: 'conv_2', text: 'Acknowledged. Sending encrypted payload now.', timestamp: _t(10, 01), isSent: true),
      Message(id: 'cm11', conversationId: 'conv_2', text: 'Sending file via garlic routing...', timestamp: _t(10, 15), isSent: false),
    ],
  };

  static DateTime _t(int hour, int minute) {
    final now = DateTime.now();
    return DateTime(now.year, now.month, now.day, hour, minute);
  }
}

final messagesProvider =
    AsyncNotifierProvider.family<MessagesNotifier, List<Message>, String>(
  MessagesNotifier.new,
);
