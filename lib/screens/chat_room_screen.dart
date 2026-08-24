import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:google_fonts/google_fonts.dart';
import '../core/theme.dart';
import '../core/constants.dart';
import '../core/providers.dart';
import '../models/conversation.dart';
import '../models/message.dart';
import '../models/contact.dart';
import '../services/session_manager.dart';
import '../widgets/chat_bubble.dart';
import '../widgets/status_dot.dart';

class ChatRoomScreen extends ConsumerStatefulWidget {
  final Conversation conversation;

  const ChatRoomScreen({super.key, required this.conversation});

  @override
  ConsumerState<ChatRoomScreen> createState() => _ChatRoomScreenState();
}

class _ChatRoomScreenState extends ConsumerState<ChatRoomScreen>
    with SingleTickerProviderStateMixin {
  final TextEditingController _msgController    = TextEditingController();
  final ScrollController      _scrollController = ScrollController();

  // ── BUG-004 FIX: Use addStatusListener instead of addListener ────────────
  late AnimationController _dissolveController;
  late Animation<double>   _dissolveAnim;
  bool _isDissolving = false;

  @override
  void initState() {
    super.initState();

    _dissolveController = AnimationController(
      vsync: this,
      duration: KamuiConstants.dissolveAnimDuration,
    );

    _dissolveAnim = Tween<double>(begin: 1.0, end: 0.0).animate(
      CurvedAnimation(parent: _dissolveController, curve: Curves.easeOutCubic),
    );

    // BUG-004 FIX: only react to animation STATUS changes — no setState every frame.
    _dissolveController.addStatusListener((status) {
      if (status == AnimationStatus.completed && mounted) {
        // voidAll() also deletes from SQLite (Phase 2 persistence).
        ref.read(messagesProvider(widget.conversation.id).notifier).voidAll();
        setState(() => _isDissolving = false);
        _dissolveController.reset();
      }
    });
  }

  @override
  void dispose() {
    _msgController.dispose();
    _scrollController.dispose();
    _dissolveController.dispose();
    super.dispose();
  }

  // ── Actions ──────────────────────────────────────────────────────────────

  int _ttlSeconds = 0;

  Future<void> _sendMessage() async {
    final text = _msgController.text.trim();
    if (text.isEmpty) return;

    // ── Fail-Closed Encryption (Security Requirement) ─────────────────────
    // encryptV4() / encryptMessage() throws SessionUnavailableException if a
    // session cannot be established. No silent fallback to weaker encryption is permitted.
    final String encryptedPayload;
    try {
      final sessionManager = ref.read(sessionManagerProvider);
      final bundle = widget.conversation.contact.preKeyBundleJson;
      if (bundle != null && bundle.isNotEmpty) {
        encryptedPayload = await sessionManager.encryptV4(
          widget.conversation.id,
          text,
          peerPreKeyBundleJson: bundle,
        );
      } else {
        encryptedPayload = await sessionManager.encryptMessage(
          widget.conversation.id,
          text,
          peerIdentityPublicKeyB64: widget.conversation.contact.identityPublicKey,
          peerPreKeyBundleJson: bundle,
        );
      }
    } on SessionUnavailableException catch (e) {
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            content: Text(
              'Send aborted — E2EE session unavailable.\n${e.reason}',
              style: GoogleFonts.jetBrainsMono(fontSize: 11),
            ),
            backgroundColor: vortexOrange,
            duration: const Duration(seconds: 5),
          ),
        );
      }
      return; // Hard abort — never send without encryption
    }

    final now       = DateTime.now();
    final expiresAt = _ttlSeconds > 0 ? now.add(Duration(seconds: _ttlSeconds)) : null;

    final msg = Message(
      id:             '${now.millisecondsSinceEpoch}',
      conversationId: widget.conversation.id,
      text:           text,
      timestamp:      now,
      isSent:         true,
      isEncrypted:    true,
      status:         MessageStatus.sending,
      ttlSeconds:     _ttlSeconds > 0 ? _ttlSeconds : null,
      expiresAt:      expiresAt,
    );

    _msgController.clear();
    _scrollToBottom();

    // Persist to local SQLite DB and update UI state
    await ref
        .read(messagesProvider(widget.conversation.id).notifier)
        .addAndPersist(msg);

    // Transmit encrypted payload via live SAM Service. On failure the wire
    // payload is queued in the outbox and the message is marked failed
    // (long-press to retry; auto-retried once on SAM reconnect).
    final sam = ref.read(samServiceProvider);
    final destination = widget.conversation.contact.destination;
    final delivered = await sam.sendRawMessage(destination, encryptedPayload);

    if (delivered) {
      await ref
          .read(messagesProvider(widget.conversation.id).notifier)
          .updateStatus(msg.id, MessageStatus.sent);
    } else {
      await ref.read(outboxServiceProvider).enqueue(
            id:              msg.id,
            conversationId:  widget.conversation.id,
            destination:     destination,
            encryptedPayload: encryptedPayload,
          );
      await ref
          .read(messagesProvider(widget.conversation.id).notifier)
          .updateStatus(msg.id, MessageStatus.failed);
    }
  }

  /// Long-press retry for a failed send: re-transmits the stored wire payload
  /// from the outbox exactly once.
  Future<void> _retryFailed(Message message) async {
    final sent = await ref
        .read(outboxServiceProvider)
        .retryOne(
          message.id,
          (entry) => ref
              .read(samServiceProvider)
              .sendRawMessage(entry.destination, entry.encryptedPayload),
        );
    if (!mounted) return;
    final messenger = ScaffoldMessenger.of(context);
    if (sent) {
      await ref
          .read(messagesProvider(widget.conversation.id).notifier)
          .updateStatus(message.id, MessageStatus.sent);
      messenger.showSnackBar(
        SnackBar(
          content: Text('Retransmitted via garlic tunnel.',
              style: GoogleFonts.jetBrainsMono(fontSize: 11)),
          backgroundColor: cyberCyan.withAlpha(200),
        ),
      );
    } else {
      messenger.showSnackBar(
        SnackBar(
          content: Text('Retry failed — SAM tunnel still offline.',
              style: GoogleFonts.jetBrainsMono(fontSize: 11)),
          backgroundColor: vortexOrange,
        ),
      );
    }
  }

  void _scrollToBottom() {
    Future<void>.delayed(const Duration(milliseconds: 80), () {
      if (_scrollController.hasClients) {
        _scrollController.animateTo(
          _scrollController.position.maxScrollExtent,
          duration: const Duration(milliseconds: 300),
          curve:    Curves.easeOut,
        );
      }
    });
  }

  void _confirmVoidAll() {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        title: Row(
          children: [
            const Icon(Icons.local_fire_department, color: vortexOrange, size: 20),
            const SizedBox(width: 10),
            Text('VOID ALL', style: GoogleFonts.rajdhani(
              color: textBright, fontSize: 16, fontWeight: FontWeight.w700, letterSpacing: 2,
            )),
          ],
        ),
        content: Text(
          'This will permanently erase all messages with ${widget.conversation.contact.name}.\nThis action cannot be undone.',
          style: GoogleFonts.jetBrainsMono(color: textMid, fontSize: 12, height: 1.6),
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: Text('CANCEL',
              style: GoogleFonts.rajdhani(color: textMid, fontSize: 12, letterSpacing: 1)),
          ),
          TextButton(
            onPressed: () { Navigator.pop(ctx); _voidAll(); },
            child: Text('VOID',
              style: GoogleFonts.rajdhani(
                color: vortexOrange, fontSize: 12, letterSpacing: 1, fontWeight: FontWeight.w700)),
          ),
        ],
      ),
    );
  }

  Future<void> _voidAll() async {
    setState(() => _isDissolving = true);
    _dissolveController.forward();
    // Delete from SQLite via repository.
    await ref
        .read(messagesProvider(widget.conversation.id).notifier)
        .voidAll();
  }

  // ── Build ─────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    final asyncMsgs = ref.watch(messagesProvider(widget.conversation.id));
    final contact   = widget.conversation.contact;

    return Scaffold(
      backgroundColor: voidBlack,
      appBar: _buildAppBar(contact),
      body: Column(
        children: [
          Expanded(
            child: asyncMsgs.when(
              loading: () => const Center(
                child: CircularProgressIndicator(color: vortexOrange, strokeWidth: 2),
              ),
              error: (e, _) => Center(
                child: Text('Error: $e',
                    style: GoogleFonts.jetBrainsMono(color: Colors.redAccent, fontSize: 12)),
              ),
              data: (messages) => messages.isEmpty
                  ? _buildEmptyMessages()
                  : AnimatedBuilder(
                      animation: _dissolveAnim,
                      builder: (_, child) => Opacity(
                        opacity: _isDissolving ? _dissolveAnim.value : 1.0,
                        child:   child,
                      ),
                      child: ListView.builder(
                        controller:  _scrollController,
                        padding:     const EdgeInsets.symmetric(vertical: 12),
                        itemCount:   messages.length,
                        itemBuilder: (_, i) {
                          final m = messages[i];
                          return ChatBubble(
                            message:           m.displayText,
                            time:              m.formattedTime,
                            isSent:            m.isSent,
                            isEncrypted:       m.isEncrypted,
                            ttlSeconds:        m.ttlSeconds,
                            expiresAt:         m.expiresAt,
                            remainingFraction: m.remainingFraction,
                            isFailed:          m.isSent && m.status == MessageStatus.failed,
                            onRetry: (m.isSent && m.status == MessageStatus.failed)
                                ? () => _retryFailed(m)
                                : null,
                          );
                        },
                      ),
                    ),
            ),
          ),
          _buildInputBar(),
        ],
      ),
    );
  }

  PreferredSizeWidget _buildAppBar(Contact contact) {
    final dotColor = statusColor(contact.status.name);

    return AppBar(
      backgroundColor: voidBlack,
      elevation: 0,
      leading: IconButton(
        icon: const Icon(Icons.arrow_back_ios_new, color: textBright, size: 18),
        onPressed: () => Navigator.pop(context),
      ),
      titleSpacing: 0,
      title: Row(
        children: [
          // Avatar
          Container(
            width:  38,
            height: 38,
            decoration: BoxDecoration(
              shape:  BoxShape.circle,
              color:  panelDark,
              border: Border.all(color: vortexOrange.withAlpha(100), width: 1.5),
              boxShadow: [BoxShadow(color: vortexOrange.withAlpha(25), blurRadius: 8)],
            ),
            child: Center(
              child: Text(
                contact.avatarInitial,
                style: GoogleFonts.orbitron(
                  color: vortexOrange, fontSize: 14, fontWeight: FontWeight.w700,
                ),
              ),
            ),
          ),

          const SizedBox(width: 10),

          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Row(
                  children: [
                    Text(
                      contact.name,
                      style: GoogleFonts.rajdhani(
                        color:      textBright,
                        fontSize:   15,
                        fontWeight: FontWeight.w600,
                        letterSpacing: 0.5,
                      ),
                    ),
                    const SizedBox(width: 8),
                    StatusDot(color: dotColor, size: 7,
                        animate: contact.status.name == 'active'),
                  ],
                ),
                Text(
                  contact.truncatedDestination,
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 9,
                    color:    cyberCyan.withAlpha(120),
                  ),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                ),
              ],
            ),
          ),
        ],
      ),
      actions: [
        PopupMenuButton<int>(
          icon: Icon(
            Icons.timer_outlined,
            color: _ttlSeconds > 0 ? warningAmber : textMid,
          ),
          tooltip: 'Self-Destruct Timer (TTL)',
          color:   panelDark,
          onSelected: (val) => setState(() => _ttlSeconds = val),
          itemBuilder: (ctx) => [
            _ttlMenuItem(0,     'Off (No Expiry)'),
            _ttlMenuItem(30,    '30 Seconds'),
            _ttlMenuItem(300,   '5 Minutes'),
            _ttlMenuItem(3600,  '1 Hour'),
            _ttlMenuItem(86400, '24 Hours'),
          ],
        ),
        IconButton(
          icon: const Icon(Icons.local_fire_department, color: vortexOrange),
          onPressed: _confirmVoidAll,
          tooltip: 'VOID ALL',
        ),
        const SizedBox(width: 4),
      ],
      bottom: PreferredSize(
        preferredSize: const Size.fromHeight(1),
        child: Container(
          height: 1,
          decoration: BoxDecoration(
            gradient: LinearGradient(colors: [
              Colors.transparent,
              cyberCyan.withAlpha(30),
              Colors.transparent,
            ]),
          ),
        ),
      ),
    );
  }

  PopupMenuItem<int> _ttlMenuItem(int value, String label) {
    final isSelected = _ttlSeconds == value;
    return PopupMenuItem<int>(
      value: value,
      child: Row(
        children: [
          Icon(
            isSelected ? Icons.check_circle : Icons.circle_outlined,
            size: 14,
            color: isSelected ? warningAmber : textDim,
          ),
          const SizedBox(width: 10),
          Text(
            label,
            style: GoogleFonts.jetBrainsMono(
              color: isSelected ? textBright : textMid,
              fontSize: 11,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildEmptyMessages() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.bubble_chart_outlined, size: 48, color: textDim),
          const SizedBox(height: 12),
          Text('Messages voided.',
              style: GoogleFonts.jetBrainsMono(color: textMid, fontSize: 14)),
          const SizedBox(height: 8),
          Text('Send a message to begin again.',
              style: GoogleFonts.jetBrainsMono(color: textDim, fontSize: 11)),
        ],
      ),
    );
  }

  Widget _buildInputBar() {
    return ClipRect(
      child: BackdropFilter(
        filter: ImageFilter.blur(sigmaX: 12, sigmaY: 12),
        child: Container(
          padding: const EdgeInsets.fromLTRB(16, 10, 16, 18),
          decoration: BoxDecoration(
            color: voidBlack.withAlpha(200),
            border: Border(
              top: BorderSide(color: cyberCyan.withAlpha(22), width: 0.5),
            ),
          ),
          child: Row(
            children: [
              // Text field
              Expanded(
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 18),
                  decoration: BoxDecoration(
                    color:        surfaceDark,
                    borderRadius: BorderRadius.circular(26),
                    border:       Border.all(color: cyberCyan.withAlpha(35), width: 0.8),
                    boxShadow: [
                      BoxShadow(color: cyberCyan.withAlpha(10), blurRadius: 12),
                    ],
                  ),
                  child: TextField(
                    controller: _msgController,
                    style: const TextStyle(color: textBright, fontSize: 14),
                    decoration: InputDecoration(
                      hintText: 'Encrypted via Kamui…',
                      hintStyle: GoogleFonts.jetBrainsMono(
                        color: textDim, fontSize: 12,
                      ),
                      border:         InputBorder.none,
                      contentPadding: const EdgeInsets.symmetric(vertical: 14),
                    ),
                    textInputAction: TextInputAction.send,
                    onSubmitted:     (_) => _sendMessage(),
                    maxLines: null,
                    keyboardType: TextInputType.multiline,
                  ),
                ),
              ),

              const SizedBox(width: 10),

              // Send button
              GestureDetector(
                onTap: _sendMessage,
                child: Container(
                  width:  50,
                  height: 50,
                  decoration: BoxDecoration(
                    shape:  BoxShape.circle,
                    color:  vortexOrange,
                    boxShadow: [
                      BoxShadow(color: vortexOrange.withAlpha(110), blurRadius: 16, spreadRadius: 1),
                      BoxShadow(color: vortexOrange.withAlpha(40),  blurRadius: 30),
                    ],
                  ),
                  child: const Icon(Icons.arrow_upward_rounded, color: Colors.white, size: 22),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}
