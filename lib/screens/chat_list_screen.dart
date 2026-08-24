import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:google_fonts/google_fonts.dart';
import '../core/theme.dart';
import '../core/providers.dart';
import '../models/conversation.dart';
import '../models/contact.dart';
import '../widgets/hud_background.dart';
import '../widgets/network_stats_sheet.dart';
import '../widgets/status_dot.dart';
import 'add_friend_screen.dart';
import 'chat_room_screen.dart';
import 'node_settings_screen.dart';

class ChatListScreen extends ConsumerStatefulWidget {
  const ChatListScreen({super.key});

  @override
  ConsumerState<ChatListScreen> createState() => _ChatListScreenState();
}

class _ChatListScreenState extends ConsumerState<ChatListScreen> {

  void _showNetworkStats() {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      builder: (_) => const NetworkStatsSheet(),
    );
  }

  @override
  Widget build(BuildContext context) {
    ref.watch(incomingMessageListenerProvider);
    // Auto-retry queued (failed) sends once per SAM reconnect.
    ref.watch(outboxRetryListenerProvider);
    final asyncConvs = ref.watch(conversationsProvider);

    return Scaffold(
      backgroundColor: voidBlack,
      body: HudBackground(
        child: SafeArea(
          child: Column(
            children: [
              _buildAppBar(),
              Expanded(
                child: asyncConvs.when(
                  loading: () => const Center(
                    child: CircularProgressIndicator(color: vortexOrange, strokeWidth: 2),
                  ),
                  error: (e, _) => Center(
                    child: Text('Error: $e',
                        style: GoogleFonts.jetBrainsMono(color: Colors.redAccent, fontSize: 12)),
                  ),
                  data: (conversations) => conversations.isEmpty
                      ? _buildEmptyState()
                      : ListView.builder(
                          padding: const EdgeInsets.fromLTRB(16, 8, 16, 80),
                          itemCount: conversations.length,
                          itemBuilder: (_, i) =>
                              _ConversationCard(conversation: conversations[i]),
                        ),
                ),
              ),
            ],
          ),
        ),
      ),
      floatingActionButton: _buildFab(),
    );
  }

  Widget _buildAppBar() {
    // Count active conversations from async state
    final asyncConvs = ref.watch(conversationsProvider);
    final all    = asyncConvs.valueOrNull ?? [];
    final active = all.where((c) => c.contact.status == ContactStatus.active).length;

    return Container(
      padding: const EdgeInsets.fromLTRB(20, 12, 8, 12),
      decoration: BoxDecoration(
        color: voidBlack.withAlpha(200),
        border: Border(
          bottom: BorderSide(color: cyberCyan.withAlpha(18), width: 0.5),
        ),
      ),
      child: Row(
        children: [
          // Logo
          ShaderMask(
            shaderCallback: (b) => const LinearGradient(
              colors: [vortexOrange, cyberCyan],
            ).createShader(b),
            child: Text(
              'KAMUI',
              style: GoogleFonts.orbitron(
                fontSize:    22,
                fontWeight:  FontWeight.w900,
                letterSpacing: 6,
                color:       Colors.white,
              ),
            ),
          ),

          const SizedBox(width: 12),

          // Tunnel status pill
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
            decoration: BoxDecoration(
              color:        cyberCyan.withAlpha(15),
              borderRadius: BorderRadius.circular(20),
              border:       Border.all(color: cyberCyan.withAlpha(50), width: 0.8),
            ),
            child: Row(
              mainAxisSize: MainAxisSize.min,
              children: [
                StatusDot(color: cyberCyan, size: 6),
                const SizedBox(width: 6),
                Text(
                  '$active Tunnels Active',
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 9,
                    color:    cyberCyan,
                    letterSpacing: 0.5,
                  ),
                ),
              ],
            ),
          ),

          const Spacer(),

          // Network console button
          IconButton(
            icon: Icon(Icons.sensors, color: vortexOrange, size: 20),
            onPressed: _showNetworkStats,
            tooltip: 'Network Console',
          ),
          // Node settings button
          IconButton(
            icon: Icon(Icons.tune_rounded, color: cyberCyan, size: 20),
            onPressed: () {
              Navigator.push(
                context,
                PageRouteBuilder(
                  pageBuilder: (_, _, _) => const NodeSettingsScreen(),
                  transitionDuration: const Duration(milliseconds: 350),
                  transitionsBuilder: (_, anim, _, child) => SlideTransition(
                    position: Tween(
                      begin: const Offset(1, 0),
                      end:   Offset.zero,
                    ).animate(CurvedAnimation(parent: anim, curve: Curves.easeOutCubic)),
                    child: child,
                  ),
                ),
              );
            },
            tooltip: 'Node Settings',
          ),
        ],
      ),
    );
  }

  Widget _buildFab() {
    return Container(
      decoration: BoxDecoration(
        shape:     BoxShape.circle,
        boxShadow: [
          BoxShadow(color: vortexOrange.withAlpha(80), blurRadius: 20, spreadRadius: 2),
        ],
      ),
      child: FloatingActionButton(
        onPressed: () {
          Navigator.push(
            context,
            PageRouteBuilder(
              pageBuilder:        (_, _, _) => const AddFriendScreen(),
              transitionDuration: const Duration(milliseconds: 400),
              transitionsBuilder: (_, anim, _, child) => SlideTransition(
                position: Tween(
                  begin: const Offset(0, 1),
                  end:   Offset.zero,
                ).animate(CurvedAnimation(parent: anim, curve: Curves.easeOutCubic)),
                child: child,
              ),
            ),
          );
        },
        backgroundColor: vortexOrange,
        child: const Icon(Icons.add, size: 26),
      ),
    );
  }

  Widget _buildEmptyState() {
    return Center(
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(Icons.wifi_tethering_off, size: 56, color: textDim),
          const SizedBox(height: 16),
          Text('No portals open.',
              style: GoogleFonts.jetBrainsMono(color: textMid, fontSize: 14)),
          const SizedBox(height: 8),
          Text('Tap + to open a new portal.',
              style: GoogleFonts.jetBrainsMono(color: textDim, fontSize: 11)),
        ],
      ),
    );
  }
}

// ── Conversation Card ─────────────────────────────────────────────────────────

class _ConversationCard extends ConsumerWidget {
  final Conversation conversation;

  const _ConversationCard({required this.conversation});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final contact = conversation.contact;
    final dot     = statusColor(contact.status.name);
    final isActive = contact.status == ContactStatus.active;

    return Padding(
      padding: const EdgeInsets.only(bottom: 10),
      child: GestureDetector(
        onTap: () => Navigator.push(
          context,
          PageRouteBuilder(
            pageBuilder: (ctx, a, _) => ChatRoomScreen(conversation: conversation),
            transitionDuration: const Duration(milliseconds: 350),
            transitionsBuilder: (ctx, a, _, child) =>
                SlideTransition(
                  position: Tween(
                    begin: const Offset(1, 0), end: Offset.zero,
                  ).animate(CurvedAnimation(parent: a, curve: Curves.easeOutCubic)),
                  child: child,
                ),
          ),
        ),
        child: ClipRRect(
          borderRadius: BorderRadius.circular(14),
          child: BackdropFilter(
            filter: ImageFilter.blur(sigmaX: 8, sigmaY: 8),
            child: Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(
                color: panelDark.withAlpha(200),
                borderRadius: BorderRadius.circular(14),
                border: Border.all(
                  color: isActive
                      ? cyberCyan.withAlpha(35)
                      : Colors.white.withAlpha(10),
                  width: 0.8,
                ),
                boxShadow: isActive
                    ? [BoxShadow(color: cyberCyan.withAlpha(12), blurRadius: 16)]
                    : [],
              ),
              child: Row(
                children: [
                  // Avatar
                  _avatar(contact),
                  const SizedBox(width: 14),

                  // Content
                  Expanded(
                    child: Column(
                      crossAxisAlignment: CrossAxisAlignment.start,
                      children: [
                        Row(
                          children: [
                            Expanded(
                              child: Text(
                                contact.name,
                                style: GoogleFonts.rajdhani(
                                  color:      textBright,
                                  fontSize:   15,
                                  fontWeight: FontWeight.w600,
                                  letterSpacing: 0.5,
                                ),
                              ),
                            ),
                            Row(
                              mainAxisSize: MainAxisSize.min,
                              children: [
                                StatusDot(color: dot, size: 7,
                                    animate: isActive),
                                const SizedBox(width: 6),
                                Text(
                                  conversation.lastMessageTimeAgo,
                                  style: GoogleFonts.jetBrainsMono(
                                    color:    textDim,
                                    fontSize: 10,
                                  ),
                                ),
                              ],
                            ),
                          ],
                        ),
                        const SizedBox(height: 3),
                        Text(
                          contact.truncatedDestination,
                          style: GoogleFonts.jetBrainsMono(
                            color:    cyberCyan.withAlpha(110),
                            fontSize: 10,
                          ),
                        ),
                        const SizedBox(height: 4),
                        Text(
                          conversation.lastMessage?.text ?? '—',
                          style: TextStyle(color: textMid, fontSize: 13),
                          maxLines:  1,
                          overflow:  TextOverflow.ellipsis,
                        ),
                      ],
                    ),
                  ),

                  // Unread badge
                  if (conversation.unreadCount > 0)
                    Container(
                      margin: const EdgeInsets.only(left: 10),
                      width:  22,
                      height: 22,
                      decoration: BoxDecoration(
                        shape:     BoxShape.circle,
                        color:     vortexOrange,
                        boxShadow: [
                          BoxShadow(color: vortexOrange.withAlpha(80), blurRadius: 8),
                        ],
                      ),
                      child: Center(
                        child: Text(
                          '${conversation.unreadCount}',
                          style: const TextStyle(
                            color:    Colors.white,
                            fontSize: 10,
                            fontWeight: FontWeight.w700,
                          ),
                        ),
                      ),
                    ),
                ],
              ),
            ),
          ),
        ),
      ),
    );
  }

  Widget _avatar(Contact contact) {
    return Container(
      width:  50,
      height: 50,
      decoration: BoxDecoration(
        shape:  BoxShape.circle,
        color:  panelDark,
        border: Border.all(
          color: vortexOrange.withAlpha(100),
          width: 1.5,
        ),
        boxShadow: [
          BoxShadow(color: vortexOrange.withAlpha(30), blurRadius: 10),
        ],
      ),
      child: Center(
        child: Text(
          contact.avatarInitial,
          style: GoogleFonts.orbitron(
            color:      vortexOrange,
            fontSize:   18,
            fontWeight: FontWeight.w700,
          ),
        ),
      ),
    );
  }
}
