import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:google_fonts/google_fonts.dart';

import '../core/constants.dart';
import '../core/providers.dart';
import '../core/theme.dart';
import '../services/lock_service.dart';
import '../services/sam_service.dart';
import '../widgets/hud_background.dart';
import '../widgets/kamui_button.dart';
import '../widgets/qr_share_dialog.dart';
import '../widgets/status_dot.dart';
import 'lock_screen.dart';

class NodeSettingsScreen extends ConsumerStatefulWidget {
  const NodeSettingsScreen({super.key});

  @override
  ConsumerState<NodeSettingsScreen> createState() => _NodeSettingsScreenState();
}

class _NodeSettingsScreenState extends ConsumerState<NodeSettingsScreen> {
  bool _isReconnecting = false;
  int  _inboundHops     = 3;
  int  _outboundHops    = 3;

  Future<void> _reconnectSam() async {
    setState(() => _isReconnecting = true);
    final sam = ref.read(samServiceProvider);

    final ok = await sam.connectAndHandshake();
    if (ok) {
      await sam.createSession('KamuiSession');
    }

    if (mounted) {
      setState(() => _isReconnecting = false);
      ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(
          backgroundColor: panelDark,
          behavior:        SnackBarBehavior.floating,
          shape: RoundedRectangleBorder(
            borderRadius: BorderRadius.circular(10),
            side: BorderSide(
                color: (ok ? emeraldGlow : Colors.redAccent).withAlpha(80)),
          ),
          content: Row(
            children: [
              Icon(ok ? Icons.check_circle_outline : Icons.error_outline,
                  color: ok ? emeraldGlow : Colors.redAccent, size: 18),
              const SizedBox(width: 10),
              Text(
                ok ? 'Connected to SAM Bridge.' : 'SAM Bridge connection failed.',
                style: GoogleFonts.jetBrainsMono(
                    color: textBright, fontSize: 12),
              ),
            ],
          ),
        ),
      );
    }
  }

  void _copyKey(String key, String label) {
    Clipboard.setData(ClipboardData(text: key));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        backgroundColor: panelDark,
        behavior:        SnackBarBehavior.floating,
        duration:        const Duration(seconds: 2),
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(10),
          side: BorderSide(color: cyberCyan.withAlpha(80)),
        ),
        content: Row(
          children: [
            Icon(Icons.copy_rounded, color: cyberCyan, size: 18),
            const SizedBox(width: 10),
            Text(
              '$label copied to clipboard.',
              style: GoogleFonts.jetBrainsMono(color: textBright, fontSize: 12),
            ),
          ],
        ),
      ),
    );
  }

  void _showExportDialog(String destKey, String b32, String sessionId) {
    final exportJson = '''
{
  "app": "${KamuiConstants.appName}",
  "version": "${KamuiConstants.appVersion}",
  "protocol": "I2P SAM v${KamuiConstants.samMaxVersion}",
  "session_id": "$sessionId",
  "b32_address": "$b32",
  "destination_key": "$destKey",
  "exported_at": "${DateTime.now().toIso8601String()}"
}''';

    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: panelDark,
        shape: RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(16),
          side: BorderSide(color: vortexOrange.withAlpha(80)),
        ),
        title: Row(
          children: [
            Icon(Icons.key_rounded, color: vortexOrange, size: 20),
            const SizedBox(width: 10),
            Text(
              'EXPORT NODE IDENTITY',
              style: GoogleFonts.rajdhani(
                color:         textBright,
                fontSize:      16,
                fontWeight:    FontWeight.w700,
                letterSpacing: 2,
              ),
            ),
          ],
        ),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              'Encrypted Node Credentials Export Package:',
              style: GoogleFonts.jetBrainsMono(color: textMid, fontSize: 11),
            ),
            const SizedBox(height: 10),
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color:        abyss,
                borderRadius: BorderRadius.circular(8),
                border:       Border.all(color: cyberCyan.withAlpha(30)),
              ),
              child: SingleChildScrollView(
                child: Text(
                  exportJson,
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 10,
                    color:    cyberCyan,
                    height:   1.5,
                  ),
                ),
              ),
            ),
          ],
        ),
        actions: [
          TextButton(
            onPressed: () => Navigator.pop(ctx),
            child: Text(
              'CLOSE',
              style: GoogleFonts.rajdhani(color: textMid, fontSize: 12),
            ),
          ),
          ElevatedButton.icon(
            onPressed: () {
              Navigator.pop(ctx);
              _copyKey(exportJson, 'Node Export JSON');
            },
            icon:  const Icon(Icons.copy, size: 14),
            label: const Text('COPY EXPORT JSON'),
            style: ElevatedButton.styleFrom(
              backgroundColor: vortexOrange,
              padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            ),
          ),
        ],
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final sam          = ref.watch(samServiceProvider);
    final isConnected  = sam.isConnected;
    final isSession    = sam.isSessionCreated;
    final destKey      = sam.localDestinationKey ?? 'Generating Destination Key…';
    final b32          = sam.b32Address;
    final sessionId    = sam.sessionId ?? 'KamuiSession';

    return Scaffold(
      backgroundColor: voidBlack,
      body: HudBackground(
        child: SafeArea(
          child: Column(
            children: [
              _buildHeader(),
              Expanded(
                child: SingleChildScrollView(
                  padding: const EdgeInsets.fromLTRB(20, 16, 20, 40),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      // Status summary card
                      _buildStatusCard(isConnected, isSession, sessionId),
                      const SizedBox(height: 24),

                      // Section 1: SAM Bridge Config
                      _buildSectionHeader(Icons.hub_outlined, 'SAM BRIDGE PROTOCOL'),
                      const SizedBox(height: 12),
                      _buildBridgeConfigCard(sam),
                      const SizedBox(height: 24),

                      // Section 2: Tunnel Config
                      _buildSectionHeader(Icons.alt_route_rounded, 'GARLIC TUNNEL CONFIGURATION'),
                      const SizedBox(height: 12),
                      _buildTunnelConfigCard(sam),
                      const SizedBox(height: 24),

                      // Section 3: Identity & Destination Key
                      _buildSectionHeader(Icons.fingerprint, 'LOCAL DESTINATION KEY & IDENTITY'),
                      const SizedBox(height: 12),
                      _buildIdentityCard(destKey, b32, sessionId),
                      const SizedBox(height: 24),

                      // Section 4: Multi-Identity Persona Switcher
                      _buildSectionHeader(Icons.person_pin_rounded, 'MULTI-IDENTITY PERSONA SWITCHER'),
                      const SizedBox(height: 12),
                      _buildPersonaSwitcherCard(),
                      const SizedBox(height: 24),

                      // Section 5: Security Shield & Duress Mode
                      _buildSectionHeader(Icons.security_rounded, 'APP SHIELD & DURESS PANIC MODE'),
                      const SizedBox(height: 12),
                      _buildSecurityShieldCard(),
                      const SizedBox(height: 24),

                      // Section 6: Neon Theme Switcher
                      _buildSectionHeader(Icons.palette_outlined, 'NEON THEME SWITCHER'),
                      const SizedBox(height: 12),
                      _buildThemeSwitcherCard(ref.watch(neonThemeNotifierProvider)),
                    ],
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  // ── Sub-Widgets ────────────────────────────────────────────────────────────

  Widget _buildHeader() {
    return Container(
      padding: const EdgeInsets.fromLTRB(20, 14, 16, 14),
      decoration: BoxDecoration(
        color: voidBlack.withAlpha(200),
        border: Border(
          bottom: BorderSide(color: cyberCyan.withAlpha(18), width: 0.5),
        ),
      ),
      child: Row(
        children: [
          GestureDetector(
            onTap: () => Navigator.pop(context),
            child: const Icon(Icons.arrow_back_ios_new, color: textBright, size: 18),
          ),
          const SizedBox(width: 16),
          ShaderMask(
            shaderCallback: (b) => const LinearGradient(
              colors: [vortexOrange, cyberCyan],
            ).createShader(b),
            child: Text(
              'NODE SETTINGS',
              style: GoogleFonts.orbitron(
                fontSize:    18,
                fontWeight:  FontWeight.w900,
                color:       Colors.white,
                letterSpacing: 4,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildSectionHeader(IconData icon, String title) {
    return Row(
      children: [
        Icon(icon, color: vortexOrange, size: 16),
        const SizedBox(width: 8),
        Text(
          title,
          style: GoogleFonts.jetBrainsMono(
            fontSize:    10,
            fontWeight:  FontWeight.w700,
            color:       textMid,
            letterSpacing: 2,
          ),
        ),
      ],
    );
  }

  Widget _buildStatusCard(bool isConnected, bool isSession, String sessionId) {
    final statusColor = isSession
        ? emeraldGlow
        : isConnected ? warningAmber : textDim;
    final statusLabel = isSession
        ? 'STREAM SESSION ACTIVE'
        : isConnected ? 'CONNECTED TO SAM' : 'SAM OFFLINE';

    return ClipRRect(
      borderRadius: BorderRadius.circular(14),
      child: BackdropFilter(
        filter: ImageFilter.blur(sigmaX: 8, sigmaY: 8),
        child: Container(
          padding: const EdgeInsets.all(18),
          decoration: BoxDecoration(
            color:        panelDark.withAlpha(220),
            borderRadius: BorderRadius.circular(14),
            border:       Border.all(color: statusColor.withAlpha(50), width: 1),
            boxShadow: [
              BoxShadow(color: statusColor.withAlpha(15), blurRadius: 16),
            ],
          ),
          child: Row(
            children: [
              StatusDot(color: statusColor, size: 10, animate: isSession),
              const SizedBox(width: 14),
              Expanded(
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    Text(
                      statusLabel,
                      style: GoogleFonts.rajdhani(
                        color:      textBright,
                        fontSize:   16,
                        fontWeight: FontWeight.w700,
                        letterSpacing: 1.5,
                      ),
                    ),
                    const SizedBox(height: 2),
                    Text(
                      'Session ID: $sessionId',
                      style: GoogleFonts.jetBrainsMono(
                        color:    cyberCyan.withAlpha(140),
                        fontSize: 11,
                      ),
                    ),
                  ],
                ),
              ),
              _isReconnecting
                  ? SizedBox(
                      width: 20,
                      height: 20,
                      child: CircularProgressIndicator(
                          strokeWidth: 2, color: vortexOrange),
                    )
                  : OutlinedButton(
                      onPressed: _reconnectSam,
                      style: OutlinedButton.styleFrom(
                        side: BorderSide(color: vortexOrange.withAlpha(80)),
                        padding: const EdgeInsets.symmetric(
                            horizontal: 12, vertical: 8),
                      ),
                      child: Text(
                        'RECONNECT',
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 9,
                          color: vortexOrange,
                          fontWeight: FontWeight.w700,
                        ),
                      ),
                    ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildBridgeConfigCard(SamService sam) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color:        panelDark,
        borderRadius: BorderRadius.circular(12),
        border:       Border.all(color: cyberCyan.withAlpha(20)),
      ),
      child: Column(
        children: [
          _configRow('SAM Bridge Host', sam.host),
          const Divider(height: 18),
          _configRow('SAM Bridge Port', '${sam.port}'),
          const Divider(height: 18),
          _configRow('Protocol Version', 'SAM v${KamuiConstants.samMaxVersion} (STREAM)'),
          const Divider(height: 18),
          _configRow('Socket Timeout', '${KamuiConstants.connectTimeout.inSeconds}s'),
        ],
      ),
    );
  }

  Widget _buildTunnelConfigCard(SamService sam) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color:        panelDark,
        borderRadius: BorderRadius.circular(12),
        border:       Border.all(color: cyberCyan.withAlpha(20)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text('Inbound Tunnels',
                  style: GoogleFonts.jetBrainsMono(color: textMid, fontSize: 11)),
              Text('${sam.inboundTunnels} active (3 hops)',
                  style: GoogleFonts.jetBrainsMono(
                      color: cyberCyan, fontSize: 11, fontWeight: FontWeight.w700)),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Text('Hops:', style: GoogleFonts.jetBrainsMono(color: textDim, fontSize: 10)),
              const SizedBox(width: 8),
              _hopChip(2, _inboundHops == 2, () => setState(() => _inboundHops = 2)),
              const SizedBox(width: 6),
              _hopChip(3, _inboundHops == 3, () => setState(() => _inboundHops = 3)),
              const SizedBox(width: 6),
              _hopChip(4, _inboundHops == 4, () => setState(() => _inboundHops = 4)),
            ],
          ),
          const Divider(height: 24),
          Row(
            mainAxisAlignment: MainAxisAlignment.spaceBetween,
            children: [
              Text('Outbound Tunnels',
                  style: GoogleFonts.jetBrainsMono(color: textMid, fontSize: 11)),
              Text('${sam.outboundTunnels} active (3 hops)',
                  style: GoogleFonts.jetBrainsMono(
                      color: cyberCyan, fontSize: 11, fontWeight: FontWeight.w700)),
            ],
          ),
          const SizedBox(height: 8),
          Row(
            children: [
              Text('Hops:', style: GoogleFonts.jetBrainsMono(color: textDim, fontSize: 10)),
              const SizedBox(width: 8),
              _hopChip(2, _outboundHops == 2, () => setState(() => _outboundHops = 2)),
              const SizedBox(width: 6),
              _hopChip(3, _outboundHops == 3, () => setState(() => _outboundHops = 3)),
              const SizedBox(width: 6),
              _hopChip(4, _outboundHops == 4, () => setState(() => _outboundHops = 4)),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildIdentityCard(String destKey, String b32, String sessionId) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color:        panelDark,
        borderRadius: BorderRadius.circular(12),
        border:       Border.all(color: vortexOrange.withAlpha(30)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Base32 address header
          Row(
            children: [
              Icon(Icons.link, color: emeraldGlow, size: 16),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  b32,
                  style: GoogleFonts.jetBrainsMono(
                    fontSize:   11,
                    color:      emeraldGlow,
                    fontWeight: FontWeight.w600,
                  ),
                ),
              ),
              IconButton(
                icon: Icon(Icons.copy_rounded, color: emeraldGlow, size: 16),
                onPressed: () => _copyKey(b32, 'B32 Address'),
                tooltip: 'Copy B32',
              ),
            ],
          ),

          const SizedBox(height: 12),
          Text(
            'FULL BASE64 DESTINATION KEY',
            style: GoogleFonts.jetBrainsMono(fontSize: 9, color: textDim, letterSpacing: 1.5),
          ),
          const SizedBox(height: 6),

          // Scrollable key box
          Container(
            height: 90,
            padding: const EdgeInsets.all(12),
            decoration: BoxDecoration(
              color:        abyss,
              borderRadius: BorderRadius.circular(8),
              border:       Border.all(color: cyberCyan.withAlpha(20)),
            ),
            child: SingleChildScrollView(
              child: SelectableText(
                destKey,
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 10,
                  color:    cyberCyan.withAlpha(180),
                  height:   1.5,
                ),
              ),
            ),
          ),

          const SizedBox(height: 16),

          // Action buttons
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () => _copyKey(destKey, 'Destination Key'),
                  icon:  Icon(Icons.copy_rounded, size: 14, color: cyberCyan),
                  label: Text('COPY',
                      style: GoogleFonts.rajdhani(
                          color: cyberCyan, letterSpacing: 1.5, fontWeight: FontWeight.w700)),
                  style: OutlinedButton.styleFrom(
                    side: BorderSide(color: cyberCyan.withAlpha(60)),
                    padding: const EdgeInsets.symmetric(vertical: 12),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () => showDialog(
                    context: context,
                    builder: (_) => QrShareDialog(destinationKey: destKey),
                  ),
                  icon:  Icon(Icons.qr_code_2_rounded, size: 14, color: emeraldGlow),
                  label: Text('SHOW QR',
                      style: GoogleFonts.rajdhani(
                          color: emeraldGlow, letterSpacing: 1.5, fontWeight: FontWeight.w700)),
                  style: OutlinedButton.styleFrom(
                    side: BorderSide(color: emeraldGlow.withAlpha(60)),
                    padding: const EdgeInsets.symmetric(vertical: 12),
                  ),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(
                child: KamuiButton(
                  label:     'EXPORT',
                  onPressed: () => _showExportDialog(destKey, b32, sessionId),
                  fullWidth: false,
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildPersonaSwitcherCard() {
    final activePersona = ref.watch(personaNotifierProvider);
    final available     = ref.watch(personaNotifierProvider.notifier).availablePersonas;

    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color:        panelDark,
        borderRadius: BorderRadius.circular(12),
        border:       Border.all(color: cyberCyan.withAlpha(20)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Active Identity Persona:',
            style: GoogleFonts.jetBrainsMono(color: textMid, fontSize: 11),
          ),
          const SizedBox(height: 12),
          Column(
            children: available.map((persona) {
              final isSelected = persona.id == activePersona.id;
              return Container(
                margin: const EdgeInsets.only(bottom: 8),
                decoration: BoxDecoration(
                  color: isSelected ? vortexOrange.withAlpha(15) : surfaceDark,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(
                    color: isSelected ? vortexOrange : textDim.withAlpha(40),
                  ),
                ),
                child: ListTile(
                  onTap: () {
                    ref.read(personaNotifierProvider.notifier).selectPersona(persona);
                    ScaffoldMessenger.of(context).showSnackBar(
                      SnackBar(
                        backgroundColor: panelDark,
                        duration: const Duration(seconds: 2),
                        content: Text(
                          'Switched persona to: ${persona.name}',
                          style: GoogleFonts.jetBrainsMono(color: cyberCyan, fontSize: 11),
                        ),
                      ),
                    );
                  },
                  leading: CircleAvatar(
                    backgroundColor: isSelected ? vortexOrange : panelDark,
                    foregroundColor: Colors.white,
                    child: Text(
                      persona.avatarInitial,
                      style: GoogleFonts.orbitron(fontWeight: FontWeight.bold),
                    ),
                  ),
                  title: Text(
                    persona.name,
                    style: GoogleFonts.rajdhani(
                      color:      textBright,
                      fontSize:   15,
                      fontWeight: FontWeight.w600,
                    ),
                  ),
                  subtitle: Text(
                    '${persona.tag} • ${persona.truncatedDestination}',
                    style: GoogleFonts.jetBrainsMono(color: textMid, fontSize: 10),
                  ),
                  trailing: isSelected
                      ? Icon(Icons.check_circle_rounded, color: vortexOrange, size: 20)
                      : null,
                ),
              );
            }).toList(),
          ),
        ],
      ),
    );
  }

  Widget _buildSecurityShieldCard() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color:        panelDark,
        borderRadius: BorderRadius.circular(12),
        border:       Border.all(color: Colors.redAccent.withAlpha(30)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Row(
            children: [
              Icon(Icons.shield_rounded, color: Colors.redAccent, size: 18),
              const SizedBox(width: 10),
              Text(
                'COERCION PROTECTION & PANIC WIPE',
                style: GoogleFonts.rajdhani(
                  color:      textBright,
                  fontSize:   14,
                  fontWeight: FontWeight.w700,
                  letterSpacing: 1,
                ),
              ),
            ],
          ),
          const SizedBox(height: 8),
          Text(
            'Configure a Duress PIN (Panic PIN). Entering the Duress PIN on launch immediately & silently wipes all local keys, message history, and database, presenting a harmless decoy feed.',
            style: GoogleFonts.jetBrainsMono(color: textMid, fontSize: 11, height: 1.5),
          ),
          const SizedBox(height: 14),
          Row(
            children: [
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () async {
                    await LockService().setupSecurity(
                      normalPin: '1337',
                      duressPin: '9999',
                    );
                    if (mounted) {
                      ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(
                          backgroundColor: panelDark,
                          content: Text(
                            'Shield Activated: Primary PIN [1337] • Duress PIN [9999]',
                            style: GoogleFonts.jetBrainsMono(color: emeraldGlow, fontSize: 11),
                          ),
                        ),
                      );
                    }
                  },
                  icon:  Icon(Icons.lock_outline, size: 14, color: emeraldGlow),
                  label: Text('ENABLE SHIELD',
                      style: GoogleFonts.rajdhani(
                          color: emeraldGlow, letterSpacing: 1.5, fontWeight: FontWeight.w700)),
                  style: OutlinedButton.styleFrom(
                    side: BorderSide(color: emeraldGlow.withAlpha(60)),
                    padding: const EdgeInsets.symmetric(vertical: 12),
                  ),
                ),
              ),
              const SizedBox(width: 10),
              Expanded(
                child: OutlinedButton.icon(
                  onPressed: () {
                    Navigator.push(
                      context,
                      MaterialPageRoute(builder: (_) => const LockScreen()),
                    );
                  },
                  icon:  Icon(Icons.lock_clock_outlined, size: 14, color: vortexOrange),
                  label: Text('TEST SHIELD',
                      style: GoogleFonts.rajdhani(
                          color: vortexOrange, letterSpacing: 1.5, fontWeight: FontWeight.w700)),
                  style: OutlinedButton.styleFrom(
                    side: BorderSide(color: vortexOrange.withAlpha(60)),
                    padding: const EdgeInsets.symmetric(vertical: 12),
                  ),
                ),
              ),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildThemeSwitcherCard(NeonTheme currentTheme) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color:        panelDark,
        borderRadius: BorderRadius.circular(12),
        border:       Border.all(color: cyberCyan.withAlpha(20)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'Select HUD Accent Theme:',
            style: GoogleFonts.jetBrainsMono(color: textMid, fontSize: 11),
          ),
          const SizedBox(height: 12),
          Wrap(
            spacing: 10,
            runSpacing: 10,
            children: NeonTheme.values.map((theme) {
              final isSelected = theme == currentTheme;
              return GestureDetector(
                onTap: () {
                  ref.read(neonThemeNotifierProvider.notifier).setTheme(theme);
                },
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 200),
                  padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
                  decoration: BoxDecoration(
                    color: isSelected
                        ? theme.primaryColor.withAlpha(25)
                        : surfaceDark,
                    borderRadius: BorderRadius.circular(8),
                    border: Border.all(
                      color: isSelected
                          ? theme.primaryColor
                          : textDim.withAlpha(50),
                      width: isSelected ? 1.5 : 1.0,
                    ),
                    boxShadow: isSelected
                        ? [
                            BoxShadow(
                              color:      theme.primaryColor.withAlpha(60),
                              blurRadius: 10,
                            ),
                          ]
                        : [],
                  ),
                  child: Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      Container(
                        width: 12,
                        height: 12,
                        decoration: BoxDecoration(
                          shape: BoxShape.circle,
                          color: theme.primaryColor,
                          boxShadow: [
                            BoxShadow(
                              color: theme.primaryColor.withAlpha(120),
                              blurRadius: 6,
                            ),
                          ],
                        ),
                      ),
                      const SizedBox(width: 8),
                      Text(
                        theme.label,
                        style: GoogleFonts.rajdhani(
                          fontSize: 13,
                          fontWeight:
                              isSelected ? FontWeight.w700 : FontWeight.w500,
                          color: isSelected ? textBright : textMid,
                          letterSpacing: 1,
                        ),
                      ),
                    ],
                  ),
                ),
              );
            }).toList(),
          ),
        ],
      ),
    );
  }

  Widget _configRow(String label, String value) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.spaceBetween,
      children: [
        Text(label, style: GoogleFonts.jetBrainsMono(color: textMid, fontSize: 11)),
        Text(value,
            style: GoogleFonts.jetBrainsMono(
                color: textBright, fontSize: 11, fontWeight: FontWeight.w600)),
      ],
    );
  }

  Widget _hopChip(int hops, bool selected, VoidCallback onTap) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
        decoration: BoxDecoration(
          color: selected ? vortexOrange.withAlpha(20) : surfaceDark,
          borderRadius: BorderRadius.circular(6),
          border: Border.all(
            color: selected ? vortexOrange : textDim.withAlpha(60),
          ),
        ),
        child: Text(
          '$hops Hops',
          style: GoogleFonts.jetBrainsMono(
            fontSize: 9,
            color: selected ? vortexOrange : textMid,
            fontWeight: selected ? FontWeight.w700 : FontWeight.normal,
          ),
        ),
      ),
    );
  }
}
