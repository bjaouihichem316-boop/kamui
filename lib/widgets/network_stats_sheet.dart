import 'dart:async';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:google_fonts/google_fonts.dart';
import '../core/theme.dart';
import '../core/providers.dart';
import '../services/sam_service.dart';

/// Cyberpunk HUD terminal bottom sheet — shows SAM network statistics and live log.
///
/// Only state the SAM v3 bridge actually reports is displayed (connection,
/// session, destination). Router-level metrics (tunnel counts, bandwidth,
/// NAT status) are not exposed by SAM v3 and render as "—".
class NetworkStatsSheet extends ConsumerStatefulWidget {
  const NetworkStatsSheet({super.key});

  @override
  ConsumerState<NetworkStatsSheet> createState() => _NetworkStatsSheetState();
}

class _NetworkStatsSheetState extends ConsumerState<NetworkStatsSheet> {
  /// Placeholder for metrics the SAM v3 bridge does not expose.
  static const String _notExposed = '—';

  /// Explanation shown wherever [_notExposed] appears.
  static const String _routerStatsNote = 'Router stats not exposed via SAM v3';

  // ── State (real SAM session data only) ────────────────────────────────
  bool   _isLive          = false;
  String _sessionId       = _notExposed;
  String _localDest       = '';
  String _connectionStatus = 'Idle';

  final List<Map<String, dynamic>> _logs = [];

  StreamSubscription<Map<String, dynamic>>? _statusSub;
  StreamSubscription<Map<String, dynamic>>? _logSub;

  @override
  void initState() {
    super.initState();
    final sam = ref.read(samServiceProvider);

    if (sam.isConnected || sam.isSessionCreated) {
      _applyState(sam);
    }

    _statusSub = sam.statusStream.listen(_onStatusUpdate);
    _logSub    = sam.logStream.listen(_onLogEntry);
  }

  void _applyState(SamService sam) {
    setState(() {
      _isLive    = sam.isConnected;
      _sessionId = sam.sessionId ?? _notExposed;
      _localDest = sam.localDestinationKey ?? '';
      _connectionStatus = sam.isSessionCreated
          ? 'Session Active'
          : _isLive ? 'Connected' : 'Idle';
    });
  }

  void _onStatusUpdate(Map<String, dynamic> status) {
    if (!mounted) return;
    setState(() {
      _isLive          = status['isConnected']    as bool?   ?? false;
      _sessionId       = status['sessionId']      as String? ?? _sessionId;
      _localDest       = status['localDestinationKey'] as String? ?? '';
      _connectionStatus = status['status'] as String? ?? _connectionStatus;
    });
  }

  void _onLogEntry(Map<String, dynamic> log) {
    if (!mounted) return;
    setState(() {
      _logs.insert(0, log);
      if (_logs.length > 50) _logs.removeLast();
    });
  }

  @override
  void dispose() {
    _statusSub?.cancel();
    _logSub?.cancel();
    super.dispose();
  }

  // ── Build ──────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.fromLTRB(24, 16, 24, 32),
      decoration: BoxDecoration(
        color: panelDark.withAlpha(240),
        borderRadius: const BorderRadius.only(
          topLeft:  Radius.circular(24),
          topRight: Radius.circular(24),
        ),
        border: Border(
          top: BorderSide(color: cyberCyan.withAlpha(40), width: 1),
        ),
        boxShadow: [
          BoxShadow(color: cyberCyan.withAlpha(15), blurRadius: 30, spreadRadius: 5),
        ],
      ),
      child: SingleChildScrollView(
        child: Column(
          mainAxisSize: MainAxisSize.min,
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            // Drag handle
            Center(
              child: Container(
                width: 40,
                height: 4,
                decoration: BoxDecoration(
                  color: cyberCyan.withAlpha(40),
                  borderRadius: BorderRadius.circular(2),
                ),
              ),
            ),
            const SizedBox(height: 20),

            // Header
            Row(
              children: [
                Icon(Icons.sensors, color: vortexOrange, size: 18),
                const SizedBox(width: 10),
                Text(
                  'NETWORK CONSOLE',
                  style: GoogleFonts.rajdhani(
                    fontSize: 14,
                    fontWeight: FontWeight.w700,
                    color: textBright,
                    letterSpacing: 4,
                  ),
                ),
                const Spacer(),
                _liveChip(),
              ],
            ),

            const SizedBox(height: 18),
            _divider(),
            const SizedBox(height: 14),

            // Stats — only values SAM v3 actually reports
            _statRow(icon: Icons.wifi, label: 'SAM Status',
                value: _connectionStatus,
                color: _isLive ? emeraldGlow : textMid),
            const SizedBox(height: 10),
            _statRow(icon: Icons.arrow_downward, label: 'Inbound Tunnels',
                value: _notExposed, color: textMid,
                tooltip: _routerStatsNote),
            const SizedBox(height: 10),
            _statRow(icon: Icons.arrow_upward, label: 'Outbound Tunnels',
                value: _notExposed, color: textMid,
                tooltip: _routerStatsNote),
            const SizedBox(height: 16),
            _divider(),
            const SizedBox(height: 14),

            // Bandwidth — SAM v3 exposes no throughput stats; honest dashes.
            Text(
              'BANDWIDTH',
              style: GoogleFonts.jetBrainsMono(
                fontSize: 10, color: textDim, letterSpacing: 2,
              ),
            ),
            const SizedBox(height: 4),
            Text(
              _routerStatsNote,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 9, color: textDim, letterSpacing: 0.5,
              ),
            ),
            const SizedBox(height: 10),
            Row(
              children: [
                Expanded(child: _meter('INBOUND',  _notExposed, 0, cyberCyan)),
                const SizedBox(width: 14),
                Expanded(child: _meter('OUTBOUND', _notExposed, 0, neonPurple)),
              ],
            ),

            const SizedBox(height: 16),
            _divider(),
            const SizedBox(height: 14),

            _statRow(icon: Icons.shield_outlined, label: 'NAT / CGNAT',
                value: _notExposed, color: textMid,
                tooltip: _routerStatsNote),
            const SizedBox(height: 10),
            _statRow(icon: Icons.fingerprint, label: 'Session ID',
                value: _sessionId, color: textMid),

            if (_localDest.isNotEmpty) ...[
              const SizedBox(height: 10),
              _statRow(
                icon:  Icons.vpn_key_outlined,
                label: 'Local Destination',
                value: _localDest.length > 16
                    ? '${_localDest.substring(0, 8)}…${_localDest.substring(_localDest.length - 4)}'
                    : _localDest,
                color: vortexOrange.withAlpha(200),
              ),
            ],

            // Live Log
            if (_logs.isNotEmpty) ...[
              const SizedBox(height: 16),
              _divider(),
              const SizedBox(height: 14),
              Text(
                'LIVE LOG',
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 10, color: textDim, letterSpacing: 3,
                ),
              ),
              const SizedBox(height: 8),
              Container(
                constraints: const BoxConstraints(maxHeight: 110),
                decoration: BoxDecoration(
                  color: abyss,
                  borderRadius: BorderRadius.circular(8),
                  border: Border.all(color: cyberCyan.withAlpha(18)),
                ),
                padding: const EdgeInsets.all(10),
                child: ListView.builder(
                  shrinkWrap: true,
                  reverse: false,
                  itemCount: _logs.length.clamp(0, 8),
                  itemBuilder: (_, i) {
                    final log  = _logs[i];
                    final type = log['type'] as String? ?? 'info';
                    final msg  = log['message'] as String? ?? '';
                    return Text(
                      msg,
                      style: GoogleFonts.jetBrainsMono(
                        fontSize: 9,
                        color: _logColor(type),
                        height: 1.6,
                      ),
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                    );
                  },
                ),
              ),
            ],

            const SizedBox(height: 20),

            // Close button
            SizedBox(
              width: double.infinity,
              child: OutlinedButton(
                onPressed: () => Navigator.pop(context),
                style: OutlinedButton.styleFrom(
                  side: BorderSide(color: cyberCyan.withAlpha(60)),
                  foregroundColor: textMid,
                  padding: const EdgeInsets.symmetric(vertical: 14),
                  shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(8),
                  ),
                ),
                child: Text(
                  'CLOSE CONSOLE',
                  style: GoogleFonts.rajdhani(
                    letterSpacing: 3,
                    fontSize: 12,
                    fontWeight: FontWeight.w600,
                    color: cyberCyan.withAlpha(160),
                  ),
                ),
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ── Sub-Widgets ────────────────────────────────────────────────────────

  Widget _liveChip() {
    final isLive = _isLive;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
      decoration: BoxDecoration(
        color: (isLive ? emeraldGlow : textDim).withAlpha(20),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: (isLive ? emeraldGlow : textDim).withAlpha(60)),
      ),
      child: Text(
        isLive ? '● LIVE' : '○ OFFLINE',
        style: GoogleFonts.jetBrainsMono(
          fontSize: 9,
          fontWeight: FontWeight.w700,
          color: isLive ? emeraldGlow : textDim,
          letterSpacing: 1.5,
        ),
      ),
    );
  }

  Widget _divider() => Container(
    height: 1,
    decoration: BoxDecoration(
      gradient: LinearGradient(colors: [
        Colors.transparent,
        cyberCyan.withAlpha(25),
        Colors.transparent,
      ]),
    ),
  );

  Widget _statRow({
    required IconData icon,
    required String   label,
    required String   value,
    required Color    color,
    String?           tooltip,
  }) {
    final valueText = Text(
      value,
      style: GoogleFonts.jetBrainsMono(
        fontSize:   11,
        fontWeight: FontWeight.w700,
        color:      color,
        letterSpacing: 0.3,
      ),
      textAlign: TextAlign.end,
      maxLines:  1,
      overflow:  TextOverflow.ellipsis,
    );
    return Row(
      children: [
        Icon(icon, size: 14, color: vortexOrange.withAlpha(160)),
        const SizedBox(width: 10),
        Expanded(
          child: Text(
            label,
            style: GoogleFonts.jetBrainsMono(fontSize: 11, color: textMid),
          ),
        ),
        Flexible(
          child: tooltip == null
              ? valueText
              : Tooltip(message: tooltip, child: valueText),
        ),
      ],
    );
  }

  Widget _meter(String label, String value, double fill, Color color) {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.spaceBetween,
          children: [
            Text(label, style: GoogleFonts.jetBrainsMono(fontSize: 9, color: textDim)),
            Text(value, style: GoogleFonts.jetBrainsMono(
              fontSize: 11, fontWeight: FontWeight.w700, color: color)),
          ],
        ),
        const SizedBox(height: 6),
        Container(
          height: 6,
          clipBehavior: Clip.hardEdge,
          decoration: BoxDecoration(
            color: Colors.white.withAlpha(10),
            borderRadius: BorderRadius.circular(3),
          ),
          child: FractionallySizedBox(
            widthFactor: fill.clamp(0.0, 1.0),
            alignment: Alignment.centerLeft,
            child: Container(
              decoration: BoxDecoration(
                gradient: LinearGradient(colors: [
                  color.withAlpha(180),
                  color,
                ]),
                borderRadius: BorderRadius.circular(3),
                boxShadow: [
                  BoxShadow(color: color.withAlpha(80), blurRadius: 6),
                ],
              ),
            ),
          ),
        ),
      ],
    );
  }

  Color _logColor(String type) {
    switch (type) {
      case 'error':   return Colors.redAccent;
      case 'success': return emeraldGlow;
      case 'data':    return cyberCyan.withAlpha(180);
      default:        return textMid;
    }
  }
}
