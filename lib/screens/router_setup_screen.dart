import 'dart:async';

import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:google_fonts/google_fonts.dart';

import '../core/constants.dart';
import '../core/providers.dart';
import '../core/theme.dart';
import '../services/sam_service.dart';
import '../widgets/hud_background.dart';
import '../widgets/kamui_button.dart';
import '../widgets/status_dot.dart';

/// Full-screen onboarding shown when the startup reachability probe finds no
/// I2P router listening on the SAM bridge port (`127.0.0.1:7656`).
///
/// Honesty contract of this screen:
///   • It NEVER claims a local node exists — Kamui ships no embedded router.
///   • The live status line is driven by [SamService.statusStream], so the
///     background cold-start reconnect loop's progress is always visible.
///   • "Continue Offline" is explicitly labeled as transport-less: messages
///     cannot send or receive until a router comes up.
class RouterSetupScreen extends ConsumerStatefulWidget {
  /// Re-runs the probe → connect → session flow. Awaited so the button can
  /// show a busy state; navigation away on success is the caller's job.
  final Future<void> Function() onRetry;

  /// Invoked when the user explicitly chooses to enter without transport.
  final VoidCallback onContinueOffline;

  const RouterSetupScreen({
    super.key,
    required this.onRetry,
    required this.onContinueOffline,
  });

  @override
  ConsumerState<RouterSetupScreen> createState() => _RouterSetupScreenState();
}

class _RouterSetupScreenState extends ConsumerState<RouterSetupScreen> {
  StreamSubscription<Map<String, dynamic>>? _statusSub;
  String _liveStatus = 'WAITING FOR ROUTER…';
  bool _isRetrying = false;

  @override
  void initState() {
    super.initState();
    _statusSub = ref.read(samServiceProvider).statusStream.listen((event) {
      if (!mounted) return;
      setState(() => _liveStatus = _describeStatus(event['status'] as String?));
    });
  }

  @override
  void dispose() {
    unawaited(_statusSub?.cancel());
    _statusSub = null;
    super.dispose();
  }

  /// Maps raw SAM status emissions to honest human-readable HUD copy.
  static String _describeStatus(String? status) {
    switch (status) {
      case 'connecting':
        return 'CONNECTING TO SAM BRIDGE…';
      case 'handshake_ok':
        return 'HANDSHAKE OK — NEGOTIATING SESSION…';
      case 'handshake_failed':
        return 'HANDSHAKE FAILED — WILL RETRY';
      case 'reconnecting':
        return 'AUTO-RETRY ARMED — WAITING FOR ROUTER…';
      case 'disconnected':
        return 'OFFLINE — NOTHING ON '
            '${KamuiConstants.samHost}:${KamuiConstants.samPort}';
      case 'session_ok':
        return 'ROUTER LINK RESTORED — TAP RETRY TO CONTINUE';
      default:
        return 'STATUS: ${(status ?? 'UNKNOWN').toUpperCase()}';
    }
  }

  /// Platform-aware, generic install guidance. No fabricated download links —
  /// i2pd.io and package managers are referenced generically.
  static String _installHint(TargetPlatform platform) {
    switch (platform) {
      case TargetPlatform.macOS:
        return 'On macOS: brew install i2pd  (or grab a build from i2pd.io)';
      case TargetPlatform.linux:
        return 'On Linux: install i2pd via your package manager '
            '(e.g. apt install i2pd), or from i2pd.io';
      case TargetPlatform.windows:
        return 'On Windows: unpack the official static i2pd build from i2pd.io';
      case TargetPlatform.android:
        return 'On Android: run i2pd on this device (F-Droid build) or on any '
            'machine reachable from it';
      case TargetPlatform.iOS:
        return 'On iOS a router cannot ship inside this app today — run i2pd '
            'on a nearby machine on your LAN';
      case TargetPlatform.fuchsia:
        return 'Install i2pd from i2pd.io';
    }
  }

  Future<void> _handleRetry() async {
    if (_isRetrying) return;
    setState(() => _isRetrying = true);
    try {
      await widget.onRetry();
    } finally {
      if (mounted) setState(() => _isRetrying = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final installHint = _installHint(Theme.of(context).platform);

    return PopScope(
      canPop: false, // no meaningful "back" into the dead splash state
      child: Scaffold(
        backgroundColor: voidBlack,
        body: HudBackground(
          child: SafeArea(
            child: SingleChildScrollView(
              padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 32),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.stretch,
                children: [
                  const SizedBox(height: 16),

                  // ── Headline ──────────────────────────────────────────
                  Icon(Icons.router_rounded,
                      color: warningAmber, size: 44),
                  const SizedBox(height: 18),
                  ShaderMask(
                    shaderCallback: (bounds) => const LinearGradient(
                      colors: [warningAmber, vortexOrange],
                    ).createShader(bounds),
                    child: Text(
                      'No I2P Router Detected',
                      textAlign: TextAlign.center,
                      style: GoogleFonts.orbitron(
                        fontSize:     22,
                        fontWeight:  FontWeight.w900,
                        letterSpacing: 3,
                        color:       Colors.white,
                      ),
                    ),
                  ),
                  const SizedBox(height: 10),
                  Text(
                    'Kamui speaks the I2P SAM protocol and needs a local '
                    'router at ${KamuiConstants.samHost}:'
                    '${KamuiConstants.samPort} to send or receive.',
                    textAlign: TextAlign.center,
                    style: GoogleFonts.jetBrainsMono(
                      fontSize: 11,
                      color:    textMid,
                      height:   1.6,
                    ),
                  ),

                  const SizedBox(height: 28),

                  // ── Setup steps ───────────────────────────────────────
                  _buildStepsCard(installHint),

                  const SizedBox(height: 20),

                  // ── Live status line ──────────────────────────────────
                  _buildLiveStatusCard(),

                  const SizedBox(height: 28),

                  // ── Actions ───────────────────────────────────────────
                  _isRetrying
                      ? const Center(
                          child: SizedBox(
                            width:  26,
                            height: 26,
                            child: CircularProgressIndicator(
                                strokeWidth: 2, color: cyberCyan),
                          ),
                        )
                      : KamuiButton(label: 'RETRY', onPressed: _handleRetry),

                  const SizedBox(height: 14),

                  OutlinedButton(
                    onPressed:
                        _isRetrying ? null : widget.onContinueOffline,
                    style: OutlinedButton.styleFrom(
                      side: BorderSide(color: textDim.withAlpha(70)),
                      padding:
                          const EdgeInsets.symmetric(vertical: 14),
                    ),
                    child: Text(
                      'ENTER WITHOUT TRANSPORT',
                      style: GoogleFonts.jetBrainsMono(
                        fontSize:     11,
                        letterSpacing: 1.5,
                        color:        textMid,
                      ),
                    ),
                  ),
                  const SizedBox(height: 8),
                  Text(
                    'No I2P router — messages cannot send or receive.',
                    textAlign: TextAlign.center,
                    style: GoogleFonts.jetBrainsMono(
                      fontSize: 9,
                      color:    textDim,
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

  Widget _buildStepsCard(String installHint) {
    return Container(
      padding: const EdgeInsets.all(18),
      decoration: BoxDecoration(
        color:        panelDark.withAlpha(220),
        borderRadius: BorderRadius.circular(12),
        border:       Border.all(color: cyberCyan.withAlpha(30)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Text(
            'GET A ROUTER RUNNING',
            style: GoogleFonts.jetBrainsMono(
              fontSize:     10,
              fontWeight:  FontWeight.w700,
              color:       cyberCyan,
              letterSpacing: 2,
            ),
          ),
          const SizedBox(height: 12),
          _stepBullet('1', 'Install i2pd', installHint),
          _stepBullet('2', 'Enable SAM',
              'i2pd enables SAM on ${KamuiConstants.samHost}:'
              '${KamuiConstants.samPort} by default; otherwise set '
              'sam.enabled=true in i2pd.conf'),
          _stepBullet('3', 'Start it and leave it running',
              'Kamui auto-retries in the background and picks the router up '
              'the moment it listens'),
        ],
      ),
    );
  }

  Widget _stepBullet(String number, String title, String detail) {
    return Padding(
      padding: const EdgeInsets.only(bottom: 12),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            width:  20,
            height: 20,
            alignment: Alignment.center,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              border: Border.all(color: vortexOrange.withAlpha(120)),
            ),
            child: Text(number,
                style: GoogleFonts.orbitron(
                    fontSize: 9, color: vortexOrange)),
          ),
          const SizedBox(width: 12),
          Expanded(
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Text(title,
                    style: GoogleFonts.rajdhani(
                      fontSize:     13,
                      fontWeight:  FontWeight.w700,
                      color:       textBright,
                      letterSpacing: 1,
                    )),
                const SizedBox(height: 2),
                Text(detail,
                    style: GoogleFonts.jetBrainsMono(
                      fontSize: 10,
                      color:    textMid,
                      height:   1.5,
                    )),
              ],
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildLiveStatusCard() {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      decoration: BoxDecoration(
        color:        abyss,
        borderRadius: BorderRadius.circular(10),
        border:       Border.all(color: cyberCyan.withAlpha(25)),
      ),
      child: Row(
        children: [
          const StatusDot(color: cyberCyan, size: 8, animate: true),
          const SizedBox(width: 12),
          Expanded(
            child: AnimatedSwitcher(
              duration: const Duration(milliseconds: 300),
              child: Text(
                _liveStatus,
                key: ValueKey(_liveStatus),
                style: GoogleFonts.jetBrainsMono(
                  fontSize:     10,
                  color:        cyberCyan.withAlpha(190),
                  letterSpacing: 1,
                ),
              ),
            ),
          ),
        ],
      ),
    );
  }
}
