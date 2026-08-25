import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:google_fonts/google_fonts.dart';

import '../core/constants.dart';
import '../core/providers.dart';
import '../core/theme.dart';
import '../services/lock_service.dart';
import '../services/sam_service.dart';
import '../widgets/hud_background.dart';
import '../widgets/kamui_button.dart';
import '../widgets/vortex_ring.dart';
import 'chat_list_screen.dart';
import 'lock_screen.dart';
import 'router_setup_screen.dart';

class SplashScreen extends ConsumerStatefulWidget {
  const SplashScreen({super.key});

  @override
  ConsumerState<SplashScreen> createState() => _SplashScreenState();
}

class _SplashScreenState extends ConsumerState<SplashScreen>
    with SingleTickerProviderStateMixin {
  late AnimationController _fadeController;
  late Animation<double>   _fadeIn;
  late Animation<double>   _titleScale;

  String _currentStatus = 'Initializing Garlic Router…';
  bool _isConnecting = true;

  @override
  void initState() {
    super.initState();

    _fadeController = AnimationController(
      vsync: this,
      duration: KamuiConstants.splashFadeDuration,
    );

    _fadeIn = Tween<double>(begin: 0.0, end: 1.0).animate(
      CurvedAnimation(
          parent: _fadeController,
          curve: const Interval(0.0, 0.6, curve: Curves.easeOut)),
    );

    _titleScale = Tween<double>(begin: 0.85, end: 1.0).animate(
      CurvedAnimation(
          parent: _fadeController,
          curve: const Interval(0.0, 0.7, curve: Curves.easeOutCubic)),
    );

    _fadeController.forward();

    // Start live SAM connection flow
    _initSamBridge();
  }

  /// Startup transport flow:
  ///  1. Fast reachability probe against the SAM bridge port.
  ///  2. Reachable → full connect → session → inbound listener chain.
  ///  3. Nothing listening → honest offline mode: arm the cold-start
  ///     reconnect loop (so a late-starting router is picked up) and hand
  ///     the user to [RouterSetupScreen] instead of pretending a local node
  ///     exists.
  Future<void> _initSamBridge() async {
    final sam = ref.read(samServiceProvider);

    _updateStatus('Probing SAM Bridge (127.0.0.1:7656)…');
    await Future<void>.delayed(const Duration(milliseconds: 600));

    final reachable = await sam.probeReachability();
    if (!mounted) return;

    if (reachable == SamReachability.reachable) {
      await _connectFullStack(sam);
      return;
    }
    _enterOfflineMode(sam);
  }

  /// Connect → session → inbound chain. Only called after the probe confirmed
  /// something is listening on the SAM port.
  Future<void> _connectFullStack(SamService sam) async {
    _updateStatus('Connecting to SAM Bridge…');
    final connected = await sam.connectAndHandshake();
    if (!mounted) return;

    if (!connected) {
      // Probe raced a router shutdown — fall back to the offline path.
      _enterOfflineMode(sam);
      return;
    }

    _updateStatus('Establishing Garlic STREAM Session…');
    final sessionOk = await sam.createSession('KamuiSession');
    if (!mounted) return;

    if (sessionOk) {
      // createSession() already armed the inbound listener; this explicit
      // re-arm is idempotent and keeps boot status honest.
      _updateStatus('Arming Inbound Garlic Listener…');
      await sam.startInbound();
      if (!mounted) return;
      _updateStatus('Garlic Destination Acquired • Active');
    } else {
      _updateStatus('Handshake OK • Session Standby Mode');
    }

    setState(() => _isConnecting = false);
  }

  /// Honest offline path: no router answered the probe. Arms the cold-start
  /// reconnect loop and shows [RouterSetupScreen]. The splash stays mounted
  /// beneath the (non-poppable) setup route so its callbacks remain valid.
  void _enterOfflineMode(SamService sam) {
    _updateStatus('Offline — No I2P Router Detected');
    sam.startReconnectLoop();

    Navigator.push(
      context,
      PageRouteBuilder(
        pageBuilder: (context, anim, secondaryAnim) => RouterSetupScreen(
          onRetry: _retryFromSetup,
          onContinueOffline: _enterTheVoid,
        ),
        transitionDuration: const Duration(milliseconds: 600),
        transitionsBuilder: (context, anim, secondaryAnim, child) =>
            FadeTransition(
          opacity: anim,
          child: child,
        ),
      ),
    );
  }

  /// RETRY from [RouterSetupScreen]: probe → connect → session → inbound.
  /// On success routes through the lock gate and clears the whole stack.
  /// On failure the setup screen stays up — its live status line keeps
  /// showing the background auto-retry state.
  Future<void> _retryFromSetup() async {
    final sam = ref.read(samServiceProvider);

    final reachable = await sam.probeReachability();
    if (!mounted || reachable != SamReachability.reachable) return;

    final connected = await sam.connectAndHandshake();
    if (!mounted || !connected) return;

    final sessionOk = await sam.createSession('KamuiSession');
    if (!mounted || !sessionOk) return;
    await sam.startInbound();
    if (!mounted) return;

    await _enterTheVoid();
  }

  void _updateStatus(String msg) {
    if (mounted) {
      setState(() => _currentStatus = msg);
    }
  }

  @override
  void dispose() {
    _fadeController.dispose();
    super.dispose();
  }

  /// Routes through the lock gate: when the shield is armed, the user must
  /// authenticate before reaching any chat surface.
  ///
  /// Clears the entire navigation stack (splash + any RouterSetupScreen on
  /// top of it), so no dead entry surface survives underneath.
  Future<void> _enterTheVoid() async {
    final lockEnabled = await LockService().isLockEnabled();
    if (!mounted) return;
    Navigator.pushAndRemoveUntil(
      context,
      PageRouteBuilder(
        pageBuilder: (context, anim, secondaryAnim) =>
            lockEnabled ? const LockScreen() : const ChatListScreen(),
        transitionDuration: const Duration(milliseconds: 600),
        transitionsBuilder: (context, anim, secondaryAnim, child) =>
            FadeTransition(
          opacity: anim,
          child: child,
        ),
      ),
      (route) => false,
    );
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: voidBlack,
      body: HudBackground(
        child: SafeArea(
          child: FadeTransition(
            opacity: _fadeIn,
            child: Column(
              children: [
                const Spacer(flex: 2),

                // ── Logo + VortexRing ─────────────────────────────────────
                ScaleTransition(
                  scale: _titleScale,
                  child: Column(
                    children: [
                      // KAMUI title with gradient
                      ShaderMask(
                        shaderCallback: (bounds) => const LinearGradient(
                          colors: [vortexOrange, Color(0xFFFF6B35), cyberCyan],
                          stops: [0.0, 0.5, 1.0],
                          begin: Alignment.topLeft,
                          end:   Alignment.bottomRight,
                        ).createShader(bounds),
                        child: Text(
                          'KAMUI',
                          style: GoogleFonts.orbitron(
                            fontSize:    44,
                            fontWeight:  FontWeight.w900,
                            letterSpacing: 14,
                            color:       Colors.white,
                          ),
                        ),
                      ),

                      const SizedBox(height: 6),

                      Text(
                        'ENTER THE UNTOUCHABLE DIMENSION',
                        style: GoogleFonts.jetBrainsMono(
                          fontSize: 9,
                          color:    cyberCyan.withAlpha(120),
                          letterSpacing: 2.5,
                        ),
                      ),
                    ],
                  ),
                ),

                const SizedBox(height: 48),

                // VortexRing
                const VortexRing(size: KamuiConstants.vortexRingSizeLarge),

                const SizedBox(height: 40),

                // ── Dynamic live status text ─────────────────────────────
                AnimatedSwitcher(
                  duration: const Duration(milliseconds: 400),
                  transitionBuilder: (child, anim) => FadeTransition(
                    opacity: anim,
                    child: child,
                  ),
                  child: Row(
                    key: ValueKey(_currentStatus),
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      if (_isConnecting) ...[
                        SizedBox(
                          width:  12,
                          height: 12,
                          child: CircularProgressIndicator(
                            strokeWidth: 1.5,
                            color:       cyberCyan,
                          ),
                        ),
                        const SizedBox(width: 10),
                      ],
                      Text(
                        _currentStatus,
                        style: GoogleFonts.jetBrainsMono(
                          fontSize:    11,
                          color:       cyberCyan.withAlpha(180),
                          letterSpacing: 1.2,
                        ),
                      ),
                    ],
                  ),
                ),

                const Spacer(flex: 2),

                // ── CTA button ────────────────────────────────────────────
                Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 40),
                  child: KamuiButton(
                    label:     'ENTER THE VOID',
                    onPressed: _enterTheVoid,
                  ),
                ),

                const SizedBox(height: 24),

                // Version
                Text(
                  'v${KamuiConstants.appVersion} — I2P SAM ${KamuiConstants.samMaxVersion}',
                  style: GoogleFonts.jetBrainsMono(
                    fontSize: 9,
                    color:    textDim,
                    letterSpacing: 1,
                  ),
                ),

                const SizedBox(height: 24),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
