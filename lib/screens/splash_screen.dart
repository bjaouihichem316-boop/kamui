import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:google_fonts/google_fonts.dart';

import '../core/constants.dart';
import '../core/providers.dart';
import '../core/theme.dart';
import '../widgets/hud_background.dart';
import '../widgets/kamui_button.dart';
import '../widgets/vortex_ring.dart';
import 'chat_list_screen.dart';

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

  Future<void> _initSamBridge() async {
    final sam = ref.read(samServiceProvider);

    _updateStatus('Connecting to SAM Bridge (127.0.0.1:7656)…');
    await Future<void>.delayed(const Duration(milliseconds: 600));

    final connected = await sam.connectAndHandshake();
    if (!mounted) return;

    if (connected) {
      _updateStatus('Establishing Garlic STREAM Session…');
      final sessionOk = await sam.createSession('KamuiSession');
      if (!mounted) return;

      if (sessionOk) {
        _updateStatus('Garlic Destination Acquired • Active');
      } else {
        _updateStatus('Handshake OK • Session Standby Mode');
      }
    } else {
      _updateStatus('SAM Offline • Running Local Node Mode');
    }

    setState(() => _isConnecting = false);
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

  void _enterTheVoid() {
    Navigator.pushReplacement(
      context,
      PageRouteBuilder(
        pageBuilder: (context, anim, secondaryAnim) => const ChatListScreen(),
        transitionDuration: const Duration(milliseconds: 600),
        transitionsBuilder: (context, anim, secondaryAnim, child) =>
            FadeTransition(
          opacity: anim,
          child: child,
        ),
      ),
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
