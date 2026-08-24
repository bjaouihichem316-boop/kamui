import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import '../core/constants.dart';
import '../core/theme.dart';
import '../services/crypto_service.dart';
import '../services/database_service.dart';
import '../services/lock_service.dart';
import '../widgets/hud_background.dart';
import '../widgets/pin_keypad.dart';
import '../widgets/vortex_ring.dart';
import 'chat_list_screen.dart';
import 'decoy_feed_screen.dart';

/// Cyberpunk Lock Screen supporting Biometrics, PIN Verification, and Duress Panic Mode.
class LockScreen extends StatefulWidget {
  const LockScreen({super.key});

  @override
  State<LockScreen> createState() => _LockScreenState();
}

class _LockScreenState extends State<LockScreen> {
  final LockService _lockService = LockService();
  String _enteredPin = '';
  bool   _canBiometric = false;
  String _statusText   = 'AUTHENTICATION REQUIRED';
  bool   _isError      = false;

  @override
  void initState() {
    super.initState();
    _checkBiometrics();
  }

  Future<void> _checkBiometrics() async {
    final available = await _lockService.canAuthenticate();
    if (!mounted) return;
    setState(() => _canBiometric = available);
    // Offer the biometric prompt immediately when the gate appears.
    if (available) await _authenticateBiometrics();
  }

  Future<void> _authenticateBiometrics() async {
    final success = await _lockService.authenticateBiometrics();
    if (success && mounted) {
      _grantAccess();
    }
  }

  void _onKeyPress(String key) {
    if (_enteredPin.length >= 6) return;
    setState(() {
      _enteredPin += key;
      _isError = false;
    });

    if (_enteredPin.length == 4 || _enteredPin.length == 6) {
      _verifyPin();
    }
  }

  void _onBackspace() {
    if (_enteredPin.isNotEmpty) {
      setState(() => _enteredPin = _enteredPin.substring(0, _enteredPin.length - 1));
    }
  }

  Future<void> _verifyPin() async {
    final pin = _enteredPin;

    // 0. Dev escape hatch — debug builds only; never compiled into releases.
    if (kDebugMode && pin == KamuiConstants.devUnlockPin) {
      _grantAccess();
      return;
    }

    // 1. Check Primary PIN (PBKDF2 hash-then-compare).
    if (await _lockService.isNormalPin(pin)) {
      _grantAccess();
      return;
    }

    // 2. Check Duress PIN (Silent Panic Wipe!)
    if (await _lockService.isDuressPin(pin)) {
      await DatabaseService().nuke();
      await CryptoService().init();
      if (mounted) {
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(builder: (_) => const DecoyFeedScreen()),
        );
      }
      return;
    }

    // Defensive: shield not armed yet (e.g. TEST SHIELD preview before setup).
    if (!(await _lockService.isLockEnabled())) {
      _grantAccess();
      return;
    }

    // Invalid PIN
    setState(() {
      _isError     = true;
      _statusText  = 'ACCESS DENIED — INVALID KEY';
      _enteredPin = '';
    });
  }

  void _grantAccess() {
    Navigator.pushReplacement(
      context,
      PageRouteBuilder(
        pageBuilder:        (_, _, _) => const ChatListScreen(),
        transitionDuration: const Duration(milliseconds: 500),
        transitionsBuilder: (_, anim, _, child) => FadeTransition(
          opacity: anim,
          child:   child,
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
          child: Column(
            children: [
              const Spacer(),
              const VortexRing(size: 100),
              const SizedBox(height: 24),
              ShaderMask(
                shaderCallback: (b) => const LinearGradient(
                  colors: [vortexOrange, cyberCyan],
                ).createShader(b),
                child: Text(
                  'KAMUI SHIELD',
                  style: GoogleFonts.orbitron(
                    fontSize:    26,
                    fontWeight:  FontWeight.w900,
                    letterSpacing: 6,
                    color:       Colors.white,
                  ),
                ),
              ),
              const SizedBox(height: 10),
              Text(
                _statusText,
                style: GoogleFonts.jetBrainsMono(
                  fontSize: 10,
                  color:    _isError ? Colors.redAccent : cyberCyan.withAlpha(160),
                  letterSpacing: 2,
                ),
              ),
              const SizedBox(height: 32),
              PinDots(filledCount: _enteredPin.length, dotCount: 4),
              const Spacer(),
              PinKeypad(
                onDigit:     _onKeyPress,
                onBackspace: _onBackspace,
                onBiometric: _canBiometric ? _authenticateBiometrics : null,
              ),
              const SizedBox(height: 24),
            ],
          ),
        ),
      ),
    );
  }
}
