import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import '../core/theme.dart';
import '../services/crypto_service.dart';
import '../services/database_service.dart';
import '../services/lock_service.dart';
import '../widgets/hud_background.dart';
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
    if (mounted) setState(() => _canBiometric = available);
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

    // 1. Check Primary PIN
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

    // If default dev PIN "1337" or no PIN set yet
    if (pin == '1337' || !(await _lockService.isLockEnabled())) {
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
              _buildPinDots(),
              const Spacer(),
              _buildKeypad(),
              const SizedBox(height: 24),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildPinDots() {
    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: List.generate(4, (i) {
        final filled = i < _enteredPin.length;
        return Container(
          margin: const EdgeInsets.symmetric(horizontal: 8),
          width:  14,
          height: 14,
          decoration: BoxDecoration(
            shape:  BoxShape.circle,
            color:  filled ? vortexOrange : surfaceDark,
            border: Border.all(
              color: filled ? vortexOrange : cyberCyan.withAlpha(40),
              width: 1.5,
            ),
            boxShadow: filled
                ? [BoxShadow(color: vortexOrange.withAlpha(100), blurRadius: 10)]
                : [],
          ),
        );
      }),
    );
  }

  Widget _buildKeypad() {
    return Column(
      children: [
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [_keyBtn('1'), _keyBtn('2'), _keyBtn('3')],
        ),
        const SizedBox(height: 14),
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [_keyBtn('4'), _keyBtn('5'), _keyBtn('6')],
        ),
        const SizedBox(height: 14),
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [_keyBtn('7'), _keyBtn('8'), _keyBtn('9')],
        ),
        const SizedBox(height: 14),
        Row(
          mainAxisAlignment: MainAxisAlignment.center,
          children: [
            _actionBtn(
              icon: Icons.fingerprint,
              color: _canBiometric ? cyberCyan : textDim,
              onTap: _canBiometric ? _authenticateBiometrics : null,
            ),
            _keyBtn('0'),
            _actionBtn(
              icon: Icons.backspace_outlined,
              color: textMid,
              onTap: _onBackspace,
            ),
          ],
        ),
      ],
    );
  }

  Widget _keyBtn(String val) {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 12),
      width:  68,
      height: 68,
      child: OutlinedButton(
        onPressed: () => _onKeyPress(val),
        style: OutlinedButton.styleFrom(
          shape: const CircleBorder(),
          side: BorderSide(color: cyberCyan.withAlpha(30)),
          backgroundColor: surfaceDark,
        ),
        child: Text(
          val,
          style: GoogleFonts.orbitron(
            fontSize:   22,
            fontWeight: FontWeight.w700,
            color:      textBright,
          ),
        ),
      ),
    );
  }

  Widget _actionBtn({
    required IconData icon,
    required Color color,
    VoidCallback? onTap,
  }) {
    return Container(
      margin: const EdgeInsets.symmetric(horizontal: 12),
      width:  68,
      height: 68,
      child: IconButton(
        onPressed: onTap,
        icon: Icon(icon, color: color, size: 24),
      ),
    );
  }
}
