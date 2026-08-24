import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import '../core/theme.dart';

/// Circular cyberpunk PIN keypad — shared by [LockScreen] and the shield
/// setup sheet. Styling mirrors lock_screen.dart's original keypad.
class PinKeypad extends StatelessWidget {
  const PinKeypad({
    super.key,
    required this.onDigit,
    required this.onBackspace,
    this.onBiometric,
  });

  /// Called with the pressed digit ('0'–'9').
  final ValueChanged<String> onDigit;

  final VoidCallback onBackspace;

  /// Biometric action; when null the fingerprint slot renders as an
  /// invisible placeholder to preserve grid alignment.
  final VoidCallback? onBiometric;

  @override
  Widget build(BuildContext context) {
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
              color: onBiometric != null ? cyberCyan : textDim,
              onTap: onBiometric,
            ),
            _keyBtn('0'),
            _actionBtn(
              icon: Icons.backspace_outlined,
              color: textMid,
              onTap: onBackspace,
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
        onPressed: () => onDigit(val),
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

/// Row of glowing PIN-entry dots — shared lock-screen styling.
class PinDots extends StatelessWidget {
  const PinDots({
    super.key,
    required this.filledCount,
    this.dotCount = 6,
  });

  /// How many leading dots are filled.
  final int filledCount;

  /// Total dots rendered.
  final int dotCount;

  @override
  Widget build(BuildContext context) {
    return Row(
      mainAxisAlignment: MainAxisAlignment.center,
      children: List.generate(dotCount, (i) {
        final filled = i < filledCount;
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
}
