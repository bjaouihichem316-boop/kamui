import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../core/theme.dart';

/// Primary CTA button used throughout Kamui.
/// Full-width by default, with a neon glow shadow.
class KamuiButton extends StatelessWidget {
  final String label;
  final VoidCallback? onPressed;
  final Color color;
  final bool fullWidth;

  const KamuiButton({
    super.key,
    required this.label,
    this.onPressed,
    this.color     = vortexOrange,
    this.fullWidth = true,
  });

  @override
  Widget build(BuildContext context) {
    final btn = GestureDetector(
      onTap: onPressed,
      child: AnimatedContainer(
        duration: const Duration(milliseconds: 150),
        padding: const EdgeInsets.symmetric(vertical: 18),
        decoration: BoxDecoration(
          color: onPressed != null ? color : color.withAlpha(80),
          borderRadius: BorderRadius.circular(6),
          boxShadow: onPressed != null
              ? [
                  BoxShadow(
                    color:       color.withAlpha(100),
                    blurRadius:  20,
                    spreadRadius: 1,
                    offset:      const Offset(0, 4),
                  ),
                  BoxShadow(
                    color:       color.withAlpha(40),
                    blurRadius:  40,
                    spreadRadius: 2,
                  ),
                ]
              : [],
          border: Border.all(
            color: onPressed != null ? color.withAlpha(160) : Colors.transparent,
            width: 0.5,
          ),
        ),
        child: Center(
          child: Text(
            label,
            style: GoogleFonts.rajdhani(
              fontSize:    14,
              fontWeight:  FontWeight.w700,
              color:       onPressed != null ? Colors.white : Colors.white38,
              letterSpacing: 3.5,
            ),
          ),
        ),
      ),
    );

    return fullWidth ? SizedBox(width: double.infinity, child: btn) : btn;
  }
}
