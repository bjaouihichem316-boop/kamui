import 'package:flutter/material.dart';
import '../core/theme.dart';
import '../core/constants.dart';

/// Animated HUD background with a subtle cyan grid and a slow vertical scan line.
///
/// Wrap any screen's Scaffold body with this widget for the cyberpunk aesthetic:
/// ```dart
/// body: HudBackground(child: YourContent()),
/// ```
class HudBackground extends StatefulWidget {
  final Widget child;

  const HudBackground({super.key, required this.child});

  @override
  State<HudBackground> createState() => _HudBackgroundState();
}

class _HudBackgroundState extends State<HudBackground>
    with SingleTickerProviderStateMixin {
  late AnimationController _scanController;
  late Animation<double>   _scanAnim;

  @override
  void initState() {
    super.initState();
    _scanController = AnimationController(
      vsync: this,
      duration: KamuiConstants.scanLineDuration,
    )..repeat();
    _scanAnim = Tween<double>(begin: 0.0, end: 1.0).animate(_scanController);
  }

  @override
  void dispose() {
    _scanController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return Stack(
      children: [
        // Grid — static, repaints never
        const RepaintBoundary(
          child: CustomPaint(
            painter: _GridPainter(),
            child: SizedBox.expand(),
          ),
        ),
        // Scan line — repaints on every animation frame
        AnimatedBuilder(
          animation: _scanAnim,
          builder: (_, _) => CustomPaint(
            painter: _ScanLinePainter(_scanAnim.value),
            child: const SizedBox.expand(),
          ),
        ),
        // Content
        widget.child,
      ],
    );
  }
}

// ── Grid Painter ──────────────────────────────────────────────────────────────

class _GridPainter extends CustomPainter {
  const _GridPainter();

  @override
  void paint(Canvas canvas, Size size) {
    final gridPaint = Paint()
      ..color = cyberCyan.withAlpha(9)  // ~3.5% opacity
      ..strokeWidth = 0.5;

    const spacing = KamuiConstants.hudGridSpacing;

    // Vertical lines
    for (double x = 0; x < size.width; x += spacing) {
      canvas.drawLine(Offset(x, 0), Offset(x, size.height), gridPaint);
    }
    // Horizontal lines
    for (double y = 0; y < size.height; y += spacing) {
      canvas.drawLine(Offset(0, y), Offset(size.width, y), gridPaint);
    }

    // Corner accent brackets
    final accentPaint = Paint()
      ..color = cyberCyan.withAlpha(30)
      ..strokeWidth = 1.5
      ..strokeCap = StrokeCap.square;
    const arm = 18.0;

    // Top-left
    canvas.drawLine(Offset.zero, const Offset(arm, 0), accentPaint);
    canvas.drawLine(Offset.zero, const Offset(0, arm), accentPaint);
    // Top-right
    canvas.drawLine(Offset(size.width, 0), Offset(size.width - arm, 0), accentPaint);
    canvas.drawLine(Offset(size.width, 0), Offset(size.width, arm), accentPaint);
    // Bottom-left
    canvas.drawLine(Offset(0, size.height), Offset(arm, size.height), accentPaint);
    canvas.drawLine(Offset(0, size.height), Offset(0, size.height - arm), accentPaint);
    // Bottom-right
    canvas.drawLine(Offset(size.width, size.height), Offset(size.width - arm, size.height), accentPaint);
    canvas.drawLine(Offset(size.width, size.height), Offset(size.width, size.height - arm), accentPaint);
  }

  @override
  bool shouldRepaint(covariant CustomPainter _) => false;
}

// ── Scan Line Painter ─────────────────────────────────────────────────────────

class _ScanLinePainter extends CustomPainter {
  final double progress;
  const _ScanLinePainter(this.progress);

  @override
  void paint(Canvas canvas, Size size) {
    final y = progress * size.height;
    final bandHeight = size.height * 0.08;

    canvas.drawRect(
      Rect.fromLTWH(0, y - bandHeight, size.width, bandHeight * 2),
      Paint()
        ..shader = LinearGradient(
          begin: Alignment.topCenter,
          end:   Alignment.bottomCenter,
          colors: [
            cyberCyan.withAlpha(0),
            cyberCyan.withAlpha(18),
            cyberCyan.withAlpha(9),
            cyberCyan.withAlpha(0),
          ],
          stops: const [0.0, 0.45, 0.6, 1.0],
        ).createShader(Rect.fromLTWH(0, y - bandHeight, size.width, bandHeight * 2)),
    );
  }

  @override
  bool shouldRepaint(covariant _ScanLinePainter old) => old.progress != progress;
}
