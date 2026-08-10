import 'dart:math';
import 'package:flutter/material.dart';
import '../core/theme.dart';
import '../core/constants.dart';

/// Animated dual-ring Cyberpunk HUD widget with particles and a glowing core.
///
/// Uses TWO [AnimationController]s:
///   • [_rotationController] — main ring rotation (3.2s loop)
///   • [_pulseController]    — core & halo pulse (1.4s reverse loop)
class VortexRing extends StatefulWidget {
  final double size;

  const VortexRing({super.key, this.size = KamuiConstants.vortexRingSizeLarge});

  @override
  State<VortexRing> createState() => _VortexRingState();
}

class _VortexRingState extends State<VortexRing>
    with TickerProviderStateMixin {
  late AnimationController _rotationController;
  late AnimationController _pulseController;

  late Animation<double> _rotation;
  late Animation<double> _pulse;

  @override
  void initState() {
    super.initState();

    _rotationController = AnimationController(
      vsync: this,
      duration: KamuiConstants.vortexRotationDuration,
    )..repeat();

    _pulseController = AnimationController(
      vsync: this,
      duration: KamuiConstants.pulseAnimDuration,
    )..repeat(reverse: true);

    _rotation = Tween<double>(begin: 0, end: 2 * pi).animate(
      CurvedAnimation(parent: _rotationController, curve: Curves.linear),
    );

    _pulse = Tween<double>(begin: 0.55, end: 1.0).animate(
      CurvedAnimation(parent: _pulseController, curve: Curves.easeInOutSine),
    );
  }

  @override
  void dispose() {
    _rotationController.dispose();
    _pulseController.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    return AnimatedBuilder(
      animation: Listenable.merge([_rotationController, _pulseController]),
      builder: (_, _) => SizedBox(
        width: widget.size,
        height: widget.size,
        child: CustomPaint(
          painter: _VortexRingPainter(
            rotation: _rotation.value,
            pulse:    _pulse.value,
          ),
        ),
      ),
    );
  }
}

class _VortexRingPainter extends CustomPainter {
  final double rotation;
  final double pulse;

  const _VortexRingPainter({required this.rotation, required this.pulse});

  @override
  void paint(Canvas canvas, Size size) {
    final center = Offset(size.width / 2, size.height / 2);
    final R      = size.width / 2; // max radius

    // ── Outer ambient glow halo ──────────────────────────────────────────
    canvas.drawCircle(
      center,
      R * 0.9,
      Paint()
        ..color = vortexOrange.withAlpha((pulse * 30).toInt())
        ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 22)
        ..style = PaintingStyle.stroke
        ..strokeWidth = 18,
    );

    // ── Tick marks (static decorative ring) ──────────────────────────────
    final tickPaint = Paint()
      ..color = cyberCyan.withAlpha(50)
      ..strokeWidth = 1;
    const ticks = 24;
    for (int i = 0; i < ticks; i++) {
      final a     = i * (2 * pi / ticks);
      final inner = R * 0.91;
      final outer = R * (i % 3 == 0 ? 0.99 : 0.95); // longer every 3rd
      canvas.drawLine(
        Offset(center.dx + cos(a) * inner, center.dy + sin(a) * inner),
        Offset(center.dx + cos(a) * outer, center.dy + sin(a) * outer),
        tickPaint,
      );
    }

    // ── Ring 1: Orange arc (clockwise) ───────────────────────────────────
    canvas.drawArc(
      Rect.fromCircle(center: center, radius: R * 0.82),
      rotation,
      pi * 1.65,  // 297° arc
      false,
      Paint()
        ..color = vortexOrange
        ..style = PaintingStyle.stroke
        ..strokeWidth = 2
        ..strokeCap = StrokeCap.round,
    );

    // ── Ring 2: Cyan arc (counter-clockwise, faster) ─────────────────────
    canvas.drawArc(
      Rect.fromCircle(center: center, radius: R * 0.63),
      -rotation * 1.4 + pi * 0.3,
      pi * 1.2,   // 216° arc
      false,
      Paint()
        ..color = cyberCyan
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1.5
        ..strokeCap = StrokeCap.round,
    );

    // ── Ring 3: Purple micro-arc (clockwise, 2× faster) ──────────────────
    canvas.drawArc(
      Rect.fromCircle(center: center, radius: R * 0.44),
      rotation * 2.0 + pi * 0.7,
      pi * 0.85,  // 153° arc
      false,
      Paint()
        ..color = neonPurple.withAlpha(180)
        ..style = PaintingStyle.stroke
        ..strokeWidth = 1.0
        ..strokeCap = StrokeCap.round,
    );

    // ── Particle dots trailing Ring 1 ────────────────────────────────────
    const particles = 7;
    for (int i = 0; i < particles; i++) {
      final angle  = rotation + (i * 2 * pi / (particles * 3));
      final px     = center.dx + cos(angle) * R * 0.82;
      final py     = center.dy + sin(angle) * R * 0.82;
      final alpha  = ((1 - i / particles) * 220).toInt();
      final radius = 2.5 - i * 0.3;
      if (radius <= 0) continue;

      // Glow
      canvas.drawCircle(
        Offset(px, py),
        radius + 2,
        Paint()
          ..color = vortexOrange.withAlpha((alpha * 0.35).toInt())
          ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 3),
      );
      // Solid
      canvas.drawCircle(
        Offset(px, py),
        radius,
        Paint()..color = vortexOrange.withAlpha(alpha),
      );
    }

    // ── Core glow ────────────────────────────────────────────────────────
    canvas.drawCircle(
      center,
      14 * pulse,
      Paint()
        ..color = vortexOrange.withAlpha((pulse * 90).toInt())
        ..maskFilter = const MaskFilter.blur(BlurStyle.normal, 10),
    );

    // ── Core solid ───────────────────────────────────────────────────────
    canvas.drawCircle(
      center,
      5.5 * pulse,
      Paint()..color = vortexOrange,
    );

    // ── Core white hot-spot ──────────────────────────────────────────────
    canvas.drawCircle(
      center,
      2,
      Paint()..color = Colors.white.withAlpha((pulse * 220).toInt()),
    );
  }

  @override
  bool shouldRepaint(covariant _VortexRingPainter old) =>
      old.rotation != rotation || old.pulse != pulse;
}
