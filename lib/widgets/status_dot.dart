import 'package:flutter/material.dart';
import '../core/theme.dart';
import '../core/constants.dart';

/// Pulsing animated status indicator dot with a neon glow shadow.
class StatusDot extends StatefulWidget {
  final Color color;
  final double size;
  final bool animate;

  const StatusDot({
    super.key,
    required this.color,
    this.size  = 8.0,
    this.animate = true,
  });

  @override
  State<StatusDot> createState() => _StatusDotState();
}

class _StatusDotState extends State<StatusDot>
    with SingleTickerProviderStateMixin {
  late AnimationController _controller;
  late Animation<double>   _pulse;

  @override
  void initState() {
    super.initState();
    _controller = AnimationController(
      vsync: this,
      duration: KamuiConstants.pulseAnimDuration,
    );
    _pulse = Tween<double>(begin: 0.3, end: 1.0).animate(
      CurvedAnimation(parent: _controller, curve: Curves.easeInOutSine),
    );
    if (widget.animate) _controller.repeat(reverse: true);
  }

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  @override
  Widget build(BuildContext context) {
    if (!widget.animate) {
      return _dot(1.0);
    }
    return AnimatedBuilder(
      animation: _pulse,
      builder: (_, _) => _dot(_pulse.value),
    );
  }

  Widget _dot(double alpha) {
    final a = (alpha * 255).toInt();
    return Container(
      width:  widget.size,
      height: widget.size,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: widget.color.withAlpha(a),
        boxShadow: [
          BoxShadow(
            color:       widget.color.withAlpha((alpha * 100).toInt()),
            blurRadius:  widget.size * 0.9,
            spreadRadius: widget.size * 0.15,
          ),
        ],
      ),
    );
  }
}

/// Returns the appropriate [StatusDot] color for a given status string.
Color statusColor(String status) {
  switch (status) {
    case 'active':
      return emeraldGlow;
    case 'building':
      return warningAmber;
    default:
      return textDim;
  }
}
