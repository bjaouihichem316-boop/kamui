import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

import '../core/theme.dart';

/// A Cyberpunk-styled glassmorphism chat bubble supporting TTL self-destruct timers.
class ChatBubble extends StatelessWidget {
  final String message;
  final String time;
  final bool isSent;
  final bool isEncrypted;
  final int? ttlSeconds;
  final DateTime? expiresAt;
  final double remainingFraction;

  /// True for outgoing messages whose SAM transmission failed — renders a
  /// warning glyph instead of the delivery checkmarks.
  final bool isFailed;

  /// Long-press handler (used to retry failed sends from the outbox).
  final VoidCallback? onRetry;

  const ChatBubble({
    super.key,
    required this.message,
    required this.time,
    this.isSent            = true,
    this.isEncrypted       = true,
    this.ttlSeconds,
    this.expiresAt,
    this.remainingFraction = 1.0,
    this.isFailed          = false,
    this.onRetry,
  });

  @override
  Widget build(BuildContext context) {
    final hasTtl = expiresAt != null;

    final bubble = Padding(
      padding: EdgeInsets.only(
        left:   isSent ? 56 : 16,
        right:  isSent ? 16 : 56,
        top:    3,
        bottom: 3,
      ),
      child: Align(
        alignment: isSent ? Alignment.centerRight : Alignment.centerLeft,
        child: ClipRRect(
          borderRadius: _borderRadius,
          child: BackdropFilter(
            filter: ImageFilter.blur(sigmaX: 10, sigmaY: 10),
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 11),
              decoration: BoxDecoration(
                color: isSent
                    ? vortexOrange.withAlpha(22)
                    : cyberCyan.withAlpha(14),
                borderRadius: _borderRadius,
                border: isSent ? _sentBorder : _receivedBorder,
                boxShadow: [
                  BoxShadow(
                    color: (isSent ? vortexOrange : cyberCyan).withAlpha(25),
                    blurRadius: 14,
                  ),
                ],
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                mainAxisSize: MainAxisSize.min,
                children: [
                  Text(
                    message,
                    style: const TextStyle(
                      color:    textBright,
                      fontSize: 14,
                      height:   1.45,
                    ),
                  ),
                  const SizedBox(height: 6),
                  Row(
                    mainAxisSize: MainAxisSize.min,
                    children: [
                      if (isEncrypted)
                        Padding(
                          padding: const EdgeInsets.only(right: 4),
                          child: Icon(
                            Icons.lock,
                            size:  9,
                            color: cyberCyan.withAlpha(130),
                          ),
                        ),
                      if (hasTtl) ...[
                        Icon(
                          Icons.timer_outlined,
                          size:  10,
                          color: warningAmber,
                        ),
                        const SizedBox(width: 3),
                        Text(
                          '${(ttlSeconds ?? 0)}s',
                          style: GoogleFonts.jetBrainsMono(
                            fontSize: 9,
                            color:    warningAmber,
                          ),
                        ),
                        const SizedBox(width: 6),
                      ],
                      Text(
                        time,
                        style: GoogleFonts.jetBrainsMono(
                          color:    textMid,
                          fontSize: 10,
                        ),
                      ),
                      if (isSent) ...[
                        const SizedBox(width: 4),
                        if (isFailed)
                          const Icon(
                            Icons.error_outline,
                            size:  11,
                            color: Colors.redAccent,
                          )
                        else
                          Icon(
                            Icons.done_all,
                            size:  10,
                            color: cyberCyan.withAlpha(140),
                          ),
                      ],
                    ],
                  ),

                  // Shrinking progress bar for self-destructing messages
                  if (hasTtl) ...[
                    const SizedBox(height: 6),
                    ClipRRect(
                      borderRadius: BorderRadius.circular(2),
                      child: LinearProgressIndicator(
                        value:           remainingFraction.clamp(0.0, 1.0),
                        minHeight:       2,
                        backgroundColor: Colors.white.withAlpha(15),
                        valueColor:      const AlwaysStoppedAnimation(warningAmber),
                      ),
                    ),
                  ],
                ],
              ),
            ),
          ),
        ),
      ),
    );

    // Long-press retry affordance for failed sends (outbox).
    if (onRetry == null) return bubble;
    return GestureDetector(onLongPress: onRetry, child: bubble);
  }

  BorderRadius get _borderRadius => BorderRadius.only(
    topLeft:     const Radius.circular(16),
    topRight:    const Radius.circular(16),
    bottomLeft:  isSent ? const Radius.circular(16) : const Radius.circular(4),
    bottomRight: isSent ? const Radius.circular(4)  : const Radius.circular(16),
  );

  Border get _sentBorder => Border.all(
    color: vortexOrange.withAlpha(90),
    width: 0.8,
  );

  Border get _receivedBorder => Border(
    left:   BorderSide(color: cyberCyan.withAlpha(130), width: 2),
    top:    BorderSide(color: cyberCyan.withAlpha(20),  width: 0.5),
    right:  BorderSide(color: cyberCyan.withAlpha(15),  width: 0.5),
    bottom: BorderSide(color: cyberCyan.withAlpha(15),  width: 0.5),
  );
}
