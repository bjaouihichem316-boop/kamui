import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:qr_flutter/qr_flutter.dart';

import '../core/theme.dart';
import '../services/identity_key_service.dart';

/// Modal dialog displaying a Cyberpunk styled QR code for sharing I2P addresses.
///
/// The encoded QR payload is a v3 X3DH Handshake JSON containing the full
/// [PreKeyBundle]: IK_ed (Ed25519), IK_dh (X25519), SPK + SPK_sig, and OPK.
/// Scanning peers can immediately initiate an authenticated X3DH session.
class QrShareDialog extends StatelessWidget {
  final String destinationKey;
  final String title;

  const QrShareDialog({
    super.key,
    required this.destinationKey,
    this.title = 'X3DH HANDSHAKE QR',
  });

  @override
  Widget build(BuildContext context) {
    // generateHandshakePayload() returns a v3 JSON payload when the service
    // is initialized, or a v2 fallback payload otherwise.
    final qrPayload = IdentityKeyService().generateHandshakePayload(destinationKey);

    return AlertDialog(
      backgroundColor: panelDark,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: BorderSide(color: cyberCyan.withAlpha(80)),
      ),
      title: Row(
        children: [
          Icon(Icons.qr_code_2_rounded, color: cyberCyan, size: 22),
          const SizedBox(width: 10),
          Text(
            title,
            style: GoogleFonts.rajdhani(
              color:         textBright,
              fontSize:      16,
              fontWeight:    FontWeight.w700,
              letterSpacing: 2,
            ),
          ),
        ],
      ),
      content: Column(
        mainAxisSize: MainAxisSize.min,
        children: [
          Container(
            padding: const EdgeInsets.all(16),
            decoration: BoxDecoration(
              color:        Colors.white,
              borderRadius: BorderRadius.circular(12),
              border:       Border.all(color: cyberCyan, width: 2),
              boxShadow: [
                BoxShadow(color: cyberCyan.withAlpha(80), blurRadius: 16),
              ],
            ),
            child: QrImageView(
              data:     qrPayload,
              version:  QrVersions.auto,
              size:     200.0,
              eyeStyle: const QrEyeStyle(
                eyeShape: QrEyeShape.square,
                color:    Color(0xFF0B0B14),
              ),
              dataModuleStyle: const QrDataModuleStyle(
                dataModuleShape: QrDataModuleShape.square,
                color:           Color(0xFF00F0FF),
              ),
            ),
          ),
          const SizedBox(height: 14),
          Text(
            'Scan to pair — embeds X3DH PreKey Bundle (IK · SPK · OPK)',
            style: GoogleFonts.jetBrainsMono(color: textMid, fontSize: 11),
            textAlign: TextAlign.center,
          ),
        ],
      ),
      actions: [
        TextButton(
          onPressed: () => Navigator.pop(context),
          child: Text(
            'CLOSE',
            style: GoogleFonts.rajdhani(color: cyberCyan, fontSize: 13, letterSpacing: 1),
          ),
        ),
      ],
    );
  }
}
