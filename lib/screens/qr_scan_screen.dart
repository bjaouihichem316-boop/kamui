import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

import '../core/theme.dart';
import '../widgets/hud_background.dart';

/// Camera QR Code scanner screen to capture a peer's Destination Key or B32 address.
class QrScanScreen extends StatefulWidget {
  const QrScanScreen({super.key});

  @override
  State<QrScanScreen> createState() => _QrScanScreenState();
}

class _QrScanScreenState extends State<QrScanScreen> {
  final MobileScannerController _controller = MobileScannerController();
  bool _hasScanned = false;

  @override
  void dispose() {
    _controller.dispose();
    super.dispose();
  }

  void _onDetect(BarcodeCapture capture) {
    if (_hasScanned) return;
    final barcode = capture.barcodes.firstOrNull;
    if (barcode != null && barcode.rawValue != null) {
      final code = barcode.rawValue!.trim();
      if (code.isNotEmpty) {
        _hasScanned = true;
        Navigator.pop(context, code);
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: voidBlack,
      body: HudBackground(
        child: SafeArea(
          child: Column(
            children: [
              _buildHeader(),
              Expanded(
                child: Stack(
                  alignment: Alignment.center,
                  children: [
                    MobileScanner(
                      controller: _controller,
                      onDetect:   _onDetect,
                    ),

                    // Cyberpunk HUD target reticle
                    Container(
                      width:  250,
                      height: 250,
                      decoration: BoxDecoration(
                        border: Border.all(color: cyberCyan, width: 2),
                        borderRadius: BorderRadius.circular(16),
                        boxShadow: [
                          BoxShadow(color: cyberCyan.withAlpha(50), blurRadius: 20),
                        ],
                      ),
                    ),

                    Positioned(
                      bottom: 40,
                      child: Container(
                        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                        decoration: BoxDecoration(
                          color:        panelDark.withAlpha(200),
                          borderRadius: BorderRadius.circular(20),
                          border:       Border.all(color: cyberCyan.withAlpha(60)),
                        ),
                        child: Text(
                          'ALIGN QR CODE INSIDE TARGET RETICLE',
                          style: GoogleFonts.jetBrainsMono(
                            fontSize: 10, color: cyberCyan, letterSpacing: 1.5,
                          ),
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildHeader() {
    return Container(
      padding: const EdgeInsets.fromLTRB(20, 14, 16, 14),
      decoration: BoxDecoration(
        color: voidBlack.withAlpha(200),
        border: Border(
          bottom: BorderSide(color: cyberCyan.withAlpha(20), width: 0.5),
        ),
      ),
      child: Row(
        children: [
          GestureDetector(
            onTap: () => Navigator.pop(context),
            child: const Icon(Icons.arrow_back_ios_new, color: textBright, size: 18),
          ),
          const SizedBox(width: 16),
          Text(
            'SCAN PEER QR CODE',
            style: GoogleFonts.orbitron(
              fontSize:    16,
              fontWeight:  FontWeight.w900,
              color:       Colors.white,
              letterSpacing: 3,
            ),
          ),
        ],
      ),
    );
  }
}
