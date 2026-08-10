import 'dart:ui';
import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:google_fonts/google_fonts.dart';
import '../core/theme.dart';
import '../core/providers.dart';
import '../models/contact.dart';
import '../models/conversation.dart';
import '../models/message.dart';
import '../widgets/hud_background.dart';
import '../widgets/kamui_button.dart';
import 'qr_scan_screen.dart';

/// Screen for adding a new contact via I2P B32 address or full Destination key.
///
/// Supports two input modes:
///   • **B32 address** — `xxxx.b32.i2p` (52-char base32 hostname)
///   • **Full Base64 destination** — 516+ character I2P key blob
///
/// On submit, creates a [Contact] + [Conversation] and persists both.
class AddFriendScreen extends ConsumerStatefulWidget {
  const AddFriendScreen({super.key});

  @override
  ConsumerState<AddFriendScreen> createState() => _AddFriendScreenState();
}

class _AddFriendScreenState extends ConsumerState<AddFriendScreen>
    with SingleTickerProviderStateMixin {
  final _formKey         = GlobalKey<FormState>();
  final _nameController  = TextEditingController();
  final _destController  = TextEditingController();

  bool _isLoading  = false;
  bool _showPreview = false;
  _InputMode _mode = _InputMode.b32;

  late AnimationController _scanAnim;
  late Animation<double> _fadeIn;

  @override
  void initState() {
    super.initState();
    _scanAnim = AnimationController(
      vsync: this,
      duration: const Duration(milliseconds: 700),
    )..forward();
    _fadeIn = CurvedAnimation(parent: _scanAnim, curve: Curves.easeOutCubic);

    _destController.addListener(_onDestChanged);
  }

  @override
  void dispose() {
    _nameController.dispose();
    _destController.dispose();
    _scanAnim.dispose();
    super.dispose();
  }

  void _onDestChanged() {
    final text  = _destController.text.trim();
    final isB32 = text.toLowerCase().endsWith('.b32.i2p') || RegExp(r'^[a-z2-7]{52}$').hasMatch(text.toLowerCase());
    setState(() {
      _mode        = isB32 ? _InputMode.b32 : _InputMode.fullDest;
      _showPreview = text.length >= 10;
    });
  }

  Future<void> _pasteFromClipboard() async {
    final data = await Clipboard.getData('text/plain');
    if (data?.text != null) {
      _destController.text = data!.text!.trim();
    }
  }

  Future<void> _submit() async {
    if (!_formKey.currentState!.validate()) return;
    setState(() => _isLoading = true);

    await Future<void>.delayed(const Duration(milliseconds: 800)); // simulate handshake

    final name    = _nameController.text.trim();
    final dest    = _destController.text.trim();
    final initial = name.isNotEmpty ? name[0].toUpperCase() : '?';
    final id      = 'c_${DateTime.now().millisecondsSinceEpoch}';
    final convId  = 'conv_$id';

    final contact = Contact(
      id:            id,
      name:          name,
      destination:   dest,
      avatarInitial: initial,
      status:        ContactStatus.building,
    );

    final welcomeMsg = Message(
      id:             'msg_${DateTime.now().millisecondsSinceEpoch}',
      conversationId: convId,
      text:           '🔐 Secure channel opened with $name. Tunnel building…',
      timestamp:      DateTime.now(),
      isSent:         false,
    );

    final conversation = Conversation(
      id:          convId,
      contact:     contact,
      lastMessage: welcomeMsg,
      unreadCount: 1,
    );

    try {
      // Persist contact + conversation to SQLite.
      await ref
          .read(conversationsProvider.notifier)
          .addAndPersist(conversation);

      if (mounted) {
        setState(() => _isLoading = false);
        Navigator.pop(context);

        ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(
            backgroundColor: panelDark,
            behavior:        SnackBarBehavior.floating,
            shape:           RoundedRectangleBorder(
              borderRadius: BorderRadius.circular(10),
              side:         BorderSide(color: emeraldGlow.withAlpha(80)),
            ),
            content: Row(
              children: [
                Icon(Icons.check_circle_outline, color: emeraldGlow, size: 18),
                const SizedBox(width: 10),
                Text(
                  '$name added — tunnel initializing.',
                  style: GoogleFonts.jetBrainsMono(color: textBright, fontSize: 12),
                ),
              ],
            ),
          ),
        );
      }
    } catch (e) {
      if (mounted) {
        setState(() => _isLoading = false);
        _showError('Failed to save contact: $e');
      }
    }
  }

  void _showError(String msg) {
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(
        backgroundColor: panelDark,
        behavior:        SnackBarBehavior.floating,
        shape:           RoundedRectangleBorder(
          borderRadius: BorderRadius.circular(10),
          side:         BorderSide(color: Colors.redAccent.withAlpha(80)),
        ),
        content: Row(
          children: [
            const Icon(Icons.error_outline, color: Colors.redAccent, size: 18),
            const SizedBox(width: 10),
            Expanded(
              child: Text(
                msg,
                style: GoogleFonts.jetBrainsMono(color: textBright, fontSize: 12),
              ),
            ),
          ],
        ),
      ),
    );
  }

  // ── Validators ─────────────────────────────────────────────────────────────

  String? _validateName(String? v) {
    if (v == null || v.trim().isEmpty) return 'Enter a display name';
    if (v.trim().length < 2) return 'Name must be ≥ 2 characters';
    return null;
  }

  String? _validateDest(String? v) {
    if (v == null || v.trim().isEmpty) return 'Paste an I2P address or Destination key';
    final val = v.trim();
    final isB32 = val.toLowerCase().endsWith('.b32.i2p') ||
        RegExp(r'^[a-z2-7]{52}$').hasMatch(val.toLowerCase());
    // Full destination: base64url 516+ chars
    final isFull = val.length >= 516 && RegExp(r'^[A-Za-z0-9+/=~-]+$').hasMatch(val);
    if (!isB32 && !isFull) {
      return 'Enter a valid B32 address (xxx.b32.i2p) or\nfull Base64 Destination key (≥516 chars)';
    }
    return null;
  }

  // ── Build ──────────────────────────────────────────────────────────────────

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: voidBlack,
      body: HudBackground(
        child: SafeArea(
          child: FadeTransition(
            opacity: _fadeIn,
            child: Column(
              children: [
                _buildHeader(),
                Expanded(
                  child: SingleChildScrollView(
                    padding: const EdgeInsets.fromLTRB(24, 8, 24, 40),
                    child: Form(
                      key: _formKey,
                      child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          const SizedBox(height: 8),
                          _buildInfoBox(),
                          const SizedBox(height: 28),
                          _buildSectionLabel('DISPLAY NAME'),
                          const SizedBox(height: 10),
                          _buildNameField(),
                          const SizedBox(height: 24),
                          _buildSectionLabel('I2P ADDRESS / DESTINATION KEY'),
                          const SizedBox(height: 10),
                          _buildDestField(),
                          if (_showPreview) ...[
                            const SizedBox(height: 14),
                            _buildDestPreview(),
                          ],
                          const SizedBox(height: 36),
                          _isLoading ? _buildLoadingIndicator() : KamuiButton(
                            label:     'OPEN SECURE PORTAL',
                            onPressed: _submit,
                          ),
                          const SizedBox(height: 16),
                          SizedBox(
                            width: double.infinity,
                            child: OutlinedButton(
                              onPressed: () => Navigator.pop(context),
                              style: OutlinedButton.styleFrom(
                                foregroundColor: textMid,
                                side: BorderSide(color: textDim.withAlpha(80)),
                                padding: const EdgeInsets.symmetric(vertical: 16),
                                shape: RoundedRectangleBorder(
                                  borderRadius: BorderRadius.circular(6),
                                ),
                              ),
                              child: Text(
                                'CANCEL',
                                style: GoogleFonts.rajdhani(
                                  letterSpacing: 3,
                                  fontSize: 12,
                                  fontWeight: FontWeight.w600,
                                  color: textDim,
                                ),
                              ),
                            ),
                          ),
                        ],
                      ),
                    ),
                  ),
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }

  // ── Sub-Widgets ────────────────────────────────────────────────────────────

  Widget _buildHeader() {
    return Container(
      padding: const EdgeInsets.fromLTRB(20, 14, 16, 14),
      decoration: BoxDecoration(
        color: voidBlack.withAlpha(200),
        border: Border(
          bottom: BorderSide(color: vortexOrange.withAlpha(30), width: 0.5),
        ),
      ),
      child: Row(
        children: [
          GestureDetector(
            onTap: () => Navigator.pop(context),
            child: const Icon(Icons.arrow_back_ios_new, color: textBright, size: 18),
          ),
          const SizedBox(width: 16),
          ShaderMask(
            shaderCallback: (b) => const LinearGradient(
              colors: [vortexOrange, cyberCyan],
            ).createShader(b),
            child: Text(
              'OPEN PORTAL',
              style: GoogleFonts.orbitron(
                fontSize:    18,
                fontWeight:  FontWeight.w900,
                color:       Colors.white,
                letterSpacing: 5,
              ),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildInfoBox() {
    return ClipRRect(
      borderRadius: BorderRadius.circular(10),
      child: BackdropFilter(
        filter: ImageFilter.blur(sigmaX: 8, sigmaY: 8),
        child: Container(
          padding: const EdgeInsets.all(16),
          decoration: BoxDecoration(
            color:        cyberCyan.withAlpha(10),
            borderRadius: BorderRadius.circular(10),
            border:       Border.all(color: cyberCyan.withAlpha(30), width: 0.8),
          ),
          child: Row(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Icon(Icons.info_outline, color: cyberCyan, size: 16),
              const SizedBox(width: 12),
              Expanded(
                child: Text(
                  'Ask your contact to share their I2P B32 address '
                  '(*.b32.i2p) or full Destination key. '
                  'The channel is end-to-end encrypted before any data leaves your device.',
                  style: GoogleFonts.jetBrainsMono(
                    color: textMid,
                    fontSize: 11,
                    height:   1.65,
                  ),
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildSectionLabel(String label) {
    return Text(
      label,
      style: GoogleFonts.jetBrainsMono(
        fontSize: 10,
        color:    textDim,
        letterSpacing: 3,
      ),
    );
  }

  Widget _buildNameField() {
    return _HudTextField(
      controller:  _nameController,
      hint:        'e.g.  Malek, Kuro, Zero_Cool',
      icon:        Icons.person_outline,
      inputAction: TextInputAction.next,
      validator:   _validateName,
    );
  }

  Widget _buildDestField() {
    return Column(
      children: [
        _HudTextField(
          controller:  _destController,
          hint:        'Paste B32 address or full Destination key…',
          icon:        Icons.vpn_key_outlined,
          inputAction: TextInputAction.done,
          validator:   _validateDest,
          maxLines:    4,
          onSubmit:    (_) => _submit(),
        ),
        const SizedBox(height: 8),
        // Mode badge + paste button row
        Row(
          children: [
            _modeBadge(),
            const Spacer(),
            GestureDetector(
              onTap: () async {
                final scanned = await Navigator.push<String>(
                  context,
                  MaterialPageRoute(builder: (_) => const QrScanScreen()),
                );
                if (scanned != null && scanned.isNotEmpty) {
                  _destController.text = scanned;
                }
              },
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
                decoration: BoxDecoration(
                  color:        cyberCyan.withAlpha(15),
                  borderRadius: BorderRadius.circular(20),
                  border:       Border.all(color: cyberCyan.withAlpha(60)),
                ),
                child: Row(
                  children: [
                    Icon(Icons.qr_code_scanner_rounded, size: 12, color: cyberCyan),
                    const SizedBox(width: 6),
                    Text(
                      'SCAN QR',
                      style: GoogleFonts.jetBrainsMono(
                        fontSize: 9,
                        fontWeight: FontWeight.w700,
                        color:    cyberCyan,
                        letterSpacing: 1,
                      ),
                    ),
                  ],
                ),
              ),
            ),
            const SizedBox(width: 8),
            GestureDetector(
              onTap: _pasteFromClipboard,
              child: Container(
                padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 7),
                decoration: BoxDecoration(
                  color:        vortexOrange.withAlpha(15),
                  borderRadius: BorderRadius.circular(20),
                  border:       Border.all(color: vortexOrange.withAlpha(60)),
                ),
                child: Row(
                  children: [
                    Icon(Icons.content_paste_rounded, size: 12, color: vortexOrange),
                    const SizedBox(width: 6),
                    Text(
                      'PASTE',
                      style: GoogleFonts.jetBrainsMono(
                        fontSize: 9,
                        fontWeight: FontWeight.w700,
                        color:    vortexOrange,
                        letterSpacing: 1,
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ],
        ),
      ],
    );
  }

  Widget _modeBadge() {
    final isB32  = _mode == _InputMode.b32;
    final color  = isB32 ? emeraldGlow : neonPurple;
    final label  = isB32 ? 'B32 FORMAT' : 'FULL DESTINATION';
    final icon   = isB32 ? Icons.link : Icons.key_outlined;

    return AnimatedContainer(
      duration: const Duration(milliseconds: 200),
      padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
      decoration: BoxDecoration(
        color:        color.withAlpha(15),
        borderRadius: BorderRadius.circular(20),
        border:       Border.all(color: color.withAlpha(60)),
      ),
      child: Row(
        mainAxisSize: MainAxisSize.min,
        children: [
          Icon(icon, size: 11, color: color),
          const SizedBox(width: 6),
          Text(
            label,
            style: GoogleFonts.jetBrainsMono(
              fontSize: 9,
              fontWeight: FontWeight.w700,
              color:    color,
              letterSpacing: 1,
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildDestPreview() {
    final dest = _destController.text.trim();
    final preview = dest.length > 24
        ? '${dest.substring(0, 12)}…${dest.substring(dest.length - 8)}'
        : dest;

    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
      decoration: BoxDecoration(
        color:        panelDark,
        borderRadius: BorderRadius.circular(8),
        border:       Border.all(color: cyberCyan.withAlpha(20)),
      ),
      child: Row(
        children: [
          Icon(Icons.fingerprint, size: 14, color: cyberCyan.withAlpha(150)),
          const SizedBox(width: 10),
          Expanded(
            child: Text(
              preview,
              style: GoogleFonts.jetBrainsMono(
                fontSize: 11,
                color:    cyberCyan.withAlpha(160),
                letterSpacing: 0.5,
              ),
            ),
          ),
          Text(
            '${dest.length} chars',
            style: GoogleFonts.jetBrainsMono(fontSize: 9, color: textDim),
          ),
        ],
      ),
    );
  }

  Widget _buildLoadingIndicator() {
    return Container(
      width:  double.infinity,
      height: 56,
      decoration: BoxDecoration(
        color:        vortexOrange.withAlpha(15),
        borderRadius: BorderRadius.circular(6),
        border:       Border.all(color: vortexOrange.withAlpha(60)),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          SizedBox(
            width:  16,
            height: 16,
            child: CircularProgressIndicator(
              strokeWidth: 2,
              color:       vortexOrange,
            ),
          ),
          const SizedBox(width: 14),
          Text(
            'INITIALIZING TUNNEL…',
            style: GoogleFonts.rajdhani(
              fontSize:    13,
              fontWeight:  FontWeight.w700,
              color:       vortexOrange,
              letterSpacing: 3,
            ),
          ),
        ],
      ),
    );
  }
}

// ─── Enum ─────────────────────────────────────────────────────────────────────

enum _InputMode { b32, fullDest }

// ─── Reusable HUD Text Field ─────────────────────────────────────────────────

class _HudTextField extends StatelessWidget {
  final TextEditingController   controller;
  final String                  hint;
  final IconData                icon;
  final TextInputAction          inputAction;
  final FormFieldValidator<String>? validator;
  final int                     maxLines;
  final ValueChanged<String>?   onSubmit;

  const _HudTextField({
    required this.controller,
    required this.hint,
    required this.icon,
    required this.inputAction,
    this.validator,
    this.maxLines  = 1,
    this.onSubmit,
  });

  @override
  Widget build(BuildContext context) {
    return TextFormField(
      controller:       controller,
      validator:        validator,
      textInputAction:  inputAction,
      onFieldSubmitted: onSubmit,
      maxLines:         maxLines,
      style:            GoogleFonts.jetBrainsMono(
        color: textBright,
        fontSize: 13,
        height: 1.5,
      ),
      decoration: InputDecoration(
        hintText:    hint,
        hintStyle:   GoogleFonts.jetBrainsMono(color: textDim, fontSize: 12),
        prefixIcon:  Icon(icon, color: vortexOrange.withAlpha(160), size: 18),
        filled:      true,
        fillColor:   surfaceDark,
        contentPadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 14),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide:   BorderSide(color: cyberCyan.withAlpha(25)),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide:   BorderSide(color: cyberCyan.withAlpha(25)),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide:   BorderSide(color: cyberCyan.withAlpha(100), width: 1.5),
        ),
        errorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide:   const BorderSide(color: Colors.redAccent, width: 1),
        ),
        focusedErrorBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(10),
          borderSide:   const BorderSide(color: Colors.redAccent, width: 1.5),
        ),
        errorStyle: GoogleFonts.jetBrainsMono(
          color: Colors.redAccent,
          fontSize: 10,
        ),
      ),
    );
  }
}
