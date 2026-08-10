import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

// ═══════════════════════════════════════════════════════════════════════════
// KAMUI COLOR PALETTE — Cyberpunk / Dark Futuristic HUD
// ═══════════════════════════════════════════════════════════════════════════

// ── Void Backgrounds ───────────────────────────────────────────────────────
const Color voidBlack   = Color(0xFF000000); // Pure void — scaffold bg
const Color abyss       = Color(0xFF050508); // Deep space
const Color panelDark   = Color(0xFF0B0B14); // Cards / panels
const Color surfaceDark = Color(0xFF11111D); // Inputs / surfaces

// ── Neon Accents ───────────────────────────────────────────────────────────
const Color vortexOrange = Color(0xFFFF4500); // Brand orange
const Color cyberCyan    = Color(0xFF00F0FF); // Primary neon (enhanced)
const Color neonPurple   = Color(0xFFBD00FF); // Secondary neon
const Color emeraldGlow  = Color(0xFF00FF88); // Success / positive
const Color warningAmber = Color(0xFFFFB800); // Warning

// ── Text Hierarchy ─────────────────────────────────────────────────────────
const Color textBright = Color(0xFFE8E8FF); // Primary text (slight blue tint)
const Color textMid    = Color(0xFF7878A0); // Secondary / label text
const Color textDim    = Color(0xFF3A3A60); // Hints / placeholders

// ── Legacy aliases ─────────────────────────────────────────────────────────
const Color chidoriCyan    = cyberCyan;
const Color stealthGrey    = panelDark;
const Color dimensionBlack = voidBlack;

// ═══════════════════════════════════════════════════════════════════════════
// NEON THEMES
// ═══════════════════════════════════════════════════════════════════════════

enum NeonTheme { cyberOrange, matrixGreen, voidPurple, electricCyan }

extension NeonThemeX on NeonTheme {
  String get label {
    switch (this) {
      case NeonTheme.cyberOrange:  return 'Cyber Orange';
      case NeonTheme.matrixGreen:  return 'Matrix Green';
      case NeonTheme.voidPurple:   return 'Void Purple';
      case NeonTheme.electricCyan: return 'Electric Cyan';
    }
  }

  Color get primaryColor {
    switch (this) {
      case NeonTheme.cyberOrange:  return const Color(0xFFFF4500);
      case NeonTheme.matrixGreen:  return const Color(0xFF00FF88);
      case NeonTheme.voidPurple:   return const Color(0xFFBD00FF);
      case NeonTheme.electricCyan: return const Color(0xFF00F0FF);
    }
  }

  Color get secondaryColor {
    switch (this) {
      case NeonTheme.cyberOrange:  return const Color(0xFF00F0FF);
      case NeonTheme.matrixGreen:  return const Color(0xFF00F0FF);
      case NeonTheme.voidPurple:   return const Color(0xFFFF4500);
      case NeonTheme.electricCyan: return const Color(0xFFBD00FF);
    }
  }
}

// ═══════════════════════════════════════════════════════════════════════════
// THEME BUILDER
// ═══════════════════════════════════════════════════════════════════════════

ThemeData buildKamuiTheme([NeonTheme theme = NeonTheme.cyberOrange]) {
  final primary   = theme.primaryColor;
  final secondary = theme.secondaryColor;

  return ThemeData(
    brightness: Brightness.dark,
    scaffoldBackgroundColor: voidBlack,
    primaryColor: primary,

    colorScheme: ColorScheme.dark(
      primary:     primary,
      secondary:   secondary,
      tertiary:    neonPurple,
      surface:     panelDark,
      onPrimary:   Colors.white,
      onSecondary: voidBlack,
      onSurface:   textBright,
      error:       const Color(0xFFFF3B3B),
      onError:     Colors.white,
    ),

    appBarTheme: AppBarTheme(
      backgroundColor: voidBlack,
      foregroundColor: textBright,
      elevation: 0,
      scrolledUnderElevation: 0,
      centerTitle: false,
      iconTheme: const IconThemeData(color: textBright, size: 22),
      titleTextStyle: GoogleFonts.rajdhani(
        fontSize: 20,
        fontWeight: FontWeight.w700,
        color: textBright,
        letterSpacing: 3,
      ),
    ),

    cardTheme: CardThemeData(
      color: panelDark,
      elevation: 0,
      shape: RoundedRectangleBorder(
        borderRadius: const BorderRadius.all(Radius.circular(12)),
        side: BorderSide(color: Colors.white.withAlpha(12), width: 0.5),
      ),
    ),

    elevatedButtonTheme: ElevatedButtonThemeData(
      style: ElevatedButton.styleFrom(
        backgroundColor: primary,
        foregroundColor: Colors.white,
        padding: const EdgeInsets.symmetric(horizontal: 32, vertical: 16),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
        elevation: 0,
        shadowColor: Colors.transparent,
        textStyle: GoogleFonts.rajdhani(
          fontSize: 14,
          fontWeight: FontWeight.w700,
          letterSpacing: 3,
        ),
      ),
    ),

    outlinedButtonTheme: OutlinedButtonThemeData(
      style: OutlinedButton.styleFrom(
        foregroundColor: textMid,
        side: BorderSide(color: primary.withAlpha(80)),
        padding: const EdgeInsets.symmetric(horizontal: 24, vertical: 14),
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(6)),
        textStyle: GoogleFonts.rajdhani(
          fontSize: 13,
          fontWeight: FontWeight.w600,
          letterSpacing: 2,
        ),
      ),
    ),

    textButtonTheme: TextButtonThemeData(
      style: TextButton.styleFrom(
        foregroundColor: textMid,
        textStyle: GoogleFonts.rajdhani(
          fontSize: 12,
          fontWeight: FontWeight.w600,
          letterSpacing: 1,
        ),
      ),
    ),

    inputDecorationTheme: InputDecorationTheme(
      filled: true,
      fillColor: surfaceDark,
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(24),
        borderSide: BorderSide(color: secondary.withAlpha(25)),
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(24),
        borderSide: BorderSide(color: secondary.withAlpha(25)),
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(24),
        borderSide: BorderSide(color: secondary.withAlpha(100), width: 1.5),
      ),
      hintStyle: const TextStyle(color: textDim, fontSize: 13),
      contentPadding: const EdgeInsets.symmetric(horizontal: 20, vertical: 14),
    ),

    textTheme: TextTheme(
      displayLarge: GoogleFonts.orbitron(
        color: textBright,
        fontWeight: FontWeight.w900,
      ),
      displayMedium: GoogleFonts.orbitron(
        color: textBright,
        fontWeight: FontWeight.w700,
      ),
      titleLarge: GoogleFonts.rajdhani(
        color: textBright,
        fontWeight: FontWeight.w700,
        fontSize: 20,
        letterSpacing: 2,
      ),
      titleMedium: GoogleFonts.rajdhani(
        color: textBright,
        fontWeight: FontWeight.w600,
        fontSize: 16,
        letterSpacing: 1,
      ),
      bodyLarge: const TextStyle(color: textBright, fontSize: 15, height: 1.5),
      bodyMedium: const TextStyle(color: textMid, fontSize: 13, height: 1.4),
      bodySmall: const TextStyle(color: textDim, fontSize: 11),
      labelSmall: GoogleFonts.jetBrainsMono(
        color: textDim,
        fontSize: 10,
        letterSpacing: 0.5,
      ),
    ),

    dividerTheme: DividerThemeData(
      color: Colors.white.withAlpha(12),
      thickness: 0.5,
      space: 0,
    ),

    dialogTheme: DialogThemeData(
      backgroundColor: panelDark,
      elevation: 24,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(16),
        side: BorderSide(color: primary.withAlpha(60)),
      ),
      titleTextStyle: GoogleFonts.rajdhani(
        color: textBright,
        fontSize: 16,
        fontWeight: FontWeight.w700,
        letterSpacing: 2,
      ),
      contentTextStyle: GoogleFonts.jetBrainsMono(
        color: textMid,
        fontSize: 12,
        height: 1.6,
      ),
    ),

    bottomSheetTheme: const BottomSheetThemeData(
      backgroundColor: Colors.transparent,
      modalBackgroundColor: Colors.transparent,
      elevation: 0,
    ),

    floatingActionButtonTheme: FloatingActionButtonThemeData(
      backgroundColor: primary,
      foregroundColor: Colors.white,
      elevation: 0,
      highlightElevation: 0,
    ),
  );
}

final ThemeData kamuiTheme = buildKamuiTheme(NeonTheme.cyberOrange);
