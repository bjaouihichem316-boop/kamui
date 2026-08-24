/// App-wide constants for Kamui.
/// Single source of truth for configuration values.
library;

class KamuiConstants {
  KamuiConstants._();

  // ─── App Identity ─────────────────────────────────────────────
  static const String appName     = 'KAMUI';
  static const String appVersion  = '1.0.0';
  static const String appTagline  = 'Enter the Untouchable Dimension.';

  // ─── SAM Bridge ───────────────────────────────────────────────
  static const String samHost         = '127.0.0.1';
  static const int    samPort         = 7656;
  static const String samMinVersion   = '3.0';
  static const String samMaxVersion   = '3.3';

  // ─── Timeouts ─────────────────────────────────────────────────
  static const Duration connectTimeout  = Duration(seconds: 5);
  static const Duration handshakeTimeout = Duration(seconds: 8);
  static const Duration sessionTimeout   = Duration(seconds: 10);
  static const Duration sendTimeout      = Duration(seconds: 15);

  // ─── UI Dimensions ────────────────────────────────────────────
  static const double vortexRingSizeLarge  = 160.0;
  static const double vortexRingSizeMedium = 120.0;
  static const double vortexRingSizeSmall  = 80.0;

  static const double borderRadiusCard   = 12.0;
  static const double borderRadiusButton = 6.0;
  static const double borderRadiusInput  = 24.0;
  static const double borderRadiusSheet  = 24.0;

  static const double hudGridSpacing  = 32.0;
  static const int    maxLogEntries   = 50;

  // ─── Animation Durations ──────────────────────────────────────
  static const Duration splashFadeDuration    = Duration(milliseconds: 1800);
  static const Duration dissolveAnimDuration  = Duration(milliseconds: 600);
  static const Duration pulseAnimDuration     = Duration(milliseconds: 1400);
  static const Duration vortexRotationDuration = Duration(milliseconds: 3200);
  static const Duration scanLineDuration       = Duration(milliseconds: 4000);

  // ─── Mock / Dev ───────────────────────────────────────────────
  /// Master switch for mock seed data. Only honored in debug builds
  /// (`kDebugMode`); release/profile builds never seed mock data.
  static const bool useMockData = true;
}
