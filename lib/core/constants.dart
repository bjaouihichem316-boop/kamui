/// App-wide constants for Kamui.
/// Single source of truth for configuration values.
library;

/// Inbound transport backend for receiving I2P messages.
enum SamInboundMode {
  /// Primary: bind a local ServerSocket and hand its port to the router via
  /// `STREAM FORWARD`; each inbound I2P connection arrives as a loopback TCP
  /// connection whose first line is `FROM <destination>`.
  forward,

  /// Fallback: repeatedly arm `STREAM ACCEPT ID=<session> SILENT=false` on
  /// dedicated sockets; each accepted reply serves exactly one connection.
  accept,
}

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

  // ─── Inbound Transport ────────────────────────────────────────
  /// Inbound backend selection. FORWARD is primary; ACCEPT is the fallback
  /// for routers without FORWARD support.
  static const SamInboundMode samInboundMode = SamInboundMode.forward;

  /// Local TCP port bound by the FORWARD listener for router hand-off.
  static const int samForwardPort = 7657;

  /// Host bound by the FORWARD listener (router connects over loopback only).
  static const String samForwardHost = '127.0.0.1';

  // ─── Reconnect Backoff ────────────────────────────────────────
  /// First reconnect delay after unexpected control-socket loss.
  static const Duration reconnectInitialBackoff = Duration(seconds: 2);

  /// Hard cap for the exponential backoff sequence (2s → 4s → … → 60s).
  static const Duration reconnectMaxBackoff = Duration(seconds: 60);

  /// ±20% jitter applied to every backoff delay to avoid thundering herds.
  static const double reconnectJitterRatio = 0.2;

  // ─── Timeouts ─────────────────────────────────────────────────
  /// Fast startup reachability probe budget (before the full handshake).
  static const Duration probeTimeout = Duration(seconds: 1);

  static const Duration connectTimeout  = Duration(seconds: 5);
  static const Duration handshakeTimeout = Duration(seconds: 8);
  static const Duration sessionTimeout   = Duration(seconds: 10);
  static const Duration sendTimeout      = Duration(seconds: 15);

  // ─── Lock Screen ──────────────────────────────────────────────
  /// Time allowed in background before the lock gate engages on resume.
  /// [Duration.zero] = immediate lock on ANY backgrounding (default policy).
  /// Consumed by the lifecycle observer in `main.dart` (`_lockIfExpired`).
  /// This constant is the DEFAULT applied when no user selection is persisted.
  static const Duration autoLockTimeout = Duration.zero;

  /// SharedPreferences key persisting the selected auto-lock timeout
  /// (index into `AutoLockOption.values`). When unset, [autoLockTimeout]
  /// above is the effective policy.
  static const String autoLockTimeoutPrefsKey = 'kamui_auto_lock_timeout_index';

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
  /// Master switch for mock seed data (personas, conversations, messages).
  ///
  /// Honored ONLY in debug builds: the Phase-0 gate lives in
  /// `core/providers.dart` (`_mockSeedingEnabled = useMockData && kDebugMode`),
  /// so release/profile builds never seed mock identities or conversations
  /// regardless of this flag. This constant gates UI seed data only — it has
  /// no effect on SAM transport, crypto, or persistence behavior.
  static const bool useMockData = true;

  /// Debug-only universal unlock PIN for the lock screen so developers are
  /// never locked out during development. Call sites MUST guard with
  /// `kDebugMode` — this is tree-shaken out of release builds.
  static const String devUnlockPin = '000000';

  /// SharedPreferences key persisting the selected neon theme index.
  /// Referenced by [DatabaseService.nuke] so a duress wipe leaves no
  /// preference residue.
  static const String themePrefsKey = 'kamui_neon_theme_index';
}
