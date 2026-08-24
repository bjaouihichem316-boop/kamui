import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'core/providers.dart';
import 'core/theme.dart';
import 'screens/lock_screen.dart';
import 'screens/splash_screen.dart';
import 'services/crypto_service.dart';
import 'services/lock_service.dart';
import 'services/notification_service.dart';

Future<void> main() async {
  WidgetsFlutterBinding.ensureInitialized();

  // Force OLED-black status/nav bar
  SystemChrome.setSystemUIOverlayStyle(
    const SystemUiOverlayStyle(
      statusBarColor:           Colors.transparent,
      statusBarIconBrightness:  Brightness.light,
      systemNavigationBarColor: Color(0xFF000000),
      systemNavigationBarIconBrightness: Brightness.light,
    ),
  );

  // Initialize AES-256-GCM key & Notification Service
  await CryptoService().init();
  await NotificationService().init();

  runApp(
    const ProviderScope(
      child: KamuiApp(),
    ),
  );
}

class KamuiApp extends ConsumerStatefulWidget {
  const KamuiApp({super.key});

  @override
  ConsumerState<KamuiApp> createState() => _KamuiAppState();
}

class _KamuiAppState extends ConsumerState<KamuiApp>
    with WidgetsBindingObserver {
  final GlobalKey<NavigatorState> _navigatorKey = GlobalKey<NavigatorState>();

  /// Time allowed in background before the lock gate engages on resume.
  /// [Duration.zero] = immediate lock on ANY backgrounding (default policy).
  static const Duration autoLockTimeout = Duration.zero;

  DateTime? _backgroundedAt;

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    switch (state) {
      case AppLifecycleState.hidden || AppLifecycleState.paused:
        _backgroundedAt ??= DateTime.now();
      case AppLifecycleState.resumed:
        _lockIfExpired();
      default:
        break;
    }
  }

  /// Re-arms the lock gate when the app was backgrounded longer than
  /// [autoLockTimeout]. No-op when the shield is not enabled.
  void _lockIfExpired() {
    final backgroundedAt = _backgroundedAt;
    _backgroundedAt = null;
    if (backgroundedAt == null) return;
    if (DateTime.now().difference(backgroundedAt) < autoLockTimeout) return;
    _presentLockScreen();
  }

  Future<void> _presentLockScreen() async {
    if (!await LockService().isLockEnabled()) return;
    final nav = _navigatorKey.currentState;
    if (nav == null) return;
    // Clearing the stack guarantees no chat surface survives behind the gate;
    // unlocking routes to ChatListScreen, whose repository queries re-run the
    // TTL purge path (deleteExpiredMessages) as usual.
    nav.pushAndRemoveUntil(
      MaterialPageRoute(builder: (_) => const LockScreen()),
      (route) => false,
    );
  }

  @override
  Widget build(BuildContext context) {
    final selectedNeonTheme = ref.watch(neonThemeNotifierProvider);

    return MaterialApp(
      title:                      'Kamui',
      debugShowCheckedModeBanner: false,
      navigatorKey:               _navigatorKey,
      theme:                      buildKamuiTheme(selectedNeonTheme),
      home:                       const SplashScreen(),
    );
  }
}
