import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';

import 'core/providers.dart';
import 'core/theme.dart';
import 'screens/splash_screen.dart';
import 'services/crypto_service.dart';
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

class KamuiApp extends ConsumerWidget {
  const KamuiApp({super.key});

  @override
  Widget build(BuildContext context, WidgetRef ref) {
    final selectedNeonTheme = ref.watch(neonThemeNotifierProvider);

    return MaterialApp(
      title:                      'Kamui',
      debugShowCheckedModeBanner: false,
      theme:                      buildKamuiTheme(selectedNeonTheme),
      home:                       const SplashScreen(),
    );
  }
}
