import 'package:flutter_local_notifications/flutter_local_notifications.dart';

/// Service for delivering native local notifications when encrypted I2P messages arrive.
class NotificationService {
  static final NotificationService _instance = NotificationService._internal();
  factory NotificationService() => _instance;
  NotificationService._internal();

  final FlutterLocalNotificationsPlugin _notificationsPlugin =
      FlutterLocalNotificationsPlugin();

  bool _isInitialized = false;

  /// Initializes local notification settings for Android, iOS, macOS, and Linux.
  Future<void> init() async {
    if (_isInitialized) return;

    const androidSettings = AndroidInitializationSettings('@mipmap/ic_launcher');
    const darwinSettings  = DarwinInitializationSettings(
      requestAlertPermission: true,
      requestBadgePermission: true,
      requestSoundPermission: true,
    );
    const linuxSettings   = LinuxInitializationSettings(
      defaultActionName: 'Open Kamui',
    );

    const initSettings = InitializationSettings(
      android: androidSettings,
      iOS:     darwinSettings,
      macOS:   darwinSettings,
      linux:   linuxSettings,
    );

    try {
      await _notificationsPlugin.initialize(
        initSettings,
        onDidReceiveNotificationResponse: (details) {
          // Future tap handling
        },
      );
      _isInitialized = true;
    } catch (_) {
      // Fallback on platform configuration error
    }
  }

  /// Displays a native notification for an incoming encrypted message.
  Future<void> showMessageNotification({
    required String senderName,
    required String messageText,
  }) async {
    if (!_isInitialized) await init();

    const androidDetails = AndroidNotificationDetails(
      'kamui_messages_channel',
      'Kamui Encrypted Messages',
      channelDescription: 'Notifications for incoming end-to-end encrypted I2P messages',
      importance: Importance.max,
      priority: Priority.high,
      showWhen: true,
    );

    const darwinDetails = DarwinNotificationDetails(
      presentAlert: true,
      presentBadge: true,
      presentSound: true,
    );

    const platformDetails = NotificationDetails(
      android: androidDetails,
      iOS:     darwinDetails,
      macOS:   darwinDetails,
    );

    try {
      await _notificationsPlugin.show(
        DateTime.now().millisecondsSinceEpoch.remainder(100000),
        '🔐 $senderName',
        messageText,
        platformDetails,
      );
    } catch (_) {
      // Gracefully ignore notification errors
    }
  }
}
