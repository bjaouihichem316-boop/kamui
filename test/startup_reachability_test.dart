import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

import 'package:fake_async/fake_async.dart';
import 'package:flutter/material.dart';
import 'package:flutter_riverpod/flutter_riverpod.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:kamui/core/constants.dart';
import 'package:kamui/core/providers.dart';
import 'package:kamui/core/theme.dart';
import 'package:kamui/screens/router_setup_screen.dart';
import 'package:kamui/services/sam_channel.dart';
import 'package:kamui/services/sam_service.dart';

// ═══════════════════════════════════════════════════════════════════════════
// In-memory SAM channel fakes (isolation style of sam_inbound_test).
// Duplicated per suite convention — test files share no private helpers.
// ═══════════════════════════════════════════════════════════════════════════

/// Fake byte channel standing in for a real socket.
class FakeChannel implements SamChannel {
  FakeChannel({this.autoRespond = true});

  final bool autoRespond;
  final StreamController<Uint8List> _controller =
      StreamController<Uint8List>.broadcast();
  final List<String> written = <String>[];
  bool destroyed = false;

  @override
  Stream<Uint8List> get dataStream => _controller.stream;

  @override
  void writeUtf8(String data) {
    written.add(data);
    if (autoRespond) _maybeRespond(data);
  }

  @override
  void destroy() {
    if (destroyed) return;
    destroyed = true;
    unawaited(_controller.close());
  }

  void routerSend(String text) =>
      _controller.add(Uint8List.fromList(text.codeUnits));

  void _maybeRespond(String request) {
    String? reply;
    if (request.contains('HELLO VERSION')) {
      reply = 'HELLO REPLY RESULT=OK VERSION=3.3';
    } else if (request.contains('SESSION CREATE')) {
      reply = 'SESSION STATUS RESULT=OK DESTINATION=fakeDestKey123~abc';
    } else if (request.contains('SESSION DESTROY')) {
      reply = 'SESSION STATUS RESULT=OK';
    } else if (request.contains('STREAM FORWARD')) {
      reply = 'DIRECTION RESULT=OK';
    } else if (request.contains('STREAM ACCEPT')) {
      reply = 'STREAM STATUS RESULT=OK';
    } else if (request.contains('STREAM CONNECT')) {
      reply = 'STREAM STATUS RESULT=OK';
    }
    if (reply == null) return;
    scheduleMicrotask(() {
      if (!destroyed) routerSend('$reply\n');
    });
  }
}

/// Fake listener socket whose connections are injected by the test.
class FakeServerChannel implements SamServerChannel {
  FakeServerChannel({this.port = 7657});

  @override
  final int port;

  final StreamController<SamChannel> _connections =
      StreamController<SamChannel>.broadcast(sync: true);
  bool closed = false;

  @override
  Stream<SamChannel> get connections => _connections.stream;

  @override
  Future<void> close() async {
    closed = true;
    await _connections.close();
  }

  void accept(FakeChannel channel) => _connections.add(channel);
}

/// Fake factory recording every connect()/bind() and simulating outages,
/// refusals, and hangs (for probe-timeout mapping).
class FakeFactory implements SamChannelFactory {
  final List<FakeChannel> connected = <FakeChannel>[];
  final List<FakeServerChannel> servers = <FakeServerChannel>[];
  bool failConnections = false;

  /// When true, connect() returns a future that never completes —
  /// simulates a black-holed host so only the caller-side timeout fires.
  bool hangConnections = false;

  int connectCount = 0;
  Duration? lastConnectTimeout;
  void Function()? onConnect;

  @override
  Future<SamChannel> connect(String host, int port, {Duration? timeout}) async {
    connectCount++;
    lastConnectTimeout = timeout;
    onConnect?.call();
    if (failConnections) {
      throw const SocketException('fake bridge refused connection');
    }
    if (hangConnections) {
      return Completer<SamChannel>().future;
    }
    final channel = FakeChannel();
    connected.add(channel);
    return channel;
  }

  @override
  Future<SamServerChannel> bind(String host, int port) async {
    final server = FakeServerChannel();
    servers.add(server);
    return server;
  }
}

void main() {
  setUpAll(() {
    // Never hit the network for font binaries during widget tests.
    GoogleFonts.config.allowRuntimeFetching = false;
  });

  group('SamReachability probe', () {
    test('1. successful TCP connect maps to reachable (and cleans up)',
        () async {
      final factory = FakeFactory();
      final service = SamService.isolated(channelFactory: factory);

      final result = await service.probeReachability();

      expect(result, SamReachability.reachable);
      expect(factory.connectCount, 1);
      expect(factory.connected.single.destroyed, isTrue,
          reason: 'probe must destroy its socket — no leaks');

      service.dispose();
    });

    test('2. connection refusal maps to unreachable', () async {
      final factory = FakeFactory()..failConnections = true;
      final service = SamService.isolated(channelFactory: factory);

      final result = await service.probeReachability();

      expect(result, SamReachability.unreachable);

      service.dispose();
    });

    test('3. hung connect times out and maps to unreachable', () {
      fakeAsync((async) {
        final factory = FakeFactory()..hangConnections = true;
        final service = SamService.isolated(channelFactory: factory);

        SamReachability? result;
        unawaited(service.probeReachability().then((r) => result = r));

        // Nothing connects before the budget expires…
        async.elapse(KamuiConstants.probeTimeout - const Duration(milliseconds: 100));
        expect(result, isNull);

        // …then the service-side timeout fires and maps to unreachable.
        async.elapse(const Duration(milliseconds: 200));
        expect(result, SamReachability.unreachable);

        service.dispose();
      });
    });

    test('4. probe uses the fast probe budget, not the full connect timeout',
        () async {
      final factory = FakeFactory();
      final service = SamService.isolated(channelFactory: factory);

      await service.probeReachability();

      expect(factory.lastConnectTimeout, KamuiConstants.probeTimeout);
      expect(factory.lastConnectTimeout, lessThan(KamuiConstants.connectTimeout));

      service.dispose();
    });
  });

  group('Cold-start reconnect loop', () {
    test('5. cold-start failure alone does NOT arm retries (gate intact)',
        () {
      fakeAsync((async) {
        final factory = FakeFactory()..failConnections = true;
        final service = SamService.isolated(channelFactory: factory);

        var coldStartOk = true;
        unawaited(service.connectAndHandshake().then((ok) => coldStartOk = ok));
        async.elapse(const Duration(milliseconds: 20));
        expect(coldStartOk, isFalse);

        // A router starting 10s later must NOT be picked up unless the
        // cold-start loop was explicitly armed (splash opts in).
        async.elapse(const Duration(seconds: 10));
        expect(factory.connectCount, 1,
            reason: 'no automatic retries without startReconnectLoop()');

        service.dispose();
      });
    });

    test('6. startReconnectLoop arms bounded backoff and recovers when '
        'the router appears late', () {
      fakeAsync((async) {
        final factory = FakeFactory();
        final service = SamService.isolated(channelFactory: factory);
        final statuses = <String>[];
        service.statusStream.listen((s) {
          statuses.add(s['status'] as String);
        });
        final attempts = <Duration>[];
        factory.onConnect = () => attempts.add(async.elapsed);

        // t=0: router down — cold-start connect fails.
        factory.failConnections = true;
        var coldStartOk = true;
        unawaited(service.connectAndHandshake().then((ok) => coldStartOk = ok));
        async.elapse(const Duration(milliseconds: 20));
        expect(coldStartOk, isFalse);
        final connectsBeforeLoop = factory.connectCount;

        // Splash arms the cold-start loop (idempotently, twice).
        service.startReconnectLoop();
        service.startReconnectLoop();

        // Only measure RETRY attempts from here on (the failed cold-start
        // connect at t=0 must not pollute the timing sample).
        attempts.clear();

        // Retry #1 lands inside [1.6s, 2.4s] → base 2s ± 20% jitter, fails.
        async.elapse(const Duration(seconds: 3));
        expect(factory.connectCount - connectsBeforeLoop, 1,
            reason: 'double-arm must not produce a double loop');
        expect(attempts.first,
            greaterThanOrEqualTo(const Duration(milliseconds: 1600)));
        expect(attempts.first,
            lessThanOrEqualTo(const Duration(milliseconds: 2400)));
        expect(statuses.where((s) => s == 'reconnecting'), isNotEmpty);

        // Router comes online before retry #2 (4s ± 20% after retry #1).
        factory.failConnections = false;
        async.elapse(const Duration(seconds: 5));
        expect(
            factory.connectCount - connectsBeforeLoop, greaterThanOrEqualTo(2));
        final gap = attempts[1] - attempts[0];
        expect(gap, greaterThanOrEqualTo(const Duration(milliseconds: 3200)));
        expect(gap, lessThanOrEqualTo(const Duration(milliseconds: 4800)));

        // Recovery completes over the fresh control channel.
        async.elapse(const Duration(milliseconds: 100));
        expect(service.isConnected, isTrue);
        expect(service.isSessionCreated, isTrue);

        service.dispose();
      });
    });

    test('7. dispose() cancels the cold-start loop permanently', () {
      fakeAsync((async) {
        final factory = FakeFactory()..failConnections = true;
        final service = SamService.isolated(channelFactory: factory);

        service.startReconnectLoop();
        async.elapse(const Duration(seconds: 3)); // retry #1 fired
        final countAtDispose = factory.connectCount;

        service.dispose();
        async.elapse(const Duration(minutes: 10));

        expect(factory.connectCount, countAtDispose,
            reason: 'no further retries after dispose');
      });
    });

    test('8. mid-session control loss STILL auto-arms the loop '
        '(existing behavior unchanged)', () {
      fakeAsync((async) {
        final factory = FakeFactory();
        final service = SamService.isolated(channelFactory: factory);
        final statuses = <String>[];
        service.statusStream.listen((s) {
          statuses.add(s['status'] as String);
        });

        var bootstrapped = false;
        unawaited(service.connectAndHandshake().then((ok) async {
          expect(ok, isTrue);
          bootstrapped = await service.createSession('sess');
        }));
        async.elapse(const Duration(milliseconds: 20));
        expect(bootstrapped, isTrue);

        // Unexpected control-socket death — NO explicit startReconnectLoop.
        factory.connected.first.destroy();
        async.elapse(const Duration(milliseconds: 20));
        expect(statuses.where((s) => s == 'reconnecting'), isNotEmpty,
            reason: '_hadLiveSession gate must keep arming on mid-session loss');

        service.dispose();
      });
    });
  });

  group('RouterSetupScreen', () {
    testWidgets('9. renders honest offline state and wires both callbacks',
        (tester) async {
      // Tall surface: the full setup column must be hit-testable.
      tester.view.physicalSize = const Size(800, 1400);
      tester.view.devicePixelRatio = 1.0;
      addTearDown(tester.view.reset);

      final factory = FakeFactory()..failConnections = true;
      final sam = SamService.isolated(channelFactory: factory);
      addTearDown(sam.dispose);

      var retryCalls = 0;
      var continueCalls = 0;

      await tester.pumpWidget(
        ProviderScope(
          overrides: [samServiceProvider.overrideWithValue(sam)],
          child: MaterialApp(
            theme: kamuiTheme,
            home: RouterSetupScreen(
              onRetry: () async => retryCalls++,
              onContinueOffline: () => continueCalls++,
            ),
          ),
        ),
      );
      // HudBackground's scan line repeats forever — plain pumps only,
      // never pumpAndSettle.
      await tester.pump();

      expect(find.text('No I2P Router Detected'), findsOneWidget);
      expect(find.text('RETRY'), findsOneWidget);
      expect(find.text('ENTER WITHOUT TRANSPORT'), findsOneWidget);
      expect(find.text('No I2P router — messages cannot send or receive.'),
          findsOneWidget);

      await tester.tap(find.text('RETRY'));
      await tester.pump();
      expect(retryCalls, 1);

      await tester.tap(find.text('ENTER WITHOUT TRANSPORT'));
      await tester.pump();
      expect(continueCalls, 1);
    });

    testWidgets('10. live status line reflects statusStream events',
        (tester) async {
      final factory = FakeFactory()..failConnections = true;
      final sam = SamService.isolated(channelFactory: factory);
      addTearDown(sam.dispose);

      await tester.pumpWidget(
        ProviderScope(
          overrides: [samServiceProvider.overrideWithValue(sam)],
          child: MaterialApp(
            theme: kamuiTheme,
            home: RouterSetupScreen(
              onRetry: () async {},
              onContinueOffline: () {},
            ),
          ),
        ),
      );
      await tester.pump();

      // Drive a REAL status emission through the failing handshake.
      unawaited(sam.connectAndHandshake());
      await tester.pump(const Duration(milliseconds: 50));

      expect(
        find.textContaining('OFFLINE'),
        findsWidgets,
        reason: "'disconnected' emission must surface on the live line",
      );
    });
  });
}
