import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:fake_async/fake_async.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:kamui/core/constants.dart';
import 'package:kamui/services/sam_channel.dart';
import 'package:kamui/services/sam_service.dart';

// ═══════════════════════════════════════════════════════════════════════════
// In-memory SAM channel fakes (isolation style of e2e_wire_handshake_test)
// ═══════════════════════════════════════════════════════════════════════════

/// Fake byte channel standing in for a real socket. When [autoRespond] is on,
/// it plays the router side: every SAM command written by the service gets a
/// deferred OK reply (deferred so the service's listener attaches first).
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

  /// Test side: push raw bytes to the app as if the router sent them.
  void routerSend(String text) => routerSendBytes(utf8.encode(text));

  void routerSendBytes(List<int> bytes) =>
      _controller.add(Uint8List.fromList(bytes));

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

  /// Bound port reported back to the service (ephemeral-bind simulations
  /// construct with the OS-assigned port they want to advertise).
  @override
  final int port;

  // Synchronous delivery: accept() attaches the service's connection handler
  // before the test can push bytes into the accepted channel.
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

/// Fake factory recording every connect()/bind() and simulating outages.
class FakeFactory implements SamChannelFactory {
  final List<FakeChannel> connected = <FakeChannel>[];
  final List<FakeServerChannel> servers = <FakeServerChannel>[];
  bool failConnections = false;
  int connectCount = 0;
  void Function()? onConnect;

  @override
  Future<SamChannel> connect(String host, int port, {Duration? timeout}) async {
    connectCount++;
    onConnect?.call();
    if (failConnections) {
      throw const SocketException('fake bridge refused connection');
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

/// Boots a fully handshaked + session-established isolated service.
Future<(SamService, FakeFactory)> _bootstrap({
  SamInboundMode mode = SamInboundMode.forward,
}) async {
  final factory = FakeFactory();
  final service = SamService.isolated(channelFactory: factory)
    ..inboundMode = mode;
  expect(await service.connectAndHandshake(), isTrue,
      reason: 'fake HELLO handshake must succeed');
  expect(await service.createSession('testSession'), isTrue,
      reason: 'fake SESSION CREATE must succeed');
  await pumpEventQueue();
  return (service, factory);
}

/// Waits until the ACCEPT loop has armed its [ordinal]-th dedicated socket.
Future<FakeChannel> _waitForArmedAcceptChannel(
  FakeFactory factory, {
  int ordinal = 1,
}) async {
  final deadline = DateTime.now().add(const Duration(seconds: 5));
  while (DateTime.now().isBefore(deadline)) {
    final armed = factory.connected
        .where((c) => c.written.any((w) => w.contains('STREAM ACCEPT')))
        .toList();
    if (armed.length >= ordinal) return armed[ordinal - 1];
    await Future<void>.delayed(const Duration(milliseconds: 1));
  }
  fail('ACCEPT channel #$ordinal was never armed');
}

void main() {
  group('Sam Inbound Transport — FORWARD mode (primary)', () {
    test('1. FROM-tagged inbound payload is dispatched to incomingMessageStream',
        () async {
      final (service, factory) = await _bootstrap();

      // FORWARD command issued against the control socket after SESSION CREATE.
      final control = factory.connected.first;
      expect(
          control.written.any((w) => w.startsWith('STREAM FORWARD ID=')),
          isTrue);
      expect(control.written.last,
          contains('PORT=${KamuiConstants.samForwardPort}'));
      expect(control.written.last, contains('SILENT=false'));

      final emissions = <Map<String, String>>[];
      final sub = service.incomingMessageStream.listen(emissions.add);

      final server = factory.servers.single;
      final conn = FakeChannel(autoRespond: false);
      server.accept(conn);
      conn.routerSend('FROM aliceDestinationXyz\n');
      conn.routerSend('kamui_v4:h:n:c\n');
      await pumpEventQueue();

      expect(emissions, [
        {'from': 'aliceDestinationXyz', 'payload': 'kamui_v4:h:n:c'},
      ]);

      sub.cancel();
      service.dispose();
    });

    test('2. connection without a valid FROM line is dropped and logged',
        () async {
      final (service, factory) = await _bootstrap();
      final logs = <Map<String, dynamic>>[];
      final logSub = service.logStream.listen(logs.add);

      final emissions = <Map<String, String>>[];
      final sub = service.incomingMessageStream.listen(emissions.add);

      final conn = FakeChannel(autoRespond: false);
      factory.servers.single.accept(conn);
      conn.routerSend('GARBAGE not-a-from-line\n');
      conn.routerSend('kamui_v4:x:y:z\n');
      await pumpEventQueue();

      expect(emissions, isEmpty, reason: 'payload without FROM must not route');
      expect(conn.destroyed, isTrue, reason: 'invalid connection is dropped');
      expect(
        logs.any((l) =>
            l['type'] == 'warning' &&
            (l['message'] as String).contains('FROM')),
        isTrue,
        reason: 'drop must be logged',
      );

      logSub.cancel();
      sub.cancel();
      service.dispose();
    });

    test('3. partial TCP writes are accumulated into one payload', () async {
      final (service, factory) = await _bootstrap();

      final emissions = <Map<String, String>>[];
      final sub = service.incomingMessageStream.listen(emissions.add);

      final conn = FakeChannel(autoRespond: false);
      factory.servers.single.accept(conn);
      conn.routerSend('FROM peerDest\n');
      await pumpEventQueue();
      conn.routerSendBytes(utf8.encode('kamui_v4:head'));
      await pumpEventQueue();
      conn.routerSendBytes(utf8.encode('er:nonce:cipherbody\n'));
      await pumpEventQueue();

      expect(emissions.single['from'], 'peerDest');
      expect(emissions.single['payload'], 'kamui_v4:header:nonce:cipherbody');

      sub.cancel();
      service.dispose();
    });

    test('4. two sequential inbound connections are both dispatched', () async {
      final (service, factory) = await _bootstrap();

      final emissions = <Map<String, String>>[];
      final sub = service.incomingMessageStream.listen(emissions.add);

      final server = factory.servers.single;

      final c1 = FakeChannel(autoRespond: false);
      server.accept(c1);
      c1.routerSend('FROM destA\nmsgA_from_a\n');
      await pumpEventQueue();
      c1.destroy();

      final c2 = FakeChannel(autoRespond: false);
      server.accept(c2);
      c2.routerSend('FROM destB\nmsgB_from_b\n');
      await pumpEventQueue();

      expect(emissions, [
        {'from': 'destA', 'payload': 'msgA_from_a'},
        {'from': 'destB', 'payload': 'msgB_from_b'},
      ]);

      sub.cancel();
      service.dispose();
    });

    test('5. control-socket loss triggers bounded backoff retries then recovery',
        () {
      fakeAsync((async) {
        final factory = FakeFactory();
        final service = SamService.isolated(channelFactory: factory);
        final statuses = <String>[];
        service.statusStream.listen((s) {
          statuses.add(s['status'] as String);
        });

        final attempts = <Duration>[];
        factory.onConnect = () => attempts.add(async.elapsed);

        var bootstrapped = false;
        unawaited(service.connectAndHandshake().then((ok) async {
          expect(ok, isTrue);
          bootstrapped = await service.createSession('sess');
        }));
        async.elapse(const Duration(milliseconds: 20));
        expect(bootstrapped, isTrue);

        // Unexpected control-socket death.
        factory.connectCount = 0;
        attempts.clear();
        factory.failConnections = true;
        factory.connected.first.destroy();
        async.elapse(const Duration(milliseconds: 20));
        expect(statuses.where((s) => s == 'disconnected'), isNotEmpty);
        expect(statuses.where((s) => s == 'reconnecting'), isNotEmpty);

        // Retry #1 lands inside [1.6s, 2.4s] → base 2s ± 20% jitter, fails.
        async.elapse(const Duration(seconds: 3));
        expect(factory.connectCount, 1);
        expect(attempts.first,
            greaterThanOrEqualTo(const Duration(milliseconds: 1600)));
        expect(attempts.first,
            lessThanOrEqualTo(const Duration(milliseconds: 2400)));

        // Retry #2 lands inside [3.2s, 4.8s] after retry #1 → 4s ± 20%.
        factory.failConnections = false;
        async.elapse(const Duration(seconds: 5));
        expect(factory.connectCount, greaterThanOrEqualTo(2));
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

    test('7a. dispose() closes the FORWARD ServerSocket cleanly', () async {
      final (service, factory) = await _bootstrap();
      final server = factory.servers.single;

      service.dispose();
      await pumpEventQueue();

      expect(server.closed, isTrue);
      expect(factory.connected.first.destroyed, isTrue);
    });
  });

  group('Sam Inbound Transport — ACCEPT mode (fallback)', () {
    test('6a. FROM-tagged payload dispatched via STREAM ACCEPT socket',
        () async {
      final (service, factory) =
          await _bootstrap(mode: SamInboundMode.accept);

      final emissions = <Map<String, String>>[];
      final sub = service.incomingMessageStream.listen(emissions.add);

      final acceptChan = await _waitForArmedAcceptChannel(factory);
      expect(acceptChan.written.any((w) => w.contains('HELLO VERSION')), isTrue);
      expect(acceptChan.written.last, contains('STREAM ACCEPT ID=testSession'));
      expect(acceptChan.written.last, contains('SILENT=false'));

      acceptChan.routerSend('FROM bobDestination\nkamui_v4:a:b:c\n');
      await pumpEventQueue();

      expect(emissions, [
        {'from': 'bobDestination', 'payload': 'kamui_v4:a:b:c'},
      ]);

      sub.cancel();
      service.dispose();
    });

    test('6b. connection without FROM line dropped in ACCEPT mode', () async {
      final (service, factory) =
          await _bootstrap(mode: SamInboundMode.accept);

      final emissions = <Map<String, String>>[];
      final sub = service.incomingMessageStream.listen(emissions.add);

      final acceptChan = await _waitForArmedAcceptChannel(factory);
      acceptChan.routerSend('NOTFROM junk\nkamui_v4:x:y:z\n');
      await pumpEventQueue();

      expect(emissions, isEmpty);
      expect(acceptChan.destroyed, isTrue);

      sub.cancel();
      service.dispose();
    });

    test('6c. partial writes assembled in ACCEPT mode', () async {
      final (service, factory) =
          await _bootstrap(mode: SamInboundMode.accept);

      final emissions = <Map<String, String>>[];
      final sub = service.incomingMessageStream.listen(emissions.add);

      final acceptChan = await _waitForArmedAcceptChannel(factory);
      acceptChan.routerSend('FromIgnored\n'); // consumed as invalid → drop
      await pumpEventQueue();

      // Loop re-arms a fresh socket after the rejected connection.
      final chan2 = await _waitForArmedAcceptChannel(factory, ordinal: 2);
      chan2.routerSend('FROM carol\nkamui_v4:he');
      await pumpEventQueue();
      chan2.routerSend('ader:n:c\n');
      await pumpEventQueue();

      expect(emissions.single['from'], 'carol');
      expect(emissions.single['payload'], 'kamui_v4:header:n:c');

      sub.cancel();
      service.dispose();
    });

    test('6d. two sequential ACCEPT sockets each serve one connection',
        () async {
      final (service, factory) =
          await _bootstrap(mode: SamInboundMode.accept);

      final emissions = <Map<String, String>>[];
      final sub = service.incomingMessageStream.listen(emissions.add);

      final chan1 = await _waitForArmedAcceptChannel(factory);
      chan1.routerSend('FROM destA\nmsgA\n');
      await pumpEventQueue();
      chan1.destroy(); // consumed → loop re-arms

      final chan2 = await _waitForArmedAcceptChannel(factory, ordinal: 2);
      chan2.routerSend('FROM destB\nmsgB\n');
      await pumpEventQueue();

      expect(emissions, [
        {'from': 'destA', 'payload': 'msgA'},
        {'from': 'destB', 'payload': 'msgB'},
      ]);

      sub.cancel();
      service.dispose();
    });

    test('7b. dispose() halts the ACCEPT loop with no further connects',
        () async {
      final (service, factory) =
          await _bootstrap(mode: SamInboundMode.accept);
      await _waitForArmedAcceptChannel(factory);

      final connectsAtDispose = factory.connectCount;
      service.dispose();
      await pumpEventQueue();
      await Future<void>.delayed(const Duration(milliseconds: 50));

      expect(factory.connected.first.destroyed, isTrue);
      expect(factory.connectCount, connectsAtDispose,
          reason: 'ACCEPT loop must stop scheduling after dispose');
    });
  });
}
