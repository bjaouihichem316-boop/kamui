import 'dart:async';
import 'dart:convert';
import 'dart:io';
import 'dart:typed_data';

import 'package:flutter_test/flutter_test.dart';
import 'package:kamui/services/sam_channel.dart';
import 'package:kamui/services/sam_service.dart';

// ═══════════════════════════════════════════════════════════════════════════
// Phase 6 — Ephemeral-port fallback for the SAM STREAM FORWARD listener.
//
// When 127.0.0.1:7657 is already in use (SocketException), the service must
// bind an OS-assigned ephemeral port (port 0) and pass THAT port in the
// STREAM FORWARD command — logging the fallback and emitting an observable
// status. ACCEPT mode stays untouched.
//
// Isolation style mirrors sam_inbound_test.dart (in-memory channel fakes).
// ═══════════════════════════════════════════════════════════════════════════

/// Fake byte channel playing the router side of the control socket.
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
      _controller.add(Uint8List.fromList(utf8.encode(text)));

  void _maybeRespond(String request) {
    String? reply;
    if (request.contains('HELLO VERSION')) {
      reply = 'HELLO REPLY RESULT=OK VERSION=3.3';
    } else if (request.contains('SESSION CREATE')) {
      reply = 'SESSION STATUS RESULT=OK DESTINATION=fakeDestKey123~abc';
    } else if (request.contains('STREAM FORWARD')) {
      reply = 'DIRECTION RESULT=OK';
    }
    if (reply == null) return;
    scheduleMicrotask(() {
      if (!destroyed) routerSend('$reply\n');
    });
  }
}

/// Fake listener socket advertising a configurable bound [port].
class FakeServerChannel implements SamServerChannel {
  FakeServerChannel({required this.port});

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

/// Factory whose bind() behavior is scripted per requested port.
class ScriptedBindFactory implements SamChannelFactory {
  ScriptedBindFactory({this.failPorts = const <int>{}});

  /// Requested ports that throw SocketException (simulating "address in use").
  final Set<int> failPorts;
  final List<FakeServerChannel> servers = <FakeServerChannel>[];
  final List<(String, int)> bindAttempts = <(String, int)>[];

  /// Port advertised by successful ephemeral binds.
  int ephemeralPort = 54321;

  @override
  Future<SamChannel> connect(String host, int port, {Duration? timeout}) async {
    final channel = FakeChannel();
    return channel;
  }

  @override
  Future<SamServerChannel> bind(String host, int port) async {
    bindAttempts.add((host, port));
    if (failPorts.contains(port)) {
      throw SocketException('address already in use', port: port);
    }
    final boundPort = port == 0 ? ephemeralPort : port;
    final server = FakeServerChannel(port: boundPort);
    servers.add(server);
    return server;
  }
}

/// Boots a handshaked + session-established isolated service, capturing
/// statuses and logs from before the inbound listener arms.
Future<(SamService, ScriptedBindFactory, List<String>, List<Map<String, dynamic>>)>
    _bootstrap(ScriptedBindFactory factory) async {
  final service = SamService.isolated(channelFactory: factory);

  final statuses = <String>[];
  final logs = <Map<String, dynamic>>[];
  service.statusStream.listen((s) => statuses.add(s['status'] as String));
  service.logStream.listen(logs.add);

  expect(await service.connectAndHandshake(), isTrue,
      reason: 'fake HELLO handshake must succeed');
  expect(await service.createSession('testSession'), isTrue,
      reason: 'fake SESSION CREATE must succeed');
  await pumpEventQueue();
  return (service, factory, statuses, logs);
}

void main() {
  group('Sam FORWARD listener — ephemeral-port fallback', () {
    test('bind(7657) in use → FORWARD carries the ephemeral port from bind(0)',
        () async {
      final factory = ScriptedBindFactory(failPorts: {7657});
      final (service, _, statuses, logs) = await _bootstrap(factory);

      // Bind attempts: first the preferred port, then the ephemeral retry.
      expect(factory.bindAttempts, [
        ('127.0.0.1', 7657),
        ('127.0.0.1', 0),
      ]);

      // The FORWARD command on the control socket (mirrored into the data
      // log as '>>> …') must carry the port the successful bind(0) actually
      // assigned — never the busy 7657.
      final forwardCmds = logs
          .map((l) => l['message'] as String)
          .where((m) => m.startsWith('>>> STREAM FORWARD'))
          .toList();
      expect(forwardCmds, hasLength(1));
      expect(forwardCmds.single, contains('PORT=54321'));
      expect(forwardCmds.single, isNot(contains('PORT=7657')));
      expect(forwardCmds.single, contains('STREAM FORWARD ID=testSession'));
      expect(forwardCmds.single, contains('HOST=127.0.0.1'));
      expect(forwardCmds.single, contains('SILENT=false'));

      // Observable fallback signal precedes the success ack.
      expect(statuses, contains('inbound_port_fallback'));
      expect(statuses.indexOf('inbound_port_fallback'),
          lessThan(statuses.indexOf('inbound_ok')));

      // The fallback is logged loudly.
      expect(
        logs.any((l) =>
            l['type'] == 'warning' &&
            (l['message'] as String).contains('ephemeral')),
        isTrue,
        reason: 'fallback must be clearly logged',
      );
      expect(
        logs.any((l) =>
            l['type'] == 'info' &&
            (l['message'] as String).contains('ephemeral port 54321')),
        isTrue,
      );

      service.dispose();
    });

    test('preferred port free → PORT=7657 unchanged, no fallback status',
        () async {
      final factory = ScriptedBindFactory(); // nothing fails
      final (service, _, statuses, logs) = await _bootstrap(factory);

      expect(factory.bindAttempts, [('127.0.0.1', 7657)]);
      expect(factory.servers.single.port, 7657);

      final forwardCmds = logs
          .map((l) => l['message'] as String)
          .where((m) => m.startsWith('>>> STREAM FORWARD'))
          .toList();
      expect(forwardCmds.single, contains('PORT=7657'));

      expect(statuses, isNot(contains('inbound_port_fallback')));
      expect(statuses, contains('inbound_ok'));

      service.dispose();
    });

    test('both preferred AND ephemeral binds fail → inbound_failed, no crash',
        () async {
      final factory = ScriptedBindFactory(failPorts: {7657, 0});
      final (service, _, statuses, _) = await _bootstrap(factory);

      expect(factory.bindAttempts, [
        ('127.0.0.1', 7657),
        ('127.0.0.1', 0),
      ]);
      expect(statuses, contains('inbound_failed'),
          reason: 'fail-closed after both bind attempts fail');
      expect(statuses, isNot(contains('inbound_ok')));

      service.dispose();
    });
  });
}
