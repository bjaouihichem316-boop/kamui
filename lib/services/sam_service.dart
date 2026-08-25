import 'dart:async';
import 'dart:convert';
import 'dart:io' show SocketException;
import 'dart:math' as math;
import 'dart:typed_data';

import 'package:crypto/crypto.dart';

import '../core/constants.dart';
import 'sam_channel.dart';

/// Result of the fast SAM-bridge reachability probe.
enum SamReachability {
  /// Something accepted a TCP connection on the SAM host/port.
  reachable,

  /// Connection refused, failed, or timed out — treat as "no router".
  unreachable,
}

/// Singleton service implementing the I2P SAM v3.3 bridge protocol.
///
/// Features:
///   • Centralized incoming line dispatcher ([_incomingLines])
///   • Live stream sockets for outbound and inbound messages
///   • Inbound transport via SAM STREAM FORWARD (STREAM ACCEPT fallback)
///   • Bounded-backoff automatic reconnect on control-socket loss
///   • Real-time broadcast stream for incoming peer messages
///
///   • Fast reachability probe ([probeReachability]) for startup flow routing
///   • Cold-start reconnect arming ([startReconnectLoop]) so a router that
///     comes up after app launch is picked up automatically
///
/// The status/log streams carry ONLY state SAM v3 actually reports
/// (connection, session, destination, inbound listener). Router-level
/// metrics such as tunnel counts and bandwidth are NOT exposed by the
/// SAM v3.3 bridge protocol and are therefore never fabricated here.
class SamService {
  // ─── Singleton ────────────────────────────────────────────────────────
  static final SamService _instance = SamService._internal();
  factory SamService() => _instance;

  /// Isolated instance for tests — injects an in-memory [channelFactory].
  factory SamService.isolated({SamChannelFactory? channelFactory}) =>
      SamService._internal(channelFactory: channelFactory);

  SamService._internal({SamChannelFactory? channelFactory})
      : _channelFactory = channelFactory ?? const IoSamChannelFactory();

  // ─── Config ──────────────────────────────────────────────────────────
  String host = KamuiConstants.samHost;
  int    port = KamuiConstants.samPort;

  /// Inbound transport backend (FORWARD primary, ACCEPT fallback).
  SamInboundMode inboundMode = KamuiConstants.samInboundMode;

  // ─── State ───────────────────────────────────────────────────────────
  final SamChannelFactory _channelFactory;
  SamChannel? _controlSocket;
  String? sessionId;
  String? localDestinationKey;

  bool _isConnected      = false;
  bool _isSessionCreated = false;

  // ─── Inbound listener state ──────────────────────────────────────────
  SamServerChannel? _forwardServer;
  int               _inboundGeneration = 0;

  // ─── Reconnect state ─────────────────────────────────────────────────
  bool _disposed       = false;
  bool _hadLiveSession = false;
  bool _isReconnecting = false;
  final math.Random _jitterRandom = math.Random();

  bool get isConnected      => _isConnected;
  bool get isSessionCreated => _isSessionCreated;

  // ─── Internal socket read buffer ─────────────────────────────────────
  String _buffer = '';

  // ─── Central incoming line dispatcher ───────────────────────────────
  final StreamController<String> _incomingLines =
      StreamController<String>.broadcast();

  // ─── Incoming Message Stream ─────────────────────────────────────────
  final StreamController<Map<String, String>> _incomingMessageController =
      StreamController<Map<String, String>>.broadcast();
  Stream<Map<String, String>> get incomingMessageStream =>
      _incomingMessageController.stream;

  // ─── Public UI Streams ───────────────────────────────────────────────
  final StreamController<Map<String, dynamic>> _logController =
      StreamController<Map<String, dynamic>>.broadcast();
  Stream<Map<String, dynamic>> get logStream => _logController.stream;

  final StreamController<Map<String, dynamic>> _statusController =
      StreamController<Map<String, dynamic>>.broadcast();
  Stream<Map<String, dynamic>> get statusStream => _statusController.stream;

  // ═══════════════════════════════════════════════════════════════════════
  // PUBLIC API
  // ═══════════════════════════════════════════════════════════════════════

  /// Connects to the SAM bridge and performs the HELLO handshake.
  Future<bool> connectAndHandshake() async {
    _log('info', 'Connecting to SAM bridge at $host:$port…');
    _emitStatus('connecting');

    try {
      _controlSocket = await _channelFactory.connect(
        host,
        port,
        timeout: KamuiConstants.connectTimeout,
      );

      _attachSocketListener();

      _write(
          'HELLO VERSION MIN=${KamuiConstants.samMinVersion} MAX=${KamuiConstants.samMaxVersion}');

      final reply = await _awaitReply(
        (line) => line.contains('HELLO REPLY'),
        timeout: KamuiConstants.handshakeTimeout,
      );

      final result = reply != null && reply.contains('RESULT=OK');
      _isConnected = result;

      if (result) {
        _log('success', 'SAM handshake OK (v3.3)');
      } else {
        _log('error', 'SAM handshake failed (reply: ${reply ?? "timeout"})');
      }

      _emitStatus(result ? 'handshake_ok' : 'handshake_failed');
      return result;
    } on SocketException catch (e) {
      _log('error', 'SAM Connection refused ($host:$port): $e');
      _isConnected = false;
      _emitStatus('disconnected');
      return false;
    } catch (e) {
      _log('error', 'SAM Unexpected error: $e');
      _isConnected = false;
      _emitStatus('disconnected');
      return false;
    }
  }

  /// Fast startup probe: can anything accept a TCP connection on the SAM
  /// bridge host/port right now?
  ///
  /// Deliberately cheaper and faster than a full [connectAndHandshake] —
  /// no protocol bytes are written. Used by the splash flow to route between
  /// the normal connect path and router-setup onboarding BEFORE attempting
  /// the handshake.
  ///
  /// Args:
  ///   timeout: Connect budget; a timeout is mapped to [SamReachability
  ///       .unreachable], never propagated to the caller.
  ///
  /// Returns: [SamReachability.reachable] when a socket connects,
  /// [SamReachability.unreachable] otherwise.
  Future<SamReachability> probeReachability({
    Duration timeout = KamuiConstants.probeTimeout,
  }) async {
    _log('info', 'Probing SAM bridge reachability at $host:$port…');
    try {
      final channel = await _channelFactory
          .connect(host, port, timeout: timeout)
          .timeout(timeout);
      channel.destroy();
      _log('success', 'SAM bridge reachable ($host:$port)');
      return SamReachability.reachable;
    } on SocketException catch (e) {
      _log('warning', 'SAM bridge unreachable ($host:$port): $e');
      return SamReachability.unreachable;
    } on TimeoutException {
      _log('warning',
          'SAM bridge probe timed out after ${timeout.inMilliseconds}ms '
          '($host:$port) — treating as unreachable');
      return SamReachability.unreachable;
    } catch (e) {
      _log('warning', 'SAM bridge probe failed ($host:$port): $e');
      return SamReachability.unreachable;
    }
  }

  /// Creates a STREAM session with a transient I2P destination.
  Future<bool> createSession(String id) async {
    if (_controlSocket == null || !_isConnected) {
      _log('error', 'Not connected — call connectAndHandshake() first.');
      return false;
    }

    sessionId = id;
    _write('SESSION CREATE STYLE=STREAM ID=$id DESTINATION=TRANSIENT');

    final reply = await _awaitReply(
      (line) => line.contains('SESSION STATUS'),
      timeout: KamuiConstants.sessionTimeout,
    );

    final result = reply != null && reply.contains('RESULT=OK');

    if (result) {
      localDestinationKey = parseDestinationKey(reply);

      if (localDestinationKey == null || localDestinationKey == 'TRANSIENT') {
        localDestinationKey = null;
        _isSessionCreated = false;
        _log('error', 'Session creation failed: SAM returned empty or transient destination key');
      } else {
        _isSessionCreated = true;
        _log('success',
            'Session "$id" active. Dest: ${_truncateDest(localDestinationKey!)}');
      }
    } else {
      _isSessionCreated = false;
      _log('error', 'Session creation failed (reply: ${reply ?? "timeout"})');
    }

    _emitStatus(result ? 'session_ok' : 'session_failed');

    if (result) {
      _hadLiveSession = true;
      await _startInbound();
    }
    return result;
  }

  /// High-level method to send an encrypted payload to a peer destination over SAM.
  Future<bool> sendRawMessage(
      String targetDestination, String encryptedPayload) async {
    _log('info',
        'Outbound Encrypted Payload -> ${_truncateDest(targetDestination)} (${encryptedPayload.length} B)');

    // Call underlying socket stream connect
    final sent = await sendMessage(targetDestination, encryptedPayload);
    if (!sent) {
      _log('warning',
          'Live SAM transport offline. Message stored locally & queued.');
    }
    return sent;
  }

  /// Opens a STREAM connection to [targetDestination] and writes [message].
  Future<bool> sendMessage(String targetDestination, String message) async {
    if (sessionId == null) {
      _log('error', 'No active session — call createSession() first.');
      return false;
    }

    _log('info',
        'Opening garlic tunnel to ${_truncateDest(targetDestination)}…');

    SamChannel? sendSocket;
    try {
      sendSocket = await _channelFactory.connect(
        host,
        port,
        timeout: KamuiConstants.connectTimeout,
      );

      String sendBuffer = '';
      final completer = Completer<bool>();

      sendSocket.dataStream.listen(
        (List<int> data) {
          sendBuffer += utf8.decode(data, allowMalformed: true);
          while (sendBuffer.contains('\n')) {
            final idx   = sendBuffer.indexOf('\n');
            final line  = sendBuffer.substring(0, idx).trim();
            sendBuffer  = sendBuffer.substring(idx + 1);
            if (line.isEmpty) continue;

            if (line.contains('HELLO REPLY') && line.contains('RESULT=OK')) {
              sendSocket?.writeUtf8(
                'STREAM CONNECT ID=$sessionId DESTINATION=$targetDestination\n',
              );
            } else if (line.contains('STREAM STATUS')) {
              if (line.contains('RESULT=OK')) {
                sendSocket?.writeUtf8('$message\n');
                _log('success', 'Message delivered to SAM socket.');
                if (!completer.isCompleted) completer.complete(true);
              } else {
                _log('error', 'Stream connect failed: $line');
                if (!completer.isCompleted) completer.complete(false);
              }
              Future<void>.delayed(
                const Duration(milliseconds: 250),
                () => sendSocket?.destroy(),
              );
            }
          }
        },
        onError: (Object error) {
          _log('error', 'Send socket error: $error');
          sendSocket?.destroy();
          if (!completer.isCompleted) completer.complete(false);
        },
        onDone: () {
          if (!completer.isCompleted) completer.complete(false);
        },
      );

      sendSocket.writeUtf8(
        'HELLO VERSION MIN=${KamuiConstants.samMinVersion} MAX=${KamuiConstants.samMaxVersion}\n',
      );

      return await completer.future.timeout(
        KamuiConstants.sendTimeout,
        onTimeout: () {
          sendSocket?.destroy();
          return false;
        },
      );
    } catch (e) {
      _log('error', 'sendMessage exception: $e');
      sendSocket?.destroy();
      return false;
    }
  }

  /// Dispatches an incoming encrypted payload as if received from an I2P stream.
  void handleIncomingPayload(String senderDestination, String encryptedPayload) {
    _log('info',
        'Incoming Encrypted Payload <- ${_truncateDest(senderDestination)} (${encryptedPayload.length} B)');
    if (!_incomingMessageController.isClosed) {
      _incomingMessageController.add({
        'from':    senderDestination,
        'payload': encryptedPayload,
      });
    }
  }

  /// Utility to parse Destination key from SAM output.
  String? parseDestinationKey(String response) {
    final match =
        RegExp(r'DESTINATION=([A-Za-z0-9+~/=-]+)').firstMatch(response);
    return match?.group(1);
  }

  /// Decodes I2P Base64 destination string to raw bytes.
  Uint8List? _decodeI2pBase64(String input) {
    try {
      String normalized = input.replaceAll('-', '+').replaceAll('~', '/');
      while (normalized.length % 4 != 0) {
        normalized += '=';
      }
      return base64Decode(normalized);
    } catch (_) {
      return null;
    }
  }

  /// Encodes byte buffer to RFC 4648 Base32 string (lowercase, no padding).
  String _encodeBase32(Uint8List bytes) {
    const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
    final buffer = StringBuffer();
    int bitBuffer = 0;
    int bitCount = 0;

    for (final b in bytes) {
      bitBuffer = (bitBuffer << 8) | (b & 0xFF);
      bitCount += 8;
      while (bitCount >= 5) {
        bitCount -= 5;
        final index = (bitBuffer >> bitCount) & 0x1F;
        buffer.write(alphabet[index]);
      }
    }

    if (bitCount > 0) {
      final index = (bitBuffer << (5 - bitCount)) & 0x1F;
      buffer.write(alphabet[index]);
    }

    return buffer.toString();
  }

  /// Returns authentic I2P Base32 address (SHA-256 of raw Destination bytes).
  String get b32Address {
    final key = localDestinationKey;
    if (key == null || key.isEmpty) return 'kamui-node.b32.i2p';

    final rawBytes = _decodeI2pBase64(key);
    final hashBytes = rawBytes != null && rawBytes.isNotEmpty
        ? sha256.convert(rawBytes).bytes
        : sha256.convert(utf8.encode(key)).bytes;

    final b32 = _encodeBase32(Uint8List.fromList(hashBytes));
    return '$b32.b32.i2p';
  }

  /// Closes current SAM session and spins up a brand new SAM session for the selected persona.
  Future<bool> switchPersonaSession(String personaId) async {
    _log('info', 'Rotating SAM Session for Persona: "$personaId"…');

    if (_isSessionCreated && sessionId != null) {
      // Tear down the inbound listener before destroying the session it
      // belongs to; createSession() re-arms it for the new persona session.
      await _teardownInboundListener();
      _write('SESSION DESTROY ID=$sessionId');
      _isSessionCreated = false;
      sessionId = null;
      localDestinationKey = null;
    }

    final newSessionId = 'kamui_${personaId}_${DateTime.now().millisecondsSinceEpoch.remainder(10000)}';
    if (_isConnected) {
      return await createSession(newSessionId);
    }
    sessionId = newSessionId;
    return true;
  }

  /// Disconnects and releases all resources.
  void dispose() {
    _disposed       = true;
    _isReconnecting = false;
    unawaited(_teardownInboundListener());
    _controlSocket?.destroy();
    _controlSocket     = null;
    _isConnected       = false;
    _isSessionCreated  = false;
    sessionId          = null;
    localDestinationKey = null;
    _buffer            = '';
    _log('info', 'SAM service disposed');
    if (!_logController.isClosed)            _logController.close();
    if (!_statusController.isClosed)         _statusController.close();
    if (!_incomingLines.isClosed)            _incomingLines.close();
    if (!_incomingMessageController.isClosed) _incomingMessageController.close();
  }

  // ═══════════════════════════════════════════════════════════════════════
  // INTERNAL — Socket Dispatcher
  // ═══════════════════════════════════════════════════════════════════════

  void _attachSocketListener() {
    _buffer = '';
    _controlSocket!.dataStream.listen(
      (List<int> data) {
        _buffer += utf8.decode(data, allowMalformed: true);
        _flushLines();
      },
      onError: (Object error) {
        _handleControlLoss('SAM control socket error: $error');
      },
      onDone: () {
        if (_buffer.trim().isNotEmpty) {
          _dispatchLine(_buffer.trim());
          _buffer = '';
        }
        _handleControlLoss('SAM control socket closed by remote');
      },
      cancelOnError: false,
    );
  }

  void _flushLines() {
    while (_buffer.contains('\n')) {
      final idx  = _buffer.indexOf('\n');
      final line = _buffer.substring(0, idx).trim();
      _buffer    = _buffer.substring(idx + 1);
      if (line.isNotEmpty) _dispatchLine(line);
    }
  }

  void _dispatchLine(String line) {
    _log('data', '<<< $line');
    if (!_incomingLines.isClosed) {
      _incomingLines.add(line);
    }
  }

  Future<String?> _awaitReply(
    bool Function(String line) matcher, {
    Duration timeout = const Duration(seconds: 10),
  }) {
    final completer = Completer<String?>();
    StreamSubscription<String>? sub;

    sub = _incomingLines.stream.listen((line) {
      if (matcher(line) && !completer.isCompleted) {
        completer.complete(line);
        Future<void>(() => sub?.cancel());
      }
    });

    return completer.future.timeout(
      timeout,
      onTimeout: () {
        sub?.cancel();
        return null;
      },
    );
  }

  // ═══════════════════════════════════════════════════════════════════════
  // INTERNAL — Inbound Transport (SAM STREAM FORWARD / STREAM ACCEPT)
  // ═══════════════════════════════════════════════════════════════════════

  /// Starts (or restarts) the inbound listener for the active session.
  ///
  /// Idempotent: any previously armed listener is torn down first. Called
  /// automatically on every successful [createSession].
  Future<void> startInbound() => _startInbound();

  Future<void> _startInbound() async {
    await _teardownInboundListener();
    if (_disposed || !_isSessionCreated || sessionId == null) return;
    switch (inboundMode) {
      case SamInboundMode.forward:
        await _armForwardListener();
      case SamInboundMode.accept:
        // Fire-and-forget: the loop logs internally and exits on teardown
        // (generation bump) or dispose; late faults are swallowed.
        unawaited(
          _runAcceptLoop(_inboundGeneration).catchError((Object e) {
            _log('error', 'ACCEPT loop fault: $e');
          }),
        );
    }
  }

  /// Closes the FORWARD server / stops the ACCEPT loop (generation bump).
  Future<void> _teardownInboundListener() async {
    _inboundGeneration++;
    final SamServerChannel? server = _forwardServer;
    _forwardServer = null;
    if (server == null) return;
    try {
      await server.close();
    } catch (e) {
      _log('warning', 'Forward listener close failed: $e');
    }
  }

  /// Arms SAM STREAM FORWARD: binds a local ServerSocket and hands its port
  /// to the router, which connects inbound I2P streams onto it.
  ///
  /// If the preferred port ([KamuiConstants.samForwardPort]) is already in
  /// use (SocketException), the listener falls back to an OS-assigned
  /// ephemeral port (bind port 0) and forwards THAT port instead. The
  /// fallback is logged and emitted as `inbound_port_fallback` so it stays
  /// observable. ACCEPT mode is untouched by this path.
  Future<void> _armForwardListener() async {
    final String id = sessionId!;
    try {
      var boundPort = KamuiConstants.samForwardPort;
      SamServerChannel server;
      try {
        server = await _channelFactory.bind(
          KamuiConstants.samForwardHost,
          KamuiConstants.samForwardPort,
        );
      } on SocketException catch (e) {
        _log(
          'warning',
          'FORWARD port ${KamuiConstants.samForwardPort} unavailable ($e) — '
          'retrying with an OS-assigned ephemeral port',
        );
        _emitStatus('inbound_port_fallback');
        server = await _channelFactory.bind(KamuiConstants.samForwardHost, 0);
        boundPort = server.port;
        _log('info', 'FORWARD listener bound to ephemeral port $boundPort');
      }
      if (_disposed || sessionId != id) {
        await server.close();
        return;
      }
      _forwardServer = server;
      server.connections.listen(_onRouterConnection);

      _write(
        'STREAM FORWARD ID=$id '
        'PORT=$boundPort '
        'HOST=${KamuiConstants.samForwardHost} SILENT=false',
      );
      final ok = await _awaitForwardAck();
      if (ok) {
        _log('success',
            'Inbound listener armed (FORWARD ${KamuiConstants.samForwardHost}:$boundPort)');
      } else {
        _log('error', 'STREAM FORWARD rejected — inbound receive offline');
      }
      _emitStatus(ok ? 'inbound_ok' : 'inbound_failed');
    } catch (e) {
      _log('error', 'Failed to arm FORWARD listener: $e');
      _emitStatus('inbound_failed');
    }
  }

  Future<bool> _awaitForwardAck() async {
    final reply = await _awaitReply(
      (line) => line.contains('DIRECTION') || line.contains('STREAM STATUS'),
      timeout: KamuiConstants.sessionTimeout,
    );
    return reply != null && reply.contains('RESULT=OK');
  }

  /// Entry point for every router hand-off connection (FORWARD mode).
  void _onRouterConnection(SamChannel connection) {
    _InboundConnectionHandler.fromLine(this, connection);
  }

  /// Fallback backend: repeatedly arms `STREAM ACCEPT ID=<session>` on
  /// dedicated sockets. Each armed socket serves exactly one inbound
  /// connection; the loop then re-arms a fresh socket.
  Future<void> _runAcceptLoop(int generation) async {
    _log('info', 'Inbound ACCEPT loop starting…');
    while (!_disposed &&
        _inboundGeneration == generation &&
        _isSessionCreated &&
        sessionId != null) {
      SamChannel? channel;
      try {
        channel = await _channelFactory.connect(
          host,
          port,
          timeout: KamuiConstants.connectTimeout,
        );
        final armed = await _armAcceptSocket(channel);
        if (!armed) {
          channel.destroy();
          await _acceptRetryPause();
          continue;
        }
        final reader = _InboundConnectionHandler.statusGated(this, channel);
        final ok = await reader.armed.timeout(
          KamuiConstants.sessionTimeout,
          onTimeout: () => false,
        );
        if (!ok) {
          reader.abort('STREAM STATUS never confirmed OK');
          await _acceptRetryPause();
          continue;
        }
        _log('info', 'STREAM ACCEPT armed — waiting for inbound peer…');
        await reader.done;
        channel.destroy();
        _log('info', 'Inbound connection consumed — re-arming ACCEPT');
      } catch (e) {
        channel?.destroy();
        _log('error', 'ACCEPT loop error: $e');
        await _acceptRetryPause();
      }
    }
    _log('info', 'Inbound ACCEPT loop stopped');
  }

  /// HELLO + STREAM ACCEPT handshake on a dedicated accept socket.
  /// The subsequent `STREAM STATUS` reply is consumed by the reader.
  Future<bool> _armAcceptSocket(SamChannel channel) async {
    channel.writeUtf8(
      'HELLO VERSION MIN=${KamuiConstants.samMinVersion} '
      'MAX=${KamuiConstants.samMaxVersion}\n',
    );
    final hello = await _awaitLineOn(
      channel,
      (line) => line.contains('HELLO REPLY'),
      timeout: KamuiConstants.handshakeTimeout,
    );
    if (hello == null || !hello.contains('RESULT=OK')) return false;
    channel.writeUtf8('STREAM ACCEPT ID=$sessionId SILENT=false\n');
    return true;
  }

  Future<void> _acceptRetryPause() {
    return Future<void>.delayed(const Duration(milliseconds: 500));
  }

  /// Waits for the first line on [channel] matching [matcher]. Unlike
  /// [_awaitReply] this targets a dedicated (non-control) socket.
  Future<String?> _awaitLineOn(
    SamChannel channel,
    bool Function(String line) matcher, {
    Duration timeout = const Duration(seconds: 10),
  }) {
    final completer = Completer<String?>();
    late final StreamSubscription<Uint8List> sub;
    var buffer = '';

    sub = channel.dataStream.listen((List<int> data) {
      buffer += utf8.decode(data, allowMalformed: true);
      while (buffer.contains('\n') && !completer.isCompleted) {
        final idx  = buffer.indexOf('\n');
        final line = buffer.substring(0, idx).trim();
        buffer     = buffer.substring(idx + 1);
        if (line.isNotEmpty && matcher(line)) {
          completer.complete(line);
          Future<void>(() => sub.cancel());
        }
      }
    }, onError: (Object e) {
      if (!completer.isCompleted) completer.complete(null);
    }, onDone: () {
      if (!completer.isCompleted) completer.complete(null);
    });

    return completer.future.timeout(timeout, onTimeout: () {
      sub.cancel();
      return null;
    });
  }

  // ═══════════════════════════════════════════════════════════════════════
  // INTERNAL — Control-Socket Loss & Reconnect Backoff
  // ═══════════════════════════════════════════════════════════════════════

  /// Handles unexpected control-socket death: marks state down and kicks the
  /// bounded-backoff reconnect loop (retries forever until [dispose]).
  void _handleControlLoss(String reason) {
    _isConnected      = false;
    _isSessionCreated = false;
    _log('error', reason);
    _emitStatus('disconnected');
    _scheduleReconnect();
  }

  /// Arms the bounded-backoff reconnect loop from a COLD START.
  ///
  /// Mid-session control loss arms the loop automatically (via
  /// [_handleControlLoss]); a failed cold start historically did not, so a
  /// router launched after the app would never be noticed. Call this after a
  /// failed cold-start connect to opt in: retries then run on the same
  /// exponential backoff until a router appears or [dispose] cancels them.
  /// Safe to call repeatedly — a no-op while the loop is already running.
  void startReconnectLoop() {
    _scheduleReconnect(overrideHadLiveSession: true);
  }

  void _scheduleReconnect({bool overrideHadLiveSession = false}) {
    if (_disposed || _isReconnecting) return;
    if (!_hadLiveSession && !overrideHadLiveSession) return;
    _isReconnecting = true;
    unawaited(_runReconnectLoop());
  }

  /// Exponential backoff 2s → 4s → … → 60s cap, ±20% jitter, infinite retries.
  Future<void> _runReconnectLoop() async {
    var delayMs = KamuiConstants.reconnectInitialBackoff.inMilliseconds;
    final capMs = KamuiConstants.reconnectMaxBackoff.inMilliseconds;

    while (!_disposed) {
      // Another path (e.g. manual retry from RouterSetupScreen) already
      // restored the link while this loop was sleeping — stand down.
      if (_isConnected && _isSessionCreated) break;

      _log('info', 'Reconnecting in ${_jitter(delayMs)}ms…');
      _emitStatus('reconnecting');
      await Future<void>.delayed(Duration(milliseconds: _jitter(delayMs)));
      if (_disposed) break;

      final recovered = await _attemptReconnect();
      if (recovered) {
        _log('success', 'SAM link restored — session "${sessionId ?? ""}"');
        _isReconnecting = false;
        return;
      }
      delayMs = math.min(delayMs * 2, capMs);
    }
    _isReconnecting = false;
  }

  Future<bool> _attemptReconnect() async {
    final id = sessionId ?? 'KamuiSession';
    final connected = await connectAndHandshake();
    if (!connected || _disposed) return false;
    return createSession(id);
  }

  /// Applies ±[KamuiConstants.reconnectJitterRatio] jitter to [ms].
  int _jitter(int ms) {
    const ratio = KamuiConstants.reconnectJitterRatio;
    final factor = 1.0 - ratio + _jitterRandom.nextDouble() * 2 * ratio;
    return (ms * factor).round();
  }

  void _write(String cmd) {
    _log('data', '>>> $cmd');
    _controlSocket?.writeUtf8('$cmd\n');
  }

  void _log(String type, String message) {
    if (_logController.isClosed) return;
    _logController.add({
      'type':      type,
      'message':   message,
      'timestamp': DateTime.now().toIso8601String(),
    });
  }

  void _emitStatus(String status) {
    if (_statusController.isClosed) return;
    _statusController.add({
      'status':             status,
      'isConnected':        _isConnected,
      'isSessionCreated':   _isSessionCreated,
      'sessionId':          sessionId,
      'localDestinationKey': localDestinationKey,
    });
  }

  String _truncateDest(String dest) {
    if (dest.length <= 12) return dest;
    return '${dest.substring(0, 6)}…${dest.substring(dest.length - 4)}';
  }
}

/// Per-connection inbound frame parser.
///
/// Wire contract (SILENT=false): the first line MUST be
/// `FROM <base64 destination>`; every subsequent newline-terminated line is
/// one encrypted payload. Sender identity comes ONLY from the FROM line —
/// it is never guessed from ciphertext. Connections violating the FROM
/// contract are dropped and logged (fail-closed, no crash).
class _InboundConnectionHandler {
  static const int _phaseStatus  = 0;
  static const int _phaseFrom    = 1;
  static const int _phasePayload = 2;

  final SamService _service;
  final SamChannel _channel;
  final Completer<void> _done  = Completer<void>();
  final Completer<bool> _armed = Completer<bool>();

  int     _phase;
  String  _buffer     = '';
  String? _senderDest;
  StreamSubscription<Uint8List>? _sub;

  _InboundConnectionHandler._(this._service, this._channel, bool statusGated)
      : _phase = statusGated ? _phaseStatus : _phaseFrom {
    _sub = _channel.dataStream.listen(
      _onData,
      onError: (Object e) => abort('Inbound stream error: $e'),
      onDone: _finish,
    );
  }

  /// Standard router hand-off (FORWARD): first line is `FROM <dest>`.
  factory _InboundConnectionHandler.fromLine(
          SamService service, SamChannel channel) =>
      _InboundConnectionHandler._(service, channel, false);

  /// ACCEPT socket: waits for `STREAM STATUS … RESULT=OK` before data mode.
  factory _InboundConnectionHandler.statusGated(
          SamService service, SamChannel channel) =>
      _InboundConnectionHandler._(service, channel, true);

  /// Completes `true` once the ACCEPT socket is armed (status-gated mode);
  /// completes immediately for FROM-gated mode.
  Future<bool> get armed =>
      _phase == _phaseStatus ? _armed.future : Future<bool>.value(true);

  /// Completes when the connection finishes (closed, aborted, or consumed).
  Future<void> get done => _done.future;

  void _onData(Uint8List data) {
    _buffer += utf8.decode(data, allowMalformed: true);
    while (_buffer.contains('\n')) {
      final idx  = _buffer.indexOf('\n');
      final line = _buffer.substring(0, idx).trim();
      _buffer    = _buffer.substring(idx + 1);
      if (line.isNotEmpty) _onLine(line);
    }
  }

  void _onLine(String line) {
    switch (_phase) {
      case _phaseStatus:
        final ok =
            line.contains('STREAM STATUS') && line.contains('RESULT=OK');
        if (!_armed.isCompleted) _armed.complete(ok);
        if (!ok) abort('STREAM ACCEPT rejected ($line)');
        _phase = _phaseFrom;
      case _phaseFrom:
        final dest = parseFromLine(line);
        if (dest == null) {
          abort('Inbound connection rejected — missing/invalid FROM line');
          return;
        }
        _senderDest = dest;
        _phase      = _phasePayload;
        _service._log('info',
            'Inbound stream opened <- ${_service._truncateDest(dest)}');
      case _phasePayload:
        _service.handleIncomingPayload(_senderDest!, line);
    }
  }

  void _finish() {
    if (_phase == _phaseStatus && !_armed.isCompleted) {
      _armed.complete(false);
    }
    if (_phase == _phaseFrom) {
      abort('Inbound connection closed before FROM line — dropped');
      return;
    }
    // Tolerant flush: sender omitted the trailing newline on the last payload.
    final tail = _buffer.trim();
    if (_phase == _phasePayload && tail.isNotEmpty) {
      _buffer = '';
      _service.handleIncomingPayload(_senderDest!, tail);
    }
    _complete();
  }

  /// Drops the connection with a warning. Safe to call multiple times.
  void abort(String reason) {
    _service._log('warning', reason);
    if (_armed.isCompleted == false) _armed.complete(false);
    _complete();
  }

  void _complete() {
    if (_done.isCompleted) return;
    unawaited(_sub?.cancel());
    _sub = null;
    _channel.destroy();
    _done.complete();
  }

  /// Parses `FROM <destination>`; returns the destination or `null`.
  static String? parseFromLine(String line) {
    if (!line.startsWith('FROM ')) return null;
    final dest = line.substring(5).trim();
    if (dest.isEmpty) return null;
    if (!RegExp(r'^[A-Za-z0-9+~/=-]+$').hasMatch(dest)) return null;
    return dest;
  }
}
