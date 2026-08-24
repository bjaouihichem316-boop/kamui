import 'dart:async';
import 'dart:io';
import 'dart:typed_data';

/// Byte-level transport channel carrying SAM protocol traffic.
///
/// Abstraction seam over `dart:io` sockets so [SamService] can be unit-tested
/// with in-memory fakes. Implementations MUST expose [dataStream] as a
/// broadcast-compatible stream (sequential and concurrent listeners allowed),
/// because the service layers reply-matchers and data readers on top of it.
abstract class SamChannel {
  /// Raw inbound bytes. Safe to listen to multiple times.
  Stream<Uint8List> get dataStream;

  /// Writes UTF-8 text to the channel (include the trailing `\n`).
  void writeUtf8(String data);

  /// Immediately tears down the channel. Idempotent.
  void destroy();
}

/// Listener socket yielding inbound [SamChannel] connections
/// (the local end of a SAM STREAM FORWARD hand-off).
abstract class SamServerChannel {
  /// Accepted inbound connections.
  Stream<SamChannel> get connections;

  /// Closes the listener socket. Idempotent.
  Future<void> close();
}

/// Factory producing channels; injection point for tests.
abstract class SamChannelFactory {
  /// Opens a client channel to [host]:[port].
  Future<SamChannel> connect(String host, int port, {Duration? timeout});

  /// Binds a server channel on [host]:[port].
  Future<SamServerChannel> bind(String host, int port);
}

/// Default production factory backed by `dart:io`.
class IoSamChannelFactory implements SamChannelFactory {
  const IoSamChannelFactory();

  @override
  Future<SamChannel> connect(String host, int port, {Duration? timeout}) async {
    final Socket socket = await Socket.connect(host, port, timeout: timeout);
    return IoSamChannel(socket);
  }

  @override
  Future<SamServerChannel> bind(String host, int port) async {
    final ServerSocket server = await ServerSocket.bind(host, port);
    return IoSamServerChannel(server);
  }
}

/// [SamChannel] wrapping a `dart:io` [Socket].
class IoSamChannel implements SamChannel {
  final Socket _socket;

  /// Cached broadcast view — must be created exactly once per socket,
  /// otherwise each getter call would re-wrap a single-subscription stream.
  late final Stream<Uint8List> _broadcast = _socket.asBroadcastStream();

  IoSamChannel(this._socket);

  @override
  Stream<Uint8List> get dataStream => _broadcast;

  @override
  void writeUtf8(String data) => _socket.write(data);

  @override
  void destroy() => _socket.destroy();
}

/// [SamServerChannel] wrapping a `dart:io` [ServerSocket].
class IoSamServerChannel implements SamServerChannel {
  final ServerSocket _serverSocket;

  IoSamServerChannel(this._serverSocket);

  @override
  Stream<SamChannel> get connections =>
      _serverSocket.map((Socket socket) => IoSamChannel(socket));

  @override
  Future<void> close() => _serverSocket.close();
}
