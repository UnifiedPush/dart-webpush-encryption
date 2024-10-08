import 'dart:convert';
import 'dart:typed_data';

import 'package:webcrypto/webcrypto.dart';

import 'curve.dart';
import 'errors.dart';

/// Public webpush key and auth secret pair.
///
/// When on the web, this is generated by the browser and the private keys are
/// kept secret.
///
/// When on the server; use [WebPushKeySet.newKeyPair] to generate the
/// public/private key pair.
class PublicWebPushKey {
  final List<int> _pubKey;
  final Uint8List _authKey;

  /// Get the base64Url encoded public key to send to application server.
  ///
  ///This should be paired with [auth].
  String get p256dh => base64UrlEncode(_pubKey);

  /// Get the base64Url encoded authentication key to send to application server.
  ///
  /// This should be paired with [p256dh].
  String get auth => base64UrlEncode(_authKey);

  /// Get the public key in webcrypto format.
  Future<EcdhPublicKey> get pubKey =>
      EcdhPublicKey.importRawKey(_pubKey, curve);

  /// Get the raw authentication key.
  Uint8List get authKey => _authKey;

  PublicWebPushKey({
    required List<int> publicKeyBytes,
    required Uint8List authKeyBytes,
  })  : _pubKey = publicKeyBytes,
        _authKey = authKeyBytes;

  /// Validate the key parameters.
  Future<PublicWebPushKey> validate() async {
    try {
      if (_authKey.length != 16) {
        throw KeyError('Invalid authentication key length ${_authKey.length}',
            'authKeyBytes');
      }
      await pubKey;
    } catch (e) {
      if (e is FormatException && e.message.contains("INVALID_ENCODING")) {
        throw KeyError('Invalid public key', 'publicKeyBytes');
      }
      rethrow;
    }
    return this;
  }

  /// For later use with [PublicWebPushKey.fromMap].
  Map<String, List<int>> toMap() => {'p256dh': _pubKey, 'auth': _authKey};

  /// Serializes public key for storage.
  ///
  /// Deserialize with [WebPushKeySet.deserialize].
  String get serialize => '$p256dh+$auth';

  /// Create a validated [PublicWebPushKey] from [keys] or throws a [KeyError].
  static Future<PublicWebPushKey> fromMap(Map<String, List<int>> keys) async {
    if (keys case {'p256dh': List<int> pub, 'auth': List<int> auth}) {
      return PublicWebPushKey(
        publicKeyBytes: pub,
        authKeyBytes: Uint8List.fromList(auth),
      ).validate();
    }
    throw KeyError('bad public key/auth');
  }
}

/// Private web push key.
///
/// When on the server; use [WebPushKeySet.newKeyPair] to generate the
/// public/private key pair.
class PrivateWebPushKey {
  final List<int> _privKey;

  ///Get key in webcrypto format
  Future<EcdhPrivateKey> get privKey =>
      EcdhPrivateKey.importPkcs8Key(_privKey, curve);

  PrivateWebPushKey({required List<int> privateKeyBytes})
      : _privKey = privateKeyBytes;

  /// Validate the key parameters.
  Future<PrivateWebPushKey> validate() async {
    try {
      await privKey;
    } catch (e) {
      if (e is FormatException && e.message.contains("INVALID_ENCODING")) {
        throw KeyError('Invalid private key', 'privateKeyBytes');
      }
      rethrow;
    }
    return this;
  }

  /// For later use with [PrivateWebPushKey.fromMap].
  Map<String, List<int>> toMap() => {'priv': _privKey};

  /// Serializes public key for storage.
  ///
  /// Deserialize with [WebPushKeySet.deserialize].
  String get serialize => base64Url.encode(_privKey);

  /// Create a validated [PrivateWebPushKey] from [keys] or throws a [KeyError].
  static Future<PrivateWebPushKey> fromMap(Map<String, List<int>> keys) async {
    if (keys case {'priv': List<int> privateKeyBytes}) {
      return PrivateWebPushKey(
        privateKeyBytes: privateKeyBytes,
      ).validate();
    }
    throw KeyError('bad public key/auth');
  }
}

/// Stores the public, private, auth key needed for webpush.
class WebPushKeySet {
  final PublicWebPushKey publicKey;
  final PrivateWebPushKey privateKey;

  WebPushKeySet({required this.publicKey, required this.privateKey});

  /// Validate one or both keys.
  Future<WebPushKeySet> validate() async {
    await publicKey.validate();
    await privateKey.validate();
    return this;
  }

  /// Parses a public, private, or key pair from the [keys] map.
  static Future<WebPushKeySet> fromMap(Map<String, List<int>> keys) async {
    if (keys
        case {
          'priv': List<int> _,
          'p256dh': List<int> _,
          'auth': List<int> _,
        }) {
      return WebPushKeySet(
          publicKey: await PublicWebPushKey.fromMap(keys),
          privateKey: await PrivateWebPushKey.fromMap(keys));
    }
    throw ArgumentError('missing keyset data (priv, p256dh, auth)', 'keys');
  }

  /// Deserializes the output of [serialize]
  ///
  /// Useful for retrieval of keys from storage.
  static Future<WebPushKeySet> deserialize(String base64str) async {
    var split = base64str.split('+');

    if (split.length != 3) {
      throw ArgumentError(
          'Invalid format - expected 3 parameters split by "+"', 'base64str');
    }

    final publicKey = PublicWebPushKey(
      publicKeyBytes: base64Decode(split[0]),
      authKeyBytes: base64Decode(split[1]),
    );

    final privateKey = PrivateWebPushKey(
      privateKeyBytes: base64Decode(split[2]),
    );

    final set = WebPushKeySet(publicKey: publicKey, privateKey: privateKey);
    await set.validate();

    return set;
  }

  /// Generate a new, random key pair.
  static Future<WebPushKeySet> newKeyPair() async {
    var authKey = Uint8List(16);
    fillRandomBytes(authKey);

    var p256dhKeyPair = await EcdhPrivateKey.generateKey(curve);
    return WebPushKeySet(
      publicKey: PublicWebPushKey(
          publicKeyBytes: await p256dhKeyPair.publicKey.exportRawKey(),
          authKeyBytes: authKey),
      privateKey: PrivateWebPushKey(
          privateKeyBytes: await p256dhKeyPair.privateKey.exportPkcs8Key()),
    );
  }

  /// Get a raw map of the key pair for later use with [fromMap].
  Map<String, List<int>> get rawKeys => {
        ...publicKey.toMap(),
        ...privateKey.toMap(),
      };

  /// Serializes public *and private* keys for storage. Deserialize with [WebPushKeys.deserialize()]
  String get serialize {
    return '${publicKey.serialize}+${privateKey.serialize}';
  }
}
