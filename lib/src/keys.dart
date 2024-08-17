import 'dart:convert';
import 'dart:typed_data';

import 'package:webcrypto/webcrypto.dart';

import 'curve.dart';
import 'errors.dart';

class WebPublicPushKey {
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

  WebPublicPushKey({
    required List<int> publicKeyBytes,
    required Uint8List authKeyBytes,
  })  : _pubKey = publicKeyBytes,
        _authKey = authKeyBytes;

  /// Validate the key parameters.
  Future<WebPublicPushKey> validate() async {
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

  /// For later use with [WebPublicPushKey.fromMap].
  Map<String, List<int>> toMap() => {'p256dh': _pubKey, 'auth': _authKey};

  /// Serializes public key for storage.
  ///
  /// Deserialize with [WebPushKeys.deserialize].
  String get serialize => '$p256dh+$auth';

  static Future<WebPublicPushKey> fromMap(Map<String, List<int>> keys) async {
    if (keys case {'p256dh': List<int> pub, 'auth': List<int> auth}) {
      return WebPublicPushKey(
        publicKeyBytes: pub,
        authKeyBytes: Uint8List.fromList(auth),
      ).validate();
    }
    throw KeyError('bad public key/auth');
  }
}

class WebPrivatePushKey {
  final List<int> _privKey;

  ///Get key in webcrypto format
  Future<EcdhPrivateKey> get privKey =>
      EcdhPrivateKey.importPkcs8Key(_privKey, curve);

  WebPrivatePushKey({required List<int> privateKeyBytes})
      : _privKey = privateKeyBytes;

  /// Validate the key parameters.
  Future<WebPrivatePushKey> validate() async {
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

  /// For later use with [WebPrivatePushKey.fromMap].
  Map<String, List<int>> toMap() => {'priv': _privKey};

  /// Serializes public key for storage.
  ///
  /// Deserialize with [WebPushKeys.deserialize].
  String get serialize => base64Url.encode(_privKey);

  static Future<WebPrivatePushKey> fromMap(Map<String, List<int>> keys) async {
    if (keys case {'priv': List<int> privateKeyBytes}) {
      return WebPrivatePushKey(
        privateKeyBytes: privateKeyBytes,
      ).validate();
    }
    throw KeyError('bad public key/auth');
  }
}

/// Stores the public, private, auth key needed for webpush.
class WebPushKeys {
  final WebPublicPushKey? publicKey;
  final WebPrivatePushKey? privateKey;

  WebPushKeys({this.publicKey, this.privateKey});

  /// Validate one or both keys.
  Future<WebPushKeys> validate() async {
    await publicKey?.validate();
    await privateKey?.validate();
    return this;
  }

  /// Parses a public, private, or key pair from the [keys] map.
  static Future<WebPushKeys> fromMap(Map<String, List<int>> keys) async {
    late final WebPrivatePushKey? privateKey;
    if (keys case {'priv': List<int> _}) {
      privateKey = await WebPrivatePushKey.fromMap(keys);
    } else {
      privateKey = null;
    }

    late final WebPublicPushKey? publicKey;
    if (keys case {'p256dh': List<int> _, 'auth': List<int> _}) {
      publicKey = await WebPublicPushKey.fromMap(keys);
    } else {
      publicKey = null;
    }

    return WebPushKeys(publicKey: publicKey, privateKey: privateKey);
  }

  /// Deserializes the output of [serialize]
  ///
  /// Useful for retrieval of keys from storage.
  static Future<WebPushKeys> deserialize(String base64str) async {
    var split = base64str.split('+');

    if (split.length == 1) {
      final privateKey = WebPrivatePushKey(
        privateKeyBytes: base64Decode(split[1]),
      );
      await privateKey.validate();
      return WebPushKeys(privateKey: privateKey);
    }

    final publicKey = WebPublicPushKey(
      publicKeyBytes: base64Decode(split[0]),
      authKeyBytes: base64Decode(split[1]),
    );
    await publicKey.validate();

    if (split.length == 2) {
      return WebPushKeys(publicKey: publicKey);
    }

    final privateKey = WebPrivatePushKey(
      privateKeyBytes: base64Decode(split[2]),
    );
    await privateKey.validate();

    return WebPushKeys(publicKey: publicKey, privateKey: privateKey);
  }

  /// Generate a new, random key pair.
  static Future<WebPushKeys> newKeyPair() async {
    var authKey = Uint8List(16);
    fillRandomBytes(authKey);

    var p256dhKeyPair = await EcdhPrivateKey.generateKey(curve);
    return WebPushKeys(
      publicKey: WebPublicPushKey(
          publicKeyBytes: await p256dhKeyPair.publicKey.exportRawKey(),
          authKeyBytes: authKey),
      privateKey: WebPrivatePushKey(
          privateKeyBytes: await p256dhKeyPair.privateKey.exportPkcs8Key()),
    );
  }

  /// Get a raw map of the key pair for later use with [fromMap].
  Map<String, List<int>> get rawKeys => {
        if (publicKey != null) ...publicKey!.toMap(),
        if (privateKey != null) ...privateKey!.toMap(),
      };

  /// Serializes public *and private* keys for storage. Deserialize with [WebPushKeys.deserialize()]
  String get serialize {
    if (privateKey != null && publicKey != null) {
      return '${publicKey!.serialize}+${privateKey!.serialize}';
    }
    if (publicKey != null) {
      return publicKey!.serialize;
    }
    if (privateKey != null) {
      return privateKey!.serialize;
    }
    return '';
  }
}
