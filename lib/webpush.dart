// Apache 2.0 2022 Simon Ser

import 'dart:convert';
import 'dart:typed_data';

import 'package:webcrypto/webcrypto.dart';

import 'ece.dart';

class DecryptionError extends ArgumentError {
  DecryptionError([dynamic message, String? name]) : super(message, name);
}

class KeyError extends DecryptionError {
  KeyError([dynamic message, String? name]) : super(message, name);
}

class WebPush {
  static Future<Uint8List> decrypt(WebPushKeys keys, Uint8List buf) async {
    try {
      Header header = await Header.fromRaw(buf);

      //only one record in webpush, so whole rest of body is record
      var record = buf.sublist(header.length);

      var serverPubKey = header.id;

      var ikm = await ECE.makeIKM(
          await keys.pubKey, await keys.privKey, keys._authKey, serverPubKey);

      var aesSecretKey = ECE.getContentKey(ikm, header.salt);
      var aesNonce = ECE.nonce(ikm, header.salt, 0);

      return ECE.decryptRecord(await aesSecretKey, await aesNonce, record);
    } catch (e) {
      throw DecryptionError(e,
          'something is wrong'); // TODO, throw more granular errors, subclass them under DecryptionError so applications can just catch DecryptionError
    }
  }
}

class WebPushKeys {
  final List<int> _pubKey;
  final Uint8List authKey;
  final List<int> _privKey;

  //WebPushKeys(this._pubKey, this.authKey, this._privKey); // FUTURE PERSON: don't do positional because messing up the order of the args is very easy
  WebPushKeys(
      {required List<int> pubKeyBytes,
      required Uint8List authKeyBytes,
      required List<int> privKeyBytes})
      : _pubKey = pubKeyBytes,
        _privKey = privKeyBytes,
        _authKey = authKeyBytes;

  static Future<WebPushKeys> fromMap(Map<String, List<int>> keys) async {
    var pub = keys['p256dh'], priv = keys['priv'], auth = keys['auth'];

    if (pub != null && priv != null && auth != null) {
      throw ArgumentError('Missing one of p256dh, priv, or auth in Map');
    }
    return WebPushKeys(
            pubKeyBytes: pub!,
            authKeyBytes: Uint8List.fromList(auth!),
            privKeyBytes: priv!)
        ._validate();
  }

  static Future<WebPushKeys> fromBase64(String base64str) {
    var split = base64str.split('+');

    if (split.length < 3) {
      throw ArgumentError('Missing one or more of p256dh, priv, or auth');
    }

    return WebPushKeys(
            pubKeyBytes: base64Decode(split[0]),
            authKeyBytes: base64Decode(split[1]),
            privKeyBytes: base64Decode(split[2]))
        ._validate();
  }

  Future<WebPushKeys> _validate() async {
    try {
      assert(_authKey.length == 16);
      await pubKey;
      await privKey;
    } catch (e) {
      if (e is FormatException && e.message.contains("INVALID_ENCODING")) {
        throw KeyError(e, 'Invalid Key');
      }
      if (e is AssertionError) throw KeyError(e, 'Auth Key');
      rethrow;
    }

    return this;
  }

  static Future<WebPushKeys> random() async {
    var authKey = Uint8List(16);
    fillRandomBytes(authKey);

    var p256dhKeyPair = await EcdhPrivateKey.generateKey(curve);
    return WebPushKeys(
        pubKeyBytes: await p256dhKeyPair.publicKey.exportRawKey(),
        authKeyBytes: authKey,
        privKeyBytes: await p256dhKeyPair.privateKey.exportPkcs8Key());
  }

// getters
  Future<EcdhPublicKey> get pubKey =>
      EcdhPublicKey.importRawKey(_pubKey, curve);

  String get pubKeyWeb => base64UrlEncode(_pubKey);
  String get authWeb => base64UrlEncode(authKey);

  Future<EcdhPrivateKey> get privKey =>
      EcdhPrivateKey.importPkcs8Key(_privKey, curve);

// export
  Map<String, List<int>> get allKeysRaw => {
        'p256dh': _pubKey,
        'auth': authKey,
        'priv': _privKey,
      };

  String get toBase64 =>
      pubKeyWeb + '+' + authWeb + '+' + base64Url.encode(_privKey);
}
