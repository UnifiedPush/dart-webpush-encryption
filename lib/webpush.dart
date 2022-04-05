// Apache 2.0 2022 Simon Ser

import 'dart:convert';
import 'dart:ffi';
import 'dart:typed_data';

import 'package:webcrypto/webcrypto.dart';

import 'ece.dart';

class WebPush {
  static Future<Uint8List> decrypt(WebPushKeys keys, Uint8List buf) async {
    Header header = await Header.fromRaw(buf);

    //only one record in webpush, so whole rest of body is record
    var record = buf.sublist(header.length);

    var serverPubKey = header.id;

    var ikm = await ECE.makeIKM(
        await keys.pubKey, await keys.privKey, keys.authKey, serverPubKey);

    var aesSecretKey = ECE.getContentKey(ikm, header.salt);
    var aesNonce = ECE.nonce(ikm, header.salt, 0);

    return ECE.decryptRecord(await aesSecretKey, await aesNonce, record);
  }
}

class WebPushKeys {
  final List<int> _pubKey;
  final Uint8List authKey;
  final List<int> _privKey;

  WebPushKeys(this._pubKey, this.authKey, this._privKey);

  static Future<WebPushKeys> fromMap(Map<String, List<int>> keys) async {
    var pub = keys['p256dh'], priv = keys['priv'], auth = keys['auth'];

    if (pub != null && priv != null && auth != null) {
      throw ArgumentError('Missing one of p256dh, priv, or auth in Map');
    }
    return WebPushKeys(pub!, Uint8List.fromList(auth!), priv!)._validate();
  }

  static Future<WebPushKeys> fromBase64(String base64str) {
    var split = base64str.split('+');

    if (split.length < 3) {
      throw ArgumentError('Missing one or more of p256dh, priv, or auth');
    }

    return WebPushKeys(base64Decode(split[0]), base64Decode(split[1]),
            base64Decode(split[2]))
        ._validate();
  }

  Future<WebPushKeys> _validate() async {
    assert(authKey.length == 16);
    await pubKey;
    await privKey;

    return this;
  }

  static Future<WebPushKeys> random() async {
    var authKey = Uint8List(16);
    fillRandomBytes(authKey);

    var p256dhKeyPair = await EcdhPrivateKey.generateKey(CURVE);
    return WebPushKeys(await p256dhKeyPair.publicKey.exportRawKey(), authKey, await p256dhKeyPair.privateKey.exportPkcs8Key());
  }

// getters
  Future<EcdhPublicKey> get pubKey =>
      EcdhPublicKey.importRawKey(_pubKey, CURVE);

  String get pubKeyWeb => base64UrlEncode(_pubKey);
  String get authWeb => base64UrlEncode(authKey);

  Future<EcdhPrivateKey> get privKey =>
      EcdhPrivateKey.importPkcs8Key(_privKey, CURVE);

// export
  Map<String, List<int>> get allKeysRaw => {
        'p256dh': _pubKey,
        'auth': authKey,
        'priv': _privKey,
      };

  String get toBase64 =>
      pubKeyWeb + '+' + authWeb + '+' + base64Url.encode(_privKey);
}
