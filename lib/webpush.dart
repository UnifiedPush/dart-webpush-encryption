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
  final List<int> _privKey;
  final Uint8List authKey;

  WebPushKeys(this._pubKey, this._privKey, this.authKey);

  static Future<WebPushKeys> fromMap(Map<String, List<int>> keys) async {
    var pub = keys['p256dh'], priv = keys['priv'], auth = keys['auth'];

    if (pub != null && priv != null && auth != null) {
      throw ArgumentError('Missing one of p256dh, priv, or auth in Map');
    }
    //make sure keys are valid
    await EcdhPublicKey.importRawKey(pub!, CURVE);
    await EcdhPrivateKey.importPkcs8Key(priv!, CURVE);

    return WebPushKeys(pub, priv, Uint8List.fromList(auth!));
  }

  static Future<WebPushKeys> random() async {
    var authKey = Uint8List(16);
    fillRandomBytes(authKey);

    var p256dhKeyPair = await EcdhPrivateKey.generateKey(CURVE);
    return WebPushKeys(await p256dhKeyPair.privateKey.exportPkcs8Key(),
        await p256dhKeyPair.publicKey.exportRawKey(), authKey);
  }

// getters
  Future<EcdhPublicKey> get pubKey =>
      EcdhPublicKey.importRawKey(_pubKey, CURVE);

  Future<EcdhPrivateKey> get privKey =>
      EcdhPrivateKey.importPkcs8Key(_privKey, CURVE);

// export
  Map<String, String> get publicKeysWeb => {
        'p256dh': base64Url.encode(_pubKey),
        'auth': base64Url.encode(authKey),
      };

  Map<String, List<int>> get allKeysRaw => {
        'p256dh': _pubKey,
        'auth': authKey,
        'priv': _privKey,
      };
}
