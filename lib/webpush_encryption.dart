// Apache 2.0 2022 Simon Ser
import 'dart:typed_data';

import 'package:webcrypto/webcrypto.dart';

import 'src/ece.dart';
import 'src/errors.dart';
import 'src/keys.dart';

export 'src/errors.dart';
export 'src/keys.dart';

/// Contains decryption method and code
class WebPush {
  /// decrypts
  ///
  /// Throws DecryptionError (or a subclass) in case of an issue.
  Future<Uint8List> decrypt(
    WebPushKeySet keys,
    Uint8List encryptedBytes,
  ) async {
    try {
      Header header = await Header.fromRaw(encryptedBytes);

      //only one record in webpush, so whole rest of body is record
      var record = encryptedBytes.sublist(header.length);

      var serverPubKey = header.id;

      var ikm = await ECE.makeIKM(
        await keys.publicKey.pubKey,
        await keys.privateKey.privKey,
        keys.publicKey.authKey,
        serverPubKey,
      );

      var aesSecretKey = ECE.getContentKey(ikm, header.salt);
      var aesNonce = ECE.nonce(ikm, header.salt, 0);

      return ECE.decryptRecord(await aesSecretKey, await aesNonce, record);
    } catch (e) {
      // TODO, throw more granular errors, subclass them under DecryptionError so applications can just catch DecryptionError
      throw DecryptionError(e, 'something is wrong');
    }
  }

  /// Encrypts [plaintext] following RFC8291.
  ///
  /// Uses public and private [serverKeys] with public and authkey [clientKeys].
  ///
  /// [salt] is optional and will be filled with cryptographically random bytes
  /// if it is not provided. This is mostly useful for debugging.
  Future<Uint8List> encrypt({
    required WebPushKeySet serverKeys,
    required PublicWebPushKey clientKeys,
    required Uint8List plaintext,
    Uint8List? salt,
  }) async {
    try {
      if (salt == null) {
        salt = Uint8List(16);
        fillRandomBytes(salt);
      }
      final uaPubKey = await clientKeys.pubKey;
      final asPubKey = await serverKeys.publicKey.pubKey;

      final ikm = await ECE.makeIKMServer(
        asPubKey,
        await serverKeys.privateKey.privKey,
        clientKeys.authKey,
        uaPubKey,
      );

      final aesSecretKey = await ECE.getContentKey(ikm, salt);
      final aesNonce = await ECE.nonce(ikm, salt, 0);

      final asRawPubKey = await asPubKey.exportRawKey();

      final cipherText =
          await ECE.encryptRecord(aesSecretKey, aesNonce, plaintext);
      final header = Header(salt, 4096, asRawPubKey.length, asPubKey);

      return Uint8List.fromList([
        ...await header.toRaw(),
        ...cipherText,
      ]);
    } catch (e) {
      throw EncryptionError(e);
    }
  }
}
