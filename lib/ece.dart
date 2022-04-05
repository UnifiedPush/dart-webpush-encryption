import 'dart:ffi';
import 'dart:math';
import 'dart:typed_data';

import 'package:webcrypto/webcrypto.dart';

const _saltSize = 16;
const _contentEncryptionKeySize = 16;

const _nonceSize = 12;
const _ikmSize = 32;

class ECE {
  static Future<Uint8List> mixKeys(
      EcdhPrivateKey privkey, EcdhPublicKey pubkey) {
    return privkey.deriveBits(32 * 8, pubkey);
  }

  static Future<HkdfSecretKey> makeIKM(
      EcdhPublicKey clientPub,
      EcdhPrivateKey clientPriv,
      Uint8List authKey,
      EcdhPublicKey serverPub) async {
    var info = [
      ...'WebPush: info'.codeUnits,
      0,
      ...(await clientPub.exportRawKey()),
      ...(await serverPub.exportRawKey()),
    ];

    var sharedEcdhSecret = mixKeys(clientPriv, serverPub);

    var hkdfSecretKey =
        await HkdfSecretKey.importRawKey(await sharedEcdhSecret);
    var ikm = await hkdfSecretKey.deriveBits(
        _ikmSize * 8, Hash.sha256, authKey, info);
    return HkdfSecretKey.importRawKey(ikm);
  }

static Future<Uint8List> nonce(
      HkdfSecretKey hkdfSecretKey, List<int> salt, int recordNum) async {
    List<int> info = [...'Content-Encoding: nonce'.codeUnits, 0];
// it needs to xor or something for records > 0
    return await hkdfSecretKey.deriveBits(
        _nonceSize * 8, Hash.sha256, salt, info);
  }

  static Future<AesGcmSecretKey> getContentKey(
      HkdfSecretKey hkdfSecretKey, Uint8List salt) async {
    var info = [...'Content-Encoding: aes128gcm'.codeUnits, 0];

    var contentEncryptionKeyBytes = await hkdfSecretKey.deriveBits(
        _contentEncryptionKeySize * 8, Hash.sha256, salt, info);
    return AesGcmSecretKey.importRawKey(contentEncryptionKeyBytes);
  }



//technically recordnum is uint96, but I don't even know
  static Future<Uint8List> decryptRecord(
      AesGcmSecretKey key, Uint8List nonce, Uint8List content) async {
    var cleartext = await key.decryptBytes(content, await nonce,
        tagLength: _contentEncryptionKeySize * 8);

    return stripPadding(cleartext);
  }

  static Uint8List stripPadding(Uint8List content) {
    // 0x01 is padding delim for non-last records, 0x02 is for the last record
    // a proper ECE library should probably communicate this last or not last record thing with other functions
    var paddingIndex =
        max(content.lastIndexOf(0x01), content.lastIndexOf(0x02));
    if (paddingIndex < 0) {
      throw FormatException('Missing padding delimiter in cleartext');
    }
    return content.sublist(0, paddingIndex);
  }

  
}

const CURVE = EllipticCurve.p256;

class Header {
  final Uint8List salt;
  late final int rs; // record size, must be between 18 and 2^32
  final int idlen;
  final EcdhPublicKey id;

  Header(this.salt, this.rs, this.idlen, this.id);

  static Future<Header> fromRaw(Uint8List buf) async {
    var offset = 0;

    var salt = buf.sublist(offset, offset + _saltSize);
    offset += salt.length;

    var recordSizeBytes = buf.sublist(offset, offset + 4);
    offset += recordSizeBytes.length;
    var recordSize = ByteData.sublistView(Uint8List.fromList(recordSizeBytes))
        .getUint32(0, Endian.big);

    var serverPubKeySize = buf[offset];
    offset++;

    var serverPubKeyBytes = buf.sublist(offset, offset + serverPubKeySize);
    offset += serverPubKeyBytes.length;
    var serverPubKey = EcdhPublicKey.importRawKey(serverPubKeyBytes, CURVE);

    return Header(salt, recordSize, serverPubKeySize, await serverPubKey);
  }

  int get length => _saltSize + 4 + 1 + idlen;
}
