class DecryptionError extends ArgumentError {
  DecryptionError([super.message, super.name]);
}

class EncryptionError extends ArgumentError {
  EncryptionError([super.message, super.name]);
}

class KeyError extends ArgumentError {
  KeyError([super.message, super.name]);
}
