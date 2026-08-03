/// Errors raised by neoasis_unrar.
library;

/// Base class for all errors produced by the library.
class UnrarException implements Exception {
  const UnrarException(this.message);

  final String message;

  @override
  String toString() => 'UnrarException: $message';
}

/// The data does not look like a supported RAR archive.
class UnrarFormatException extends UnrarException {
  const UnrarFormatException(super.message);

  @override
  String toString() => 'UnrarFormatException: $message';
}

/// An archive block or checksum is corrupted.
class UnrarHeaderException extends UnrarException {
  const UnrarHeaderException(super.message);

  @override
  String toString() => 'UnrarHeaderException: $message';
}
