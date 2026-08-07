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

/// A RAR 3.x entry relies on a VM filter program that is not one of the six
/// standard filters (x86 E8/E8E9, Itanium, Delta, RGB, Audio). The RAR VM
/// bytecode interpreter is not ported, so such entries cannot be decoded.
///
/// The C library silently produces truncated output for these entries; this
/// library fails loudly instead.
class UnsupportedFilterException extends UnrarException {
  const UnsupportedFilterException(super.message);

  @override
  String toString() => 'UnsupportedFilterException: $message';
}
