/// RAR 4.x unicode file name decoder, ported from the RARLAB UnRAR source
/// (`encname.cpp`).
///
/// RAR 4.x stores the base ASCII name followed by a packed representation of
/// the high bytes of the UTF-16 name. The base name is decoded first so the
/// `decPos < name.length` bound in the C code maps to the same buffer.
library;

/// Decodes an encoded RAR 4.x file name.
///
/// [name] is the raw name buffer of `ReadNameSize` bytes (including the null
/// terminator), and [encName] is the encoded high-byte data following the
/// null terminator.
String decodeEncodedName(List<int> name, List<int> encName) {
  var encPos = 0;
  var decPos = 0;
  final highByte = encPos < encName.length ? encName[encPos++] : 0;
  var flags = 0;
  var flagBits = 0;
  final nameW = <int>[];

  while (encPos < encName.length) {
    if (flagBits == 0) {
      flags = encName[encPos++];
      flagBits = 8;
    }
    switch (flags >> 6) {
      case 0:
        if (encPos >= encName.length) {
          break;
        }
        nameW.add(encName[encPos++]);
        decPos++;
        break;
      case 1:
        if (encPos >= encName.length) {
          break;
        }
        nameW.add(encName[encPos++] + (highByte << 8));
        decPos++;
        break;
      case 2:
        if (encPos + 1 >= encName.length) {
          break;
        }
        nameW.add(encName[encPos] + (encName[encPos + 1] << 8));
        encPos += 2;
        decPos++;
        break;
      case 3:
        if (encPos >= encName.length) {
          break;
        }
        var length = encName[encPos++];
        if ((length & 0x80) != 0) {
          if (encPos >= encName.length) {
            break;
          }
          final correction = encName[encPos++];
          for (length = (length & 0x7f) + 2;
              length > 0 && decPos < name.length;
              length--, decPos++) {
            nameW.add(((name[decPos] + correction) & 0xff) + (highByte << 8));
          }
        } else {
          for (length += 2; length > 0 && decPos < name.length;
              length--, decPos++) {
            nameW.add(name[decPos]);
          }
        }
        break;
    }
    // In the C source Flags is a `byte`, so shifting wraps at 8 bits.
    flags = (flags << 2) & 0xff;
    flagBits -= 2;
  }

  return String.fromCharCodes(nameW);
}
