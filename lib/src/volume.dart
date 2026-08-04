/// Multi-volume archive utilities, ported from `pathfn.cpp`
/// (`GetVolNumPos`, `NextVolumeName`) and `volume.cpp`.
///
/// The library core stays `dart:io`-free by using a [VolumeResolver]
/// callback rather than opening files directly.  `lib/io.dart` provides a
/// file-system-backed resolver for VM / Flutter desktop targets.
library;

import 'byte_source.dart';

/// Called when the reader needs the next volume in a multi-part archive.
///
/// [currentName] is the *archive name* (path or bare name) that was used to
/// open the current volume. [nextName] is the suggested next-part name
/// derived by [nextVolumeName].
///
/// Return a [ByteSource] opened at position 0 for the next volume, or `null`
/// if the volume cannot be located (extraction will then throw an
/// [UnrarException]).
typedef VolumeResolver = Future<ByteSource?> Function(
    String currentName, String nextName);

/// Returns the index of the last digit of the first numeric run in the
/// archive name stem, matching `GetVolNumPos` from `pathfn.cpp`.
int _getVolNumPos(String name, int nameStart) {
  if (nameStart >= name.length) return nameStart;

  // Start at the last character.
  var pos = name.length - 1;

  // Skip the archive extension (non-digit chars before the last digit run).
  while (pos > nameStart && !_isDigit(name[pos])) {
    pos--;
  }
  if (!_isDigit(name[pos])) return pos;

  // Walk back over the digit run.
  var numPos = pos;
  while (numPos > nameStart && _isDigit(name[numPos])) {
    numPos--;
  }

  // Search for an earlier numeric run (e.g. "part##of##"). Stop at a dot.
  var probe = numPos;
  while (probe > nameStart && name[probe] != '.') {
    if (_isDigit(name[probe])) {
      // Only use this earlier run if there is a dot somewhere before it.
      final dotPos = name.indexOf('.', nameStart);
      if (dotPos != -1 && dotPos < probe) {
        pos = probe;
      }
      break;
    }
    probe--;
  }

  return pos;
}

bool _isDigit(String c) => c.codeUnitAt(0) >= 0x30 && c.codeUnitAt(0) <= 0x39;

/// Computes the name of the next volume in a multi-part archive set,
/// mirroring `NextVolumeName` from `pathfn.cpp`.
///
/// [arcName] is the current volume's name (path included).
/// [oldNumbering] selects the RAR 2.x naming convention
/// (`.rar → .r00 → .r01 …`); use `false` for modern archives
/// (`.part1.rar → .part2.rar`, counter-incremented).
String nextVolumeName(String arcName, {bool oldNumbering = false}) {
  // Locate the directory separator so we never increment characters in
  // the directory component.
  final slashPos = arcName.lastIndexOf('/');
  final backslashPos = arcName.lastIndexOf('\\');
  final nameStart = (slashPos > backslashPos ? slashPos : backslashPos) + 1;

  final dotPos = arcName.lastIndexOf('.');

  // Ensure the name has a .rar extension to work from.
  String name;
  if (dotPos < nameStart) {
    // No extension at all.
    name = '$arcName.rar';
  } else {
    final ext = arcName.substring(dotPos + 1).toLowerCase();
    if (ext == 'exe' || ext == 'sfx') {
      name = '${arcName.substring(0, dotPos)}.rar';
    } else {
      name = arcName;
    }
  }

  if (!oldNumbering) {
    // New-style: find the numeric counter and increment it with carry.
    final numPos = _getVolNumPos(name, nameStart);
    final chars = name.split('');
    var pos = numPos;
    // Mirrors: while (++ArcName[NumPos]=='9'+1) { ... }
    while (true) {
      final newCode = chars[pos].codeUnitAt(0) + 1;
      if (newCode != 0x3A /* ':' == '9'+1 — only carry on exact overflow */) {
        chars[pos] = String.fromCharCode(newCode);
        break;
      }
      // Carry: reset this digit to '0' and move left.
      chars[pos] = '0';
      if (pos == 0 || pos == nameStart) break;
      pos--;
      if (!_isDigit(chars[pos])) {
        // Insert a '1' before the carry position, e.g. part9→part10.
        chars.insert(pos + 1, '1');
        break;
      }
    }
    return chars.join();
  } else {
    // Old-style: .rar → .r00 → .r01 → … → .r99 → .s00 …
    final reDot = name.lastIndexOf('.');
    var ext = name.substring(reDot + 1);
    if (ext.length < 3) {
      ext = 'rar';
    }
    if (!_isDigit(ext[1]) || !_isDigit(ext[2])) {
      // .rar → .r00
      ext = '${ext[0]}00';
    } else {
      final chars = ext.split('');
      var p = chars.length - 1;
      // Mirrors the C `while (++ArcName[NumPos]=='9'+1)` loop which
      // increments ANY character and only carries on '9'+1 = ':'.
      while (true) {
        final newCode = chars[p].codeUnitAt(0) + 1;
        if (newCode != 0x3A /* ':' == '9'+1 */) {
          chars[p] = String.fromCharCode(newCode);
          break;
        }
        // Carry: digit overflowed through '9'.
        if (p == 0 || chars[p - 1] == '.') {
          chars[p] = 'a'; // .999 → .a00 edge case
          break;
        }
        chars[p--] = '0';
      }
      ext = chars.join();
    }
    return '${name.substring(0, reDot + 1)}$ext';
  }
}
