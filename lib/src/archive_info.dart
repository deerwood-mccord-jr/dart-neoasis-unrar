/// Information parsed from the main archive header, modeled on the
/// `MainHeader` struct from the RARLAB UnRAR source (`headers.hpp`).
class ArchiveInfo {
  ArchiveInfo();

  bool volume = false;
  bool solid = false;
  bool locked = false;
  bool protected = false;
  bool encrypted = false;
  bool firstVolume = false;
  bool newNumbering = false;
  int volNumber = 0;

  /// Archive contains a comment. RAR 4.x: `MHD_COMMENT` main-header flag or a
  /// `CMT` service sub-header. RAR 5.0: a `CMT` service sub-header.
  bool comment = false;

  /// Archive has an authenticity verification (AV) signature. RAR 4.x only:
  /// set when the main header's AV block position is non-zero; always false
  /// for RAR 5.0 (matching `arcread.cpp`).
  bool signed = false;

  /// RAR 4.x only: present if an AV header is stored.
  int highPosAv = 0;
  int posAv = 0;

  void reset() {
    volume = false;
    solid = false;
    locked = false;
    protected = false;
    encrypted = false;
    firstVolume = false;
    newNumbering = false;
    volNumber = 0;
    comment = false;
    signed = false;
    highPosAv = 0;
    posAv = 0;
  }
}
