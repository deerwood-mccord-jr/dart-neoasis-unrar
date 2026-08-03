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
    highPosAv = 0;
    posAv = 0;
  }
}
