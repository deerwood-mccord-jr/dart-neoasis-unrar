/// Header type constants, sizes, and flag masks ported from the RARLAB UnRAR
/// source (`headers.hpp`, `headers5.hpp`, `crypt.hpp`).
library;

// RAR 4.x sizes.
const int sizofMarkHead3 = 7;
const int sizofMainHead3 = 13;
const int sizofFileHead3 = 32;
const int sizofShortBlockHead = 7;
const int sizofLongBlockHead = 11;

// RAR 5.0 sizes.
const int sizofMarkHead5 = 8;
const int sizofShortBlockHead5 = 7;

// Unpack versions.
const int verPack5 = 50;
const int verPack7 = 70;
const int verUnknown = 9999;

// RAR 4.x main archive header flags.
const int mhdVolume = 0x0001;
const int mhdComment = 0x0002;
const int mhdLock = 0x0004;
const int mhdSolid = 0x0008;
const int mhdPackComment = 0x0010;
const int mhdNewNumbering = 0x0010;
const int mhdAv = 0x0020;
const int mhdProtect = 0x0040;
const int mhdPassword = 0x0080;
const int mhdFirstVolume = 0x0100;

// RAR 4.x local file header flags.
const int lhdSplitBefore = 0x0001;
const int lhdSplitAfter = 0x0002;
const int lhdPassword = 0x0004;
const int lhdComment = 0x0008;
const int lhdSolid = 0x0010;
const int lhdWindowMask = 0x00e0;
const int lhdWindow64 = 0x0000;
const int lhdDirectory = 0x00e0;
const int lhdLarge = 0x0100;
const int lhdUnicode = 0x0200;
const int lhdSalt = 0x0400;
const int lhdVersion = 0x0800;
const int lhdExtTime = 0x1000;

const int skipIfUnknown = 0x4000;
const int longBlock = 0x8000;

// RAR 4.x end of archive flags.
const int earcNextVolume = 0x0001;
const int earcDataCrc = 0x0002;
const int earcRevSpace = 0x0004;
const int earcVolNumber = 0x0008;

// RAR 5.0 block flags common for all blocks.
const int hflExtra = 0x0001;
const int hflData = 0x0002;
const int hflSkipIfUnknown = 0x0004;
const int hflSplitBefore = 0x0008;
const int hflSplitAfter = 0x0010;
const int hflChild = 0x0020;
const int hflInherited = 0x0040;

// RAR 5.0 main archive header flags.
const int mhflVolume = 0x0001;
const int mhflVolNumber = 0x0002;
const int mhflSolid = 0x0004;
const int mhflProtect = 0x0008;
const int mhflLock = 0x0010;

// RAR 5.0 file header flags.
const int fhflDirectory = 0x0001;
const int fhflUTime = 0x0002;
const int fhflCrc32 = 0x0004;
const int fhflUnpUnknown = 0x0008;

// RAR 5.0 end of archive flags.
const int ehflNextVolume = 0x0001;

// RAR 5.0 encryption header flags.
const int chflCryptPswCheck = 0x0001;

// RAR 5.0 FHEXTRA_CRYPT flags.
const int fhExtraCryptPswCheck = 0x0001;
const int fhExtraCryptHashMac = 0x0002; // CRC32 in header is HMAC-SHA256 MAC.

// RAR 5.0 header extra area record types.
const int fhExtraCrypt = 0x01; // Encryption parameters.
const int fhExtraHash = 0x02; // File hash.
const int fhExtraHtime = 0x03; // High precision file time.
const int fhExtraVersion = 0x04; // File version information.
const int fhExtraRedir = 0x05; // File system redirection.
const int fhExtraUowner = 0x06; // Unix owner and group information.
const int fhExtraSubdata = 0x07; // Service header subdata array.

// RAR 5.0 file compression info flags.
const int fciSolid = 0x00000040;
const int fciRar5Compat = 0x00100000;

// Sub-header flags.
const int subheadFlagsInherited = 0x80000000;

// Service sub-header types.
const List<int> subheadTypeCmt = [0x43, 0x4d, 0x54]; // "CMT"
const List<int> subheadTypeQOpen = [0x51, 0x4f]; // "QO"
const List<int> subheadTypeRr = [0x52, 0x52]; // "RR"
const List<int> subheadTypeUOwner = [0x55, 0x4f, 0x57]; // "UOW"

// RAR 5.0 FHEXTRA_HTIME flags.
const int fhExtraHtimeUnixTime = 0x01;
const int fhExtraHtimeMtime = 0x02;
const int fhExtraHtimeCtime = 0x04;
const int fhExtraHtimeAtime = 0x08;
const int fhExtraHtimeUnixNs = 0x10;

// RAR 5.0 FHEXTRA_UOWNER flags.
const int fhExtraUownerNumUid = 0x01;
const int fhExtraUownerNumGid = 0x02;
const int fhExtraUownerUname = 0x04;
const int fhExtraUownerGname = 0x08;

// RAR 5.0 FHEXTRA_REDIR flags.
const int fhExtraRedirDir = 0x01;
const int sizeSalt50 = 16;
const int sizeSalt30 = 8;
const int sizeInitV = 16;
const int sizePswCheck = 8;

// Limits.
const int maxHeaderSizeRar5 = 0x200000;
const int maxPathSize = 0x10000;
const int maxSfxSize = 0x400000;

/// Sentinel indicating an unknown unpacked size.
const int int64Ndf = 0x7FFFFFFF7FFFFFFF;

/// RAR 5.0 header types and RAR 1.5 - 4.x header types.
enum HeaderType {
  // RAR 5.0 header types.
  headMark(0x00),
  headMain(0x01),
  headFile(0x02),
  headService(0x03),
  headCrypt(0x04),
  headEndArc(0x05),
  headUnknown(0xff),

  // RAR 1.5 - 4.x header types.
  head3Mark(0x72),
  head3Main(0x73),
  head3File(0x74),
  head3Cmt(0x75),
  head3Av(0x76),
  head3OldService(0x77),
  head3Protect(0x78),
  head3Sign(0x79),
  head3Service(0x7a),
  head3EndArc(0x7b);

  const HeaderType(this.value);

  final int value;
}

/// Detected RAR archive format.
enum RarFormat {
  rarFmtNone(0),
  rarFmt14(1),
  rarFmt15(2),
  rarFmt50(3),
  rarFmtFuture(4);

  const RarFormat(this.value);

  final int value;
}

/// Host operating system (RAR 3.0/4.x).
const int hostMsDos = 0;
const int hostOs2 = 1;
const int hostWin32 = 2;
const int hostUnix = 3;
const int hostMacOs = 4;
const int hostBeos = 5;
const int hostMax = 6;

/// Host operating system (RAR 5.0).
const int host5Windows = 0;
const int host5Unix = 1;

/// Unified, format-independent host system classification.
enum HostSystemType {
  hsysWindows,
  hsysUnix,
  hsysUnknown,
}

/// File system redirects stored in RAR 5.0 extra fields.
enum FileSystemRedirect {
  fsRedirNone(0),
  fsRedirUnixSymlink(1),
  fsRedirWinSymlink(2),
  fsRedirJunction(3),
  fsRedirHardLink(4),
  fsRedirFileCopy(5);

  const FileSystemRedirect(this.value);

  final int value;
}
