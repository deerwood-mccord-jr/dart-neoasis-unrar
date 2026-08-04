/// RAR time helpers ported from the RARLAB UnRAR source (`timefn.cpp`).
library;

/// Converts a DOS date/time field to a local [DateTime], matching
/// `RarTime::SetDos`. DOS stores the seconds with 2-second precision.
DateTime dosTimeToDateTime(int dosTime) {
  final second = (dosTime & 0x1f) * 2;
  final minute = (dosTime >> 5) & 0x3f;
  final hour = (dosTime >> 11) & 0x1f;
  final day = (dosTime >> 16) & 0x1f;
  final month = (dosTime >> 21) & 0x0f;
  final year = (dosTime >> 25) + 1980;
  return DateTime(year, month, day, hour, minute, second);
}

/// Converts a Unix time (`time_t`) to a UTC [DateTime], matching
/// `RarTime::SetUnix`.
DateTime unixTimeToDateTime(int unix) =>
    DateTime.fromMillisecondsSinceEpoch(unix * 1000, isUtc: true);

/// Converts a Unix time plus optional nanoseconds to a UTC [DateTime].
/// The nanoseconds are truncated to microsecond precision.
DateTime unixTimeToDateTimeWithNs(int unix, int nanoseconds) {
  final base = DateTime.fromMillisecondsSinceEpoch(unix * 1000, isUtc: true);
  final us = (nanoseconds ~/ 1000) % 1000;
  return base.add(Duration(microseconds: us));
}

/// Converts a Windows FILETIME value (100-nanosecond intervals since
/// 1601-01-01 UTC) to a UTC [DateTime], matching `RarTime::SetWin`.
DateTime winFileTimeToDateTime(int winTime) {
  // Windows FILETIME epoch: 1601-01-01 00:00:00 UTC.
  // Dart epoch: 1970-01-01 00:00:00 UTC.
  // Difference: 11644473600 seconds = 116444736000000000 × 100-ns intervals.
  const winEpochOffset = 116444736000000000; // 100-ns intervals to Unix epoch
  final us = (winTime - winEpochOffset) ~/ 10; // 100-ns → microseconds
  return DateTime.fromMicrosecondsSinceEpoch(us, isUtc: true);
}

/// Returns `true` if [year] is a leap year, matching `IsLeapYear`.
bool isLeapYear(int year) =>
    (year & 3) == 0 && (year % 100 != 0 || year % 400 == 0);
