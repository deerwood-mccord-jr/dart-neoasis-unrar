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

/// Returns `true` if [year] is a leap year, matching `IsLeapYear`.
bool isLeapYear(int year) =>
    (year & 3) == 0 && (year % 100 != 0 || year % 400 == 0);
