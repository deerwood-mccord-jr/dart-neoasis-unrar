import 'dart:typed_data';

/// Copies an LZ match with RAR's forward-replication semantics and returns the
/// updated destination pointer.
///
/// [endMargin] is the decoder's maximum match size. If source and destination
/// are farther than this from the circular-window end, typed range operations
/// can be used without wrap checks. Otherwise the reference byte loop is used.
int copyLzMatch({
  required Uint8List window,
  required int destination,
  required int length,
  required int distance,
  required int windowSize,
  required bool firstWindowDone,
  required int endMargin,
}) {
  var source = destination - distance;

  if (distance > destination) {
    source += windowSize;
    if (distance > windowSize || !firstWindowDone) {
      while (length-- > 0) {
        window[destination] = 0;
        destination++;
        if (destination == windowSize) destination = 0;
      }
      return destination;
    }
  }

  if (distance > 0 &&
      source < windowSize - endMargin &&
      destination < windowSize - endMargin) {
    final start = destination;
    if (distance == 1) {
      window.fillRange(start, start + length, window[source]);
      return start + length;
    }
    if (distance >= length) {
      window.setRange(start, start + length, window, source);
      return start + length;
    }

    // Seed one full repetition from the preceding dictionary data. Each
    // subsequent range is copied from bytes produced by this same match. The
    // ranges are adjacent, not overlapping, so this does not degrade into
    // memmove semantics when distance < length.
    var produced = distance;
    window.setRange(start, start + produced, window, source);
    while (produced < length) {
      var chunk = produced;
      final remaining = length - produced;
      if (chunk > remaining) chunk = remaining;
      window.setRange(
          start + produced, start + produced + chunk, window, start);
      produced += chunk;
    }
    return start + length;
  }

  while (length-- > 0) {
    if (source >= windowSize) source -= windowSize;
    window[destination] = window[source++];
    destination++;
    if (destination == windowSize) destination = 0;
  }
  return destination;
}
