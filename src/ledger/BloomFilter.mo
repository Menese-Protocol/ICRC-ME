/// BloomFilter.mo — Time-windowed Bloom filter for O(1) transaction deduplication
///
/// Replaces O(log n) Map lookup for the 99%+ case where a timestamp
/// is NOT a duplicate. False positives fall through to the Map for
/// exact checking. False negatives are impossible.
///
/// Design: Two filters (current + previous window), swapped on expiry.
/// No per-element pruning needed — just clear the old filter.
///
/// Parameters for 10K elements, 1% false positive rate:
///   m = 95,851 bits (~12 KB)
///   k = 7 hash functions
///
/// Uses FNV-1a hash with different seeds for each of k functions.

import Nat "mo:core/Nat";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import VarArray "mo:core/VarArray";

module {

  // ═══════════════════════════════════════════════════════
  //  CONFIGURATION
  // ═══════════════════════════════════════════════════════

  // ~12KB per filter, 1% false positive rate at 10K elements
  let FILTER_BITS : Nat32 = 95851;
  let FILTER_WORDS : Nat = 2996; // ceil(95851 / 32)
  let NUM_HASHES : Nat32 = 7;

  // FNV-1a constants (32-bit)
  let FNV_OFFSET : Nat32 = 2166136261;
  let FNV_PRIME : Nat32 = 16777619;

  // ═══════════════════════════════════════════════════════
  //  STATE
  // ═══════════════════════════════════════════════════════

  public type State = {
    var current : [var Nat32];  // current window bit array
    var previous : [var Nat32]; // previous window bit array
    var windowStart : Nat64;    // timestamp when current window started
    windowDuration : Nat64;     // window size in nanoseconds
  };

  public func newState(windowDurationNs : Nat64) : State {
    {
      var current = VarArray.repeat<Nat32>(0, FILTER_WORDS);
      var previous = VarArray.repeat<Nat32>(0, FILTER_WORDS);
      var windowStart : Nat64 = 0;
      windowDuration = windowDurationNs;
    };
  };

  // ═══════════════════════════════════════════════════════
  //  HASH FUNCTIONS (FNV-1a with seed mixing)
  // ═══════════════════════════════════════════════════════

  /// FNV-1a hash of a Nat64 value with a seed
  func fnv1a(value : Nat64, seed : Nat32) : Nat32 {
    let v = Nat64.toNat(value);
    var hash = FNV_OFFSET ^ seed;
    // Process 8 bytes of the Nat64
    hash := (hash ^ Nat32.fromNat(v % 256)) *% FNV_PRIME;
    hash := (hash ^ Nat32.fromNat((v / 256) % 256)) *% FNV_PRIME;
    hash := (hash ^ Nat32.fromNat((v / 65536) % 256)) *% FNV_PRIME;
    hash := (hash ^ Nat32.fromNat((v / 16777216) % 256)) *% FNV_PRIME;
    hash := (hash ^ Nat32.fromNat((v / 4294967296) % 256)) *% FNV_PRIME;
    hash := (hash ^ Nat32.fromNat((v / 1099511627776) % 256)) *% FNV_PRIME;
    hash := (hash ^ Nat32.fromNat((v / 281474976710656) % 256)) *% FNV_PRIME;
    hash := (hash ^ Nat32.fromNat((v / 72057594037927936) % 256)) *% FNV_PRIME;
    hash
  };

  // ═══════════════════════════════════════════════════════
  //  OPERATIONS
  // ═══════════════════════════════════════════════════════

  /// Rotate windows if the current window has expired
  func maybeRotate(state : State, now : Nat64) {
    if (state.windowStart == 0) {
      state.windowStart := now;
      return;
    };
    if (now > state.windowStart + state.windowDuration) {
      // Swap: current becomes previous, allocate new current
      state.previous := state.current;
      state.current := VarArray.repeat<Nat32>(0, FILTER_WORDS);
      state.windowStart := now;
    };
  };

  /// Set a bit in a filter
  func setBit(filter : [var Nat32], bitIndex : Nat32) {
    let wordIdx = Nat32.toNat(bitIndex / 32);
    let bitPos = bitIndex % 32;
    filter[wordIdx] := filter[wordIdx] | (1 << bitPos);
  };

  /// Test a bit in a filter
  func testBit(filter : [var Nat32], bitIndex : Nat32) : Bool {
    let wordIdx = Nat32.toNat(bitIndex / 32);
    let bitPos = bitIndex % 32;
    (filter[wordIdx] & (1 << bitPos)) != 0
  };

  /// Add a timestamp to the current filter
  public func add(state : State, timestamp : Nat64, now : Nat64) {
    maybeRotate(state, now);
    var i : Nat32 = 0;
    while (i < NUM_HASHES) {
      let h = fnv1a(timestamp, i) % FILTER_BITS;
      setBit(state.current, h);
      i += 1;
    };
  };

  /// Check if a timestamp MIGHT be in the filter.
  /// Returns false = DEFINITELY not seen (fast path, common case).
  /// Returns true = POSSIBLY seen (need Map fallback for exact check).
  public func mightContain(state : State, timestamp : Nat64, now : Nat64) : Bool {
    maybeRotate(state, now);
    // Check current filter
    var allSet = true;
    var i : Nat32 = 0;
    while (i < NUM_HASHES and allSet) {
      let h = fnv1a(timestamp, i) % FILTER_BITS;
      if (not testBit(state.current, h)) { allSet := false };
      i += 1;
    };
    if (allSet) return true;
    // Check previous filter (for timestamps in the overlap window)
    allSet := true;
    i := 0;
    while (i < NUM_HASHES and allSet) {
      let h = fnv1a(timestamp, i) % FILTER_BITS;
      if (not testBit(state.previous, h)) { allSet := false };
      i += 1;
    };
    allSet
  };
};
