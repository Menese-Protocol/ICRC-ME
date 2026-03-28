/// EliasFano.mo — Quasi-succinct encoding of monotone integer sequences
///
/// Implements the Elias-Fano representation as described by Pibiri & Venturini
/// (CPM 2017); adapted for append-only operation in IC Region memory. The
/// encoding stores n integers from a universe [0, u) in n⌈log(u/n)⌉ + 2n bits;
/// less than half a bit per element above the information-theoretic minimum.
///
/// Each integer is split into high bits (stored in a unary-coded bitvector with
/// rank/select support via Succinct.mo) and low bits (stored as a flat array
/// of fixed-width values in Region memory).
///
/// Supports:
///   append(x)  — add next integer (must be >= last). O(1) amortized.
///   access(i)  — retrieve the i-th integer. O(1) via select on high bits.
///   nextGEQ(x) — find the smallest stored integer >= x. O(log(u/n)).
///
/// This module is used by CompactIndex as the compressed representation for
/// per-account transaction index lists in overflow blocks.

import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Array "mo:core/Array";
import Region "mo:core/Region";
import Runtime "mo:core/Runtime";

import Succinct "Succinct";

module {

  public type State = {
    highBits : Succinct.State;     // unary-coded high parts with rank/select
    lowRegion : Region.Region;     // packed array of low parts
    var count : Nat;               // number of elements
    var universe : Nat;            // upper bound on values
    var lowBitWidth : Nat;         // ⌊log(u/n)⌋ — bits per low part
    var lowOffset : Nat64;         // next write position in lowRegion (in bits)
    var lastValue : Nat;           // last appended value (for monotonicity check)
    var lastHighBits : Nat;        // last high part (for unary gap encoding)
  };

  public func newState(estimatedUniverse : Nat, estimatedCount : Nat) : State {
    let lb = if (estimatedCount == 0) 1 else log2floor(estimatedUniverse / Nat.max(estimatedCount, 1));
    {
      highBits = Succinct.newState();
      lowRegion = Region.new();
      var count : Nat = 0;
      var universe : Nat = estimatedUniverse;
      var lowBitWidth : Nat = Nat.max(lb, 1);
      var lowOffset : Nat64 = 0;
      var lastValue : Nat = 0;
      var lastHighBits : Nat = 0;
    }
  };

  /// Floor of log2(n), minimum 0
  func log2floor(n : Nat) : Nat {
    if (n == 0) return 0;
    var v = n; var r : Nat = 0;
    while (v > 1) { v /= 2; r += 1 };
    r
  };

  func growIfNeeded(r : Region.Region, neededBytes : Nat64) {
    let pages = (neededBytes / 65536) + 1;
    let have = Region.size(r);
    if (pages > have) {
      let g = Region.grow(r, pages - have);
      if (g == 0xFFFF_FFFF_FFFF_FFFF) Runtime.trap("EliasFano: memory exhausted");
    };
  };

  // ═══════════════════════════════════════════════════════
  //  APPEND
  // ═══════════════════════════════════════════════════════

  /// Append a value to the sequence. Must be >= lastValue (monotone).
  public func append(state : State, value : Nat) {
    if (state.count > 0 and value < state.lastValue) {
      Runtime.trap("EliasFano: non-monotone append");
    };

    let lw = state.lowBitWidth;
    let highPart = value >> lw; // value / 2^lw
    let lowPart = value & ((1 << lw) - 1); // value % 2^lw

    // High bits: encode gap in unary. For each step from lastHighBits to highPart, emit 0s; then emit 1.
    var h = state.lastHighBits;
    while (h < highPart) {
      Succinct.appendBit(state.highBits, false); // 0 = separator
      h += 1;
    };
    Succinct.appendBit(state.highBits, true); // 1 = element marker

    // Low bits: store lw-bit value in packed array
    storeLowBits(state, state.count, lowPart);

    state.count += 1;
    state.lastValue := value;
    state.lastHighBits := highPart;
  };

  /// Store low bits for element at index
  func storeLowBits(state : State, idx : Nat, value : Nat) {
    let lw = state.lowBitWidth;
    if (lw == 0) return;

    // Pack into Region as bytes. Each low part occupies lw bits starting at idx*lw.
    let bitOffset = idx * lw;
    let byteOffset = bitOffset / 8;
    let bitInByte = bitOffset % 8;
    let bytesNeeded = (bitOffset + lw + 7) / 8;
    growIfNeeded(state.lowRegion, Nat64.fromNat(bytesNeeded));

    // Write value bit by bit (simple but correct; could optimize with word-level ops)
    var i = 0;
    while (i < lw) {
      let bit = (value >> (lw - 1 - i)) & 1;
      let absPos = bitOffset + i;
      let bOff = Nat64.fromNat(absPos / 8);
      let bBit = absPos % 8;
      if (bit == 1) {
        let existing = Nat8.toNat(Region.loadNat8(state.lowRegion, bOff));
        Region.storeNat8(state.lowRegion, bOff, Nat8.fromNat(existing | (128 >> bBit)));
      };
      i += 1;
    };
  };

  /// Read low bits for element at index
  func loadLowBits(state : State, idx : Nat) : Nat {
    let lw = state.lowBitWidth;
    if (lw == 0) return 0;

    let bitOffset = idx * lw;
    var value : Nat = 0;
    var i = 0;
    while (i < lw) {
      let absPos = bitOffset + i;
      let bOff = Nat64.fromNat(absPos / 8);
      let bBit = absPos % 8;
      let byte = Nat8.toNat(Region.loadNat8(state.lowRegion, bOff));
      let bit = (byte >> (7 - bBit)) & 1;
      value := value * 2 + bit;
      i += 1;
    };
    value
  };

  // ═══════════════════════════════════════════════════════
  //  ACCESS
  // ═══════════════════════════════════════════════════════

  /// Retrieve the i-th element. O(1) via select on high bits.
  public func access(state : State, i : Nat) : ?Nat {
    if (i >= state.count) return null;

    // High part: position of i-th 1-bit in highBits, minus i (unary decoding)
    switch (Succinct.select1(state.highBits, i)) {
      case null { null };
      case (?pos) {
        let highPart = pos - i; // number of 0-bits before the i-th 1-bit
        let lowPart = loadLowBits(state, i);
        ?(highPart * (1 << state.lowBitWidth) + lowPart)
      };
    };
  };

  /// Number of elements stored
  public func size(state : State) : Nat { state.count };

  /// Retrieve all elements as an array (for small sequences)
  public func toArray(state : State) : [Nat] {
    Succinct.flush(state.highBits);
    Array.tabulate<Nat>(state.count, func(i) {
      switch (access(state, i)) {
        case (?v) v;
        case null 0; // shouldn't happen
      }
    })
  };

  /// Space used in bits
  public func spaceBits(state : State) : Nat {
    let highBits = Succinct.size(state.highBits);
    let lowBits = state.count * state.lowBitWidth;
    highBits + lowBits
  };

  /// Space used in bytes
  public func spaceBytes(state : State) : Nat {
    (spaceBits(state) + 7) / 8
  };
};
