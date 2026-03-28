/// Succinct.mo — Rank/Select bitvector in Region memory
///
/// Implements a succinct bitvector with O(1) rank and O(log n) select queries;
/// stored entirely in Region stable memory. This is the foundational primitive
/// for Elias-Fano encoding and other compressed data structures.
///
/// Design: Poppy-style three-level directory (Vigna, 2008; Zhou et al., 2013).
///   Level 0 (superblock): cumulative popcount every 2048 bits (8 bytes per superblock)
///   Level 1 (block): relative popcount every 64 bits (2 bytes per block, delta from L0)
///   Data: raw 64-bit words
///
/// Space overhead: ~3.125% beyond the raw bits.
///   For 10B bits: 1.25GB data + ~39MB directory.
///
/// Operations:
///   rank1(i)  — count of 1-bits in positions [0, i). O(1).
///   select1(k) — position of the k-th 1-bit. O(log n) via binary search on rank.
///   access(i)  — value of bit at position i. O(1).
///   append(bit) — add a bit at the end. O(1) amortized.
///
/// Reference: Zhou, Andersen, Kaminsky. "Space-Efficient, High-Performance
/// Rank and Select Structures on Uncompressed Bit Sequences" (SEA 2013).

import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat16 "mo:core/Nat16";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Region "mo:core/Region";
import Runtime "mo:core/Runtime";

module {

  // Bits per word, block, superblock
  let WORD_BITS : Nat = 64;
  let WORDS_PER_SUPERBLOCK : Nat = 32; // 32 words = 2048 bits per superblock
  let BITS_PER_SUPERBLOCK : Nat = 2048;

  public type State = {
    dataRegion : Region.Region;    // raw 64-bit words
    dirRegion : Region.Region;     // L0 (Nat64 per superblock) + L1 (Nat16 per word)
    var bitCount : Nat;            // total bits stored
    var oneCount : Nat;            // total 1-bits
    var currentWord : Nat64;       // buffered word being built
    var wordPos : Nat;             // position within currentWord (0-63)
  };

  public func newState() : State {
    {
      dataRegion = Region.new();
      dirRegion = Region.new();
      var bitCount : Nat = 0;
      var oneCount : Nat = 0;
      var currentWord : Nat64 = 0;
      var wordPos : Nat = 0;
    }
  };

  func growIfNeeded(r : Region.Region, needed : Nat64) {
    let pages = (needed / 65536) + 1;
    let have = Region.size(r);
    if (pages > have) {
      let g = Region.grow(r, pages - have);
      if (g == 0xFFFF_FFFF_FFFF_FFFF) Runtime.trap("Succinct: memory exhausted");
    };
  };

  /// Software popcount (count 1-bits in a Nat64)
  func popcount64(x : Nat64) : Nat {
    var v = Nat64.toNat(x);
    var count = 0;
    while (v > 0) { count += 1; v := v & (v - 1) }; // Kernighan's method
    count
  };

  /// Number of completed words
  func wordCount(state : State) : Nat { state.bitCount / WORD_BITS };

  // ═══════════════════════════════════════════════════════
  //  APPEND
  // ═══════════════════════════════════════════════════════

  /// Append a single bit (0 or 1)
  public func appendBit(state : State, bit : Bool) {
    if (bit) {
      // Set bit at wordPos in currentWord
      let mask = Nat64.fromNat(1) << Nat64.fromNat(Nat64.toNat(63 - Nat64.fromNat(state.wordPos)));
      state.currentWord := state.currentWord | mask;
      state.oneCount += 1;
    };
    state.wordPos += 1;
    state.bitCount += 1;

    if (state.wordPos == WORD_BITS) {
      // Flush word to data region
      let wordIdx = wordCount(state) - 1; // we just incremented bitCount
      let wordOff = Nat64.fromNat(wordIdx * 8);
      growIfNeeded(state.dataRegion, wordOff + 8);
      Region.storeNat64(state.dataRegion, wordOff, state.currentWord);

      // Update directory
      updateDirectory(state, wordIdx, state.currentWord);

      state.currentWord := 0;
      state.wordPos := 0;
    };
  };

  /// Flush partial word (call before querying if there are pending bits)
  public func flush(state : State) {
    if (state.wordPos > 0) {
      let wordIdx = state.bitCount / WORD_BITS;
      let wordOff = Nat64.fromNat(wordIdx * 8);
      growIfNeeded(state.dataRegion, wordOff + 8);
      Region.storeNat64(state.dataRegion, wordOff, state.currentWord);
      updateDirectory(state, wordIdx, state.currentWord);
    };
  };

  /// Update L0/L1 directory after writing a word
  func updateDirectory(state : State, wordIdx : Nat, word : Nat64) {
    let superblockIdx = wordIdx / WORDS_PER_SUPERBLOCK;
    let wordInSuperblock = wordIdx % WORDS_PER_SUPERBLOCK;
    let pc = popcount64(word);

    // Directory layout in dirRegion:
    //   For each superblock: [L0:8 bytes (cumulative)] + [L1: 32 × 2 bytes (relative)]
    //   Total per superblock: 8 + 64 = 72 bytes
    let sbOff = Nat64.fromNat(superblockIdx * 72);
    growIfNeeded(state.dirRegion, sbOff + 72);

    if (wordInSuperblock == 0) {
      // Start of new superblock; L0 = total 1-bits before this superblock
      let prevOnes = state.oneCount - pc; // oneCount was already incremented
      Region.storeNat64(state.dirRegion, sbOff, Nat64.fromNat(prevOnes));
      // L1[0] = 0 (relative to L0)
      Region.storeNat16(state.dirRegion, sbOff + 8, 0);
    } else {
      // L1[wordInSuperblock] = cumulative popcount within this superblock
      // Read previous L1 and add
      let prevL1Off = sbOff + 8 + Nat64.fromNat((wordInSuperblock - 1) * 2);
      let prevL1 = Nat16.toNat(Region.loadNat16(state.dirRegion, prevL1Off));
      let prevWord = Region.loadNat64(state.dataRegion, Nat64.fromNat((wordIdx - 1) * 8));
      let prevPc = popcount64(prevWord);
      let newL1 = prevL1 + prevPc;
      let l1Off = sbOff + 8 + Nat64.fromNat(wordInSuperblock * 2);
      Region.storeNat16(state.dirRegion, l1Off, Nat16.fromNat(newL1 % 65536));
    };
  };

  // ═══════════════════════════════════════════════════════
  //  RANK
  // ═══════════════════════════════════════════════════════

  /// rank1(i) — count of 1-bits in positions [0, i)
  public func rank1(state : State, i : Nat) : Nat {
    if (i == 0) return 0;
    if (i >= state.bitCount) return state.oneCount;

    let wordIdx = i / WORD_BITS;
    let bitInWord = i % WORD_BITS;
    let superblockIdx = wordIdx / WORDS_PER_SUPERBLOCK;
    let wordInSuperblock = wordIdx % WORDS_PER_SUPERBLOCK;

    // L0: cumulative count before this superblock
    let sbOff = Nat64.fromNat(superblockIdx * 72);
    let l0 = Nat64.toNat(Region.loadNat64(state.dirRegion, sbOff));

    // L1: cumulative count within superblock before this word
    let l1 = Nat16.toNat(Region.loadNat16(state.dirRegion, sbOff + 8 + Nat64.fromNat(wordInSuperblock * 2)));

    // Popcount of partial word up to bitInWord
    let word = Region.loadNat64(state.dataRegion, Nat64.fromNat(wordIdx * 8));
    // Mask: keep only the top bitInWord bits
    let mask = if (bitInWord == 0) (0 : Nat64) else {
      Nat64.fromNat(0xFFFFFFFFFFFFFFFF) << Nat64.fromNat(64 - bitInWord)
    };
    let partialPc = popcount64(word & mask);

    l0 + l1 + partialPc
  };

  // ═══════════════════════════════════════════════════════
  //  SELECT
  // ═══════════════════════════════════════════════════════

  /// select1(k) — position of the k-th 1-bit (0-indexed). Returns null if k >= oneCount.
  public func select1(state : State, k : Nat) : ?Nat {
    if (k >= state.oneCount) return null;

    // Binary search on superblocks for the one containing the k-th 1-bit
    let numSuperblocks = (state.bitCount + BITS_PER_SUPERBLOCK - 1) / BITS_PER_SUPERBLOCK;
    var lo : Nat = 0;
    var hi : Nat = numSuperblocks;
    while (lo < hi) {
      let mid = (lo + hi) / 2;
      let sbOff = Nat64.fromNat(mid * 72);
      let l0 = Nat64.toNat(Region.loadNat64(state.dirRegion, sbOff));
      if (l0 <= k) { lo := mid + 1 } else { hi := mid };
    };
    let sb = if (lo > 0) lo - 1 else 0;
    let sbOff = Nat64.fromNat(sb * 72);
    var remaining = k - Nat64.toNat(Region.loadNat64(state.dirRegion, sbOff));

    // Linear scan words within superblock
    let startWord = sb * WORDS_PER_SUPERBLOCK;
    let endWord = Nat.min(startWord + WORDS_PER_SUPERBLOCK, wordCount(state) + 1);
    var w = startWord;
    while (w < endWord) {
      let word = Region.loadNat64(state.dataRegion, Nat64.fromNat(w * 8));
      let pc = popcount64(word);
      if (pc > remaining) {
        // The k-th 1-bit is in this word; find its position
        var bit = 0;
        var seen = 0;
        let wn = Nat64.toNat(word);
        while (bit < 64) {
          if ((wn >> (63 - bit)) & 1 == 1) {
            if (seen == remaining) return ?(w * 64 + bit);
            seen += 1;
          };
          bit += 1;
        };
      };
      remaining -= pc;
      w += 1;
    };
    null // shouldn't reach here
  };

  // ═══════════════════════════════════════════════════════
  //  ACCESS
  // ═══════════════════════════════════════════════════════

  /// Get the bit at position i
  public func access(state : State, i : Nat) : Bool {
    if (i >= state.bitCount) Runtime.trap("Succinct: access out of bounds");
    let wordIdx = i / WORD_BITS;
    let bitInWord = i % WORD_BITS;
    let word = Region.loadNat64(state.dataRegion, Nat64.fromNat(wordIdx * 8));
    (Nat64.toNat(word) >> (63 - bitInWord)) & 1 == 1
  };

  /// Total bits stored
  public func size(state : State) : Nat { state.bitCount };

  /// Total 1-bits
  public func ones(state : State) : Nat { state.oneCount };
};
