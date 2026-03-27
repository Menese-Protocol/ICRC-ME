/// MerkleMMR.mo — Merkle Mountain Range for O(log n) inclusion proofs
///
/// A Merkle Mountain Range (MMR) is an append-only accumulator that provides:
///   - O(1) append (amortized)
///   - O(log n) proof of inclusion for any leaf
///   - O(log n) root hash computation
///
/// Used by Bitcoin (via Mimblewimble/Grin), Polkadot, and now this ledger.
///
/// Structure: MMR is a forest of perfect binary Merkle trees.
/// When appending leaf N, if there are two trees of the same height,
/// they merge into one tree of height+1. This repeats until no
/// two trees share a height.
///
/// Example after 7 leaves:
///          6
///        /   \
///       2     5
///      / \   / \
///     0   1 3   4   <- leaves at positions 0-4
///
///                    7  <- peak at position 7 (single leaf)
///
/// Peaks: [6, 7] — the roots of each tree in the forest.
/// Root = H(H(peak0) || H(peak1) || ...)
///
/// Storage: peaks stored in a compact array. On append, peaks merge
/// bottom-up. Only O(log n) peaks exist at any time.

import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Blob "mo:core/Blob";
import VarArray "mo:core/VarArray";
import List "mo:core/List";

import Sha256 "mo:sha2/Sha256";

module {

  // ═══════════════════════════════════════════════════════
  //  STABLE STATE
  // ═══════════════════════════════════════════════════════

  /// MMR state: peaks array + leaf count + internal node hashes for proof generation
  /// peaks[i] = hash of a perfect binary tree of height i (or null if no tree at that height)
  /// Max 64 peaks supports 2^64 leaves (~18 quintillion)
  public type State = {
    var peaks : [var ?Blob]; // peaks[height] = hash or null
    var leafCount : Nat;
    var leafHashes : List.List<Blob>; // all leaf hashes for proof generation
  };

  let MAX_HEIGHT : Nat = 64;

  public func newState() : State {
    { var peaks = VarArray.repeat<?Blob>(null, MAX_HEIGHT); var leafCount = 0; var leafHashes = List.empty<Blob>() };
  };

  // ═══════════════════════════════════════════════════════
  //  CORE OPERATIONS
  // ═══════════════════════════════════════════════════════

  /// Hash two children into a parent node: H(0x01 || left || right)
  /// Domain separation: 0x00 for leaf, 0x01 for internal
  func hashNode(left : Blob, right : Blob) : Blob {
    let digest = Sha256.Digest(#sha256);
    digest.writeArray([0x01]); // internal node marker
    digest.writeBlob(left);
    digest.writeBlob(right);
    digest.sum()
  };

  /// Hash a leaf: H(0x00 || data)
  public func hashLeaf(data : Blob) : Blob {
    let digest = Sha256.Digest(#sha256);
    digest.writeArray([0x00]); // leaf marker
    digest.writeBlob(data);
    digest.sum()
  };

  /// Append a leaf hash to the MMR. Returns the new leaf index.
  /// O(log n) amortized — merges peaks of equal height.
  public func append(state : State, leafHash : Blob) : Nat {
    let idx = state.leafCount;
    List.add(state.leafHashes, leafHash); // store for proof generation
    var current = leafHash;
    var height : Nat = 0;

    // Merge with existing peaks of the same height (like binary addition carry)
    while (height < MAX_HEIGHT) {
      switch (state.peaks[height]) {
        case (?existing) {
          // Two trees of same height → merge into height+1
          current := hashNode(existing, current);
          state.peaks[height] := null;
          height += 1;
        };
        case null {
          // No tree at this height → place here
          state.peaks[height] := ?current;
          state.leafCount += 1;
          return idx;
        };
      };
    };
    // Should never reach here with < 2^64 leaves
    state.leafCount += 1;
    idx
  };

  /// Compute the MMR root hash by hashing all peaks right-to-left.
  /// root = H(peaks[highest] || H(peaks[next] || ...))
  /// O(log n) — at most 64 peaks.
  public func rootHash(state : State) : ?Blob {
    if (state.leafCount == 0) return null;

    // Collect non-null peaks from highest to lowest
    var result : ?Blob = null;
    var h : Nat = MAX_HEIGHT;
    while (h > 0) {
      h -= 1;
      switch (state.peaks[h]) {
        case (?peak) {
          result := switch (result) {
            case null ?peak;
            case (?acc) ?hashNode(peak, acc);
          };
        };
        case null {};
      };
    };
    result
  };

  /// Get the number of peaks (= number of 1-bits in leafCount)
  public func peakCount(state : State) : Nat {
    var count : Nat = 0;
    for (p in state.peaks.vals()) {
      switch (p) { case (?_) count += 1; case null {} };
    };
    count
  };

  /// Generate an inclusion proof for a leaf at the given index.
  /// Returns sibling hashes + peaks for full root reconstruction.
  public func generateProof(
    state : State,
    leafIndex : Nat,
  ) : ?{ siblings : [Blob]; peakIndex : Nat; peaks : [Blob] } {
    if (leafIndex >= state.leafCount) return null;

    let allLeaves = List.toArray(state.leafHashes);

    // Find which peak-tree this leaf belongs to (highest height first)
    var treeStart : Nat = 0;
    var treeHeight : Nat = 0;
    var found = false;
    var peakHeightIdx : Nat = 0;

    var h : Nat = MAX_HEIGHT;
    while (h > 0 and not found) {
      h -= 1;
      switch (state.peaks[h]) {
        case (?_) {
          let treeSize = 2 ** h;
          if (leafIndex < treeStart + treeSize) {
            treeHeight := h;
            peakHeightIdx := h;
            found := true;
          } else {
            treeStart += treeSize;
          };
        };
        case null {};
      };
    };

    if (not found) return null;

    // Build Merkle proof within this tree using stored leaf hashes
    let localIndex = leafIndex - treeStart;
    let treeSize = 2 ** treeHeight;
    let siblings = List.empty<Blob>();

    // Extract this tree's leaves
    var level = VarArray.repeat<Blob>("" : Blob, treeSize);
    var li = 0;
    while (li < treeSize) {
      level[li] := allLeaves[treeStart + li];
      li += 1;
    };

    // Walk up: at each level, record sibling, then compute parent level
    var idx = localIndex;
    var currentSize = treeSize;
    while (currentSize > 1) {
      let sibIdx = if (idx % 2 == 0) idx + 1 else idx - 1;
      List.add(siblings, level[sibIdx]);
      // Compute next level
      let halfSize = currentSize / 2;
      let nextLevel = VarArray.repeat<Blob>("" : Blob, halfSize);
      var j = 0;
      while (j < halfSize) {
        nextLevel[j] := hashNode(level[j * 2], level[j * 2 + 1]);
        j += 1;
      };
      level := nextLevel;
      idx /= 2;
      currentSize := halfSize;
    };

    // Collect all peaks (high-to-low)
    let peakList = List.empty<Blob>();
    var peakIdx : Nat = 0;
    var targetPeakIdx : Nat = 0;
    var pi : Nat = MAX_HEIGHT;
    while (pi > 0) {
      pi -= 1;
      switch (state.peaks[pi]) {
        case (?peak) {
          List.add(peakList, peak);
          if (pi == peakHeightIdx) { targetPeakIdx := peakIdx };
          peakIdx += 1;
        };
        case null {};
      };
    };

    ?{
      siblings = List.toArray(siblings);
      peakIndex = targetPeakIdx;
      peaks = List.toArray(peakList);
    }
  };

  /// Verify an inclusion proof: given a leaf hash, siblings, and peaks,
  /// reconstruct the root and compare.
  public func verifyProof(
    leafHash : Blob,
    siblings : [Blob],
    leafIndex : Nat,
    expectedRoot : Blob,
    peaks : [Blob],
    peakIndex : Nat,
  ) : Bool {
    // Reconstruct peak from leaf + siblings
    var current = leafHash;
    var idx = leafIndex;
    for (sib in siblings.vals()) {
      if (idx % 2 == 0) {
        current := hashNode(current, sib);
      } else {
        current := hashNode(sib, current);
      };
      idx /= 2;
    };

    // Verify this matches the claimed peak
    if (peakIndex >= peaks.size()) return false;
    if (current != peaks[peakIndex]) return false;

    // Reconstruct root from peaks (right-to-left fold)
    var root : ?Blob = null;
    var i = peaks.size();
    while (i > 0) {
      i -= 1;
      root := switch (root) {
        case null ?peaks[i];
        case (?acc) ?hashNode(peaks[i], acc);
      };
    };

    switch (root) {
      case (?r) r == expectedRoot;
      case null false;
    };
  };
};
