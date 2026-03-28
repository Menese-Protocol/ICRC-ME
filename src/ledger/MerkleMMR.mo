/// MerkleMMR.mo — Merkle Mountain Range for O(log n) inclusion proofs
///
/// Leaf hashes and internal node hashes are stored in Region stable memory.
/// Proof generation reads O(log n) hashes from Region — no recomputation.
///
/// Storage layout in Region:
///   Positions 0..N-1 map to MMR node positions (not leaf indices).
///   MMR position numbering follows the standard post-order scheme:
///     Leaf 0 → pos 0, Leaf 1 → pos 1, Internal → pos 2,
///     Leaf 2 → pos 3, etc.
///   Each position stores a 32-byte SHA-256 hash.
///
/// This gives O(1) append, O(log n) proof, O(log n) root computation.

import Nat "mo:core/Nat";
import Nat64 "mo:core/Nat64";
import Blob "mo:core/Blob";
import VarArray "mo:core/VarArray";
import List "mo:core/List";
import Region "mo:core/Region";
import Runtime "mo:core/Runtime";

import Sha256 "mo:sha2/Sha256";

module {

  let HASH_SIZE : Nat64 = 32;
  let MAX_HEIGHT : Nat = 64;

  public type State = {
    var peaks : [var ?Blob];
    var leafCount : Nat;
    var nodeCount : Nat;       // total MMR nodes (leaves + internals)
    var baggedRoot : ?Blob;    // pre-computed root hash — O(1) access
    hashRegion : Region.Region;
    var hashRegionSize : Nat64;
  };

  public func newState() : State {
    {
      var peaks = VarArray.repeat<?Blob>(null, MAX_HEIGHT);
      var leafCount = 0;
      var nodeCount = 0;
      var baggedRoot : ?Blob = null;
      hashRegion = Region.new();
      var hashRegionSize : Nat64 = 0;
    };
  };

  func growIfNeeded(region : Region.Region, needed : Nat64) {
    let pages = (needed / 65536) + 1;
    if (pages > Region.size(region)) {
      let g = Region.grow(region, pages - Region.size(region));
      if (g == 0xFFFF_FFFF_FFFF_FFFF) Runtime.trap("MerkleMMR: memory exhausted");
    };
  };

  func storeHash(state : State, pos : Nat, hash : Blob) {
    let off = Nat64.fromNat(pos) * HASH_SIZE;
    let needed = off + HASH_SIZE;
    growIfNeeded(state.hashRegion, needed);
    Region.storeBlob(state.hashRegion, off, hash);
    if (needed > state.hashRegionSize) { state.hashRegionSize := needed };
  };

  func loadHash(state : State, pos : Nat) : Blob {
    Region.loadBlob(state.hashRegion, Nat64.fromNat(pos) * HASH_SIZE, 32)
  };

  // ═══════════════════════════════════════════════════════
  //  HASH PRIMITIVES
  // ═══════════════════════════════════════════════════════

  func hashNode(left : Blob, right : Blob) : Blob {
    let digest = Sha256.Digest(#sha256);
    digest.writeArray([0x01]);
    digest.writeBlob(left);
    digest.writeBlob(right);
    digest.sum()
  };

  public func hashLeaf(data : Blob) : Blob {
    let digest = Sha256.Digest(#sha256);
    digest.writeArray([0x00]);
    digest.writeBlob(data);
    digest.sum()
  };

  // ═══════════════════════════════════════════════════════
  //  MMR POSITION ARITHMETIC
  //
  //  Standard MMR uses post-order positions:
  //    Height 0 (leaves): positions where all bits below height are 0
  //    The position of leaf i: i * 2 + popcount of merged trees
  //
  //  Simpler approach: store nodes sequentially as they're created.
  //  Leaf positions and internal positions interleave naturally.
  //  Track with a running counter (nodeCount).
  // ═══════════════════════════════════════════════════════

  /// Append a leaf hash. Stores leaf + all internal nodes created by merging.
  /// O(log n) amortized. Returns the leaf index (0-based).
  public func append(state : State, leafHash : Blob) : Nat {
    let leafIdx = state.leafCount;
    // Store leaf node
    let leafPos = state.nodeCount;
    storeHash(state, leafPos, leafHash);
    state.nodeCount += 1;

    var current = leafHash;
    var height : Nat = 0;
    while (height < MAX_HEIGHT) {
      switch (state.peaks[height]) {
        case (?existing) {
          // Merge: create internal node
          current := hashNode(existing, current);
          let internalPos = state.nodeCount;
          storeHash(state, internalPos, current);
          state.nodeCount += 1;
          state.peaks[height] := null;
          height += 1;
        };
        case null {
          state.peaks[height] := ?current;
          state.leafCount += 1;
          recomputeBaggedRoot(state);
          return leafIdx;
        };
      };
    };
    state.leafCount += 1;
    recomputeBaggedRoot(state);
    leafIdx
  };

  /// Recompute bagged root from peaks. Called once per append.
  func recomputeBaggedRoot(state : State) {
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
    state.baggedRoot := result;
  };

  /// Root hash — O(1) via pre-computed bagged root.
  public func rootHash(state : State) : ?Blob { state.baggedRoot };

  public func peakCount(state : State) : Nat {
    var count : Nat = 0;
    for (p in state.peaks.vals()) {
      switch (p) { case (?_) count += 1; case null {} };
    };
    count
  };

  /// Generate inclusion proof for a leaf. O(log n) Region reads.
  ///
  /// Strategy: Given leafIndex, we know the leaf's position in the MMR.
  /// The MMR node positions follow a predictable pattern based on the
  /// binary representation of the leaf count at insertion time.
  /// For each level of the proof, we compute the sibling's position
  /// and read its stored hash directly. No subtree recomputation needed.
  public func generateProof(
    state : State,
    leafIndex : Nat,
  ) : ?{ siblings : [Blob]; peakIndex : Nat; peaks : [Blob] } {
    if (leafIndex >= state.leafCount) return null;

    // Find which peak-tree contains this leaf
    var treeStart : Nat = 0;
    var treeHeight : Nat = 0;
    var found = false;
    var peakHeightIdx : Nat = 0;
    // Also track the MMR node position where this tree starts
    var treeNodeStart : Nat = 0;

    var h : Nat = MAX_HEIGHT;
    while (h > 0 and not found) {
      h -= 1;
      switch (state.peaks[h]) {
        case (?_) {
          let treeSize = 2 ** h; // number of leaves in this tree
          if (leafIndex < treeStart + treeSize) {
            treeHeight := h;
            peakHeightIdx := h;
            found := true;
          } else {
            treeStart += treeSize;
            // A perfect binary tree with 2^h leaves has 2^(h+1)-1 nodes
            treeNodeStart += 2 ** (h + 1) - 1;
          };
        };
        case null {};
      };
    };

    if (not found) return null;

    // Compute proof path using MMR node positions.
    // In a perfect binary tree stored in level-order within our sequential layout:
    //   - Leaves are at positions treeNodeStart + 0, +2, +4, ... (stride 2)
    //   - But we stored in creation order (post-order), not level-order.
    //
    // Simpler approach: rebuild the sibling path using the stored hashes.
    // At each level, compute the sibling subtree hash from stored nodes.
    // For a perfect binary tree, the sibling at level k needs 2^k leaf hashes
    // and we can read the stored internal node hash directly if we track positions.
    //
    // Most efficient: compute positions of all siblings using the binary structure.
    // The MMR node for a subtree root at height h containing 2^h leaves
    // is at a position we can calculate from (treeNodeStart, localIndex, height).
    let siblings = List.empty<Blob>();
    let localIndex = leafIndex - treeStart;

    // Walk the tree bottom-up. At each level, find sibling hash.
    // Use recursive subtree hash computation — but only read the ROOT of the sibling,
    // which is already stored in Region (stored during append).
    // The root of a subtree = the last node stored in that subtree's range.
    var idx = localIndex;
    var currentHeight : Nat = 0;
    while (currentHeight < treeHeight) {
      let subtreeLeaves = 2 ** currentHeight;
      let sibIdx = if (idx % 2 == 0) idx + 1 else idx - 1;
      // Compute the node position of the sibling subtree's root.
      // In our sequential storage, a subtree of height h starting at leaf offset L
      // within the tree has its root at:
      //   treeNodeStart + subtreeRootPos(L, h, treeHeight)
      let sibLeafStart = sibIdx * subtreeLeaves;
      let sibRootPos = subtreeRootPosition(treeNodeStart, sibLeafStart, currentHeight, treeHeight);
      List.add(siblings, loadHash(state, sibRootPos));
      idx /= 2;
      currentHeight += 1;
    };

    // Collect peaks
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

  /// Compute the node position of a subtree root within the sequential MMR layout.
  /// A perfect binary tree of height H stored in post-order has 2^(H+1)-1 nodes.
  /// The root is the LAST node. For a subtree at height h starting at leaf offset
  /// leafStart within a tree of height treeHeight:
  ///   - The subtree spans nodes [start..start + 2^(h+1) - 2]
  ///   - The root is at start + 2^(h+1) - 2
  func subtreeRootPosition(treeNodeStart : Nat, leafStart : Nat, subtreeHeight : Nat, treeHeight : Nat) : Nat {
    // In our post-order layout, leaf i of the tree is at position:
    //   treeNodeStart + nodePositionInTree(i, treeHeight)
    // A subtree rooted at height h covering leaves [L..L+2^h-1] has its root
    // at the position of the last node in that subtree.
    //
    // For a post-order traversal of a perfect binary tree:
    //   nodePosition(leafStart, height) gives us the start of the subtree
    //   The root of height-h subtree starting at leaf L is at:
    //   sum of nodes in all complete subtrees before L, plus 2^(h+1)-2
    var pos = treeNodeStart;
    // Walk the path from root to the subtree, accumulating node offsets
    var currentLeafStart : Nat = 0;
    var currentHeight = treeHeight;
    var targetLeafStart = leafStart;

    while (currentHeight > subtreeHeight) {
      let halfLeaves = 2 ** (currentHeight - 1);
      let leftSubtreeNodes = 2 ** currentHeight - 1; // nodes in left child
      if (targetLeafStart < currentLeafStart + halfLeaves) {
        // Go left — skip nothing, left subtree starts at pos
        currentHeight -= 1;
      } else {
        // Go right — skip left subtree + left subtree's nodes
        pos += leftSubtreeNodes;
        currentLeafStart += halfLeaves;
        currentHeight -= 1;
      };
    };
    // Now at the subtree root level. The root of a post-order subtree
    // of height h is the LAST node: pos + 2^(h+1) - 2
    pos + 2 ** (subtreeHeight + 1) - 2
  };

  /// Verify an inclusion proof.
  public func verifyProof(
    leafHash : Blob,
    siblings : [Blob],
    leafIndex : Nat,
    expectedRoot : Blob,
    peaks : [Blob],
    peakIndex : Nat,
  ) : Bool {
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

    if (peakIndex >= peaks.size()) return false;
    if (current != peaks[peakIndex]) return false;

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
