/// RegionBTree.mo — B-tree in Region stable memory
///
/// A sorted key-value map stored entirely in IC Region memory. Page-aligned
/// nodes with configurable branching factor. Supports lookup, insert, and
/// sorted iteration. No deletion (append-only ledger semantics).
///
/// Design follows DFINITY's ic-stable-structures BTreeMap but adapted for
/// Motoko's Region API with fixed-size keys and values for zero-overhead
/// serialisation.
///
/// Node layout (8KB pages):
///   Leaf:     [type:1][count:2][entries: (key:K + value:V) × count]
///   Internal: [type:1][count:2][children:6×(count+1)][keys:K×count]
///
/// For K=62, V=10 (account key + chain head):
///   Leaf capacity:  (8192 - 3) / 72 = 113 entries
///   Internal:       keys + children fit ~109 keys, 110 children
///   Depth at 1B:    ~4 levels (log_110(1B) ≈ 4.4)
///   Total at 1B:    ~71GB (comparable to hash table approach)
///
/// Advantage over hash table: no fixed bucket allocation; grows naturally;
/// sorted iteration for range queries; no load factor degradation.

import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat16 "mo:core/Nat16";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Blob "mo:core/Blob";
import Array "mo:core/Array";
import List "mo:core/List";
import Region "mo:core/Region";
import Runtime "mo:core/Runtime";
import Order "mo:core/Order";


module {

  // ═══════════════════════════════════════════════════════
  //  CONFIGURATION
  // ═══════════════════════════════════════════════════════

  let PAGE_SIZE : Nat64 = 8192;     // 8KB per node
  let KEY_SIZE : Nat = 62;          // accountKeyToBlob output
  let VAL_SIZE : Nat = 16;          // [count:4][chain_head:6][chain_tail:6]
  let ENTRY_SIZE : Nat = 78;        // KEY_SIZE + VAL_SIZE
  let CHILD_PTR : Nat = 6;          // 48-bit node offset

  let LEAF_CAP : Nat = 104;      // (8192 - 3) / 78
  let INTERNAL_CAP : Nat = 120;  // (8192 - 3 - 6) / (62 + 6) — unchanged, internal nodes don't store values

  let NODE_LEAF : Nat8 = 0;
  let NODE_INTERNAL : Nat8 = 1;
  let NULL_NODE : Nat64 = 0xFFFF_FFFF_FFFF;

  // ═══════════════════════════════════════════════════════
  //  STATE
  // ═══════════════════════════════════════════════════════

  public type State = {
    region : Region.Region;
    var root : Nat64;        // offset of root node (NULL_NODE if empty)
    var nodeCount : Nat64;   // total allocated nodes
    var entryCount : Nat;    // total key-value pairs
  };

  public func newState() : State {
    { region = Region.new(); var root : Nat64 = NULL_NODE; var nodeCount : Nat64 = 0; var entryCount : Nat = 0 }
  };

  // ═══════════════════════════════════════════════════════
  //  NODE ACCESS HELPERS
  // ═══════════════════════════════════════════════════════

  func growIfNeeded(state : State, needed : Nat64) {
    let pages = (needed / 65536) + 1;
    let have = Region.size(state.region);
    if (pages > have) {
      let g = Region.grow(state.region, pages - have);
      if (g == 0xFFFF_FFFF_FFFF_FFFF) Runtime.trap("RegionBTree: memory exhausted");
    };
  };

  func allocNode(state : State, nodeType : Nat8) : Nat64 {
    let off = state.nodeCount * PAGE_SIZE;
    state.nodeCount += 1;
    growIfNeeded(state, (state.nodeCount) * PAGE_SIZE);
    Region.storeNat8(state.region, off, nodeType);
    Region.storeNat16(state.region, off + 1, 0); // count = 0
    off
  };

  func nodeType(state : State, node : Nat64) : Nat8 {
    Region.loadNat8(state.region, node)
  };

  func nodeCount(state : State, node : Nat64) : Nat {
    Nat16.toNat(Region.loadNat16(state.region, node + 1))
  };

  func setNodeCount(state : State, node : Nat64, count : Nat) {
    Region.storeNat16(state.region, node + 1, Nat16.fromNat(count));
  };

  // ── Leaf node access ──

  func leafKeyOff(node : Nat64, idx : Nat) : Nat64 {
    node + 3 + Nat64.fromNat(idx * ENTRY_SIZE)
  };

  func leafKey(state : State, node : Nat64, idx : Nat) : Blob {
    Region.loadBlob(state.region, leafKeyOff(node, idx), KEY_SIZE)
  };

  func leafVal(state : State, node : Nat64, idx : Nat) : Blob {
    Region.loadBlob(state.region, leafKeyOff(node, idx) + Nat64.fromNat(KEY_SIZE), VAL_SIZE)
  };

  func setLeafEntry(state : State, node : Nat64, idx : Nat, key : Blob, val : Blob) {
    Region.storeBlob(state.region, leafKeyOff(node, idx), key);
    Region.storeBlob(state.region, leafKeyOff(node, idx) + Nat64.fromNat(KEY_SIZE), val);
  };

  // ── Internal node access ──
  // Layout: [type:1][count:2][children:6×(count+1)][keys:62×count]

  func internalChildOff(node : Nat64, idx : Nat) : Nat64 {
    node + 3 + Nat64.fromNat(idx * CHILD_PTR)
  };

  func internalKeyOff(node : Nat64, idx : Nat) : Nat64 {
    // Keys start after max children: 3 + 6*(INTERNAL_CAP+1)
    node + 3 + Nat64.fromNat((INTERNAL_CAP + 1) * CHILD_PTR) + Nat64.fromNat(idx * KEY_SIZE)
  };

  func getChild(state : State, node : Nat64, idx : Nat) : Nat64 {
    let off = internalChildOff(node, idx);
    let lo = Nat32.toNat(Region.loadNat32(state.region, off));
    let hi = Nat16.toNat(Region.loadNat16(state.region, off + 4));
    Nat64.fromNat(lo + hi * 4294967296)
  };

  func setChild(state : State, node : Nat64, idx : Nat, child : Nat64) {
    let off = internalChildOff(node, idx);
    Region.storeNat32(state.region, off, Nat32.fromNat(Nat64.toNat(child) % 4294967296));
    Region.storeNat16(state.region, off + 4, Nat16.fromNat(Nat64.toNat(child) / 4294967296));
  };

  func internalKey(state : State, node : Nat64, idx : Nat) : Blob {
    Region.loadBlob(state.region, internalKeyOff(node, idx), KEY_SIZE)
  };

  func setInternalKey(state : State, node : Nat64, idx : Nat, key : Blob) {
    Region.storeBlob(state.region, internalKeyOff(node, idx), key);
  };

  // ═══════════════════════════════════════════════════════
  //  KEY COMPARISON
  // ═══════════════════════════════════════════════════════

  func compareKeys(a : Blob, b : Blob) : Order.Order {
    // Fixed-size keys (62 bytes) — use Blob.compare directly (avoids array allocation)
    Blob.compare(a, b)
  };

  /// Binary search in a leaf node. Returns the index where key would be inserted.
  func leafSearch(state : State, node : Nat64, key : Blob) : (Nat, Bool) {
    let count = nodeCount(state, node);
    if (count == 0) return (0, false);
    var lo = 0; var hi = count;
    while (lo < hi) {
      let mid = (lo + hi) / 2;
      switch (compareKeys(leafKey(state, node, mid), key)) {
        case (#less) { lo := mid + 1 };
        case (#equal) { return (mid, true) };
        case (#greater) { hi := mid };
      };
    };
    (lo, false)
  };

  /// Binary search in internal node for child index
  func internalSearch(state : State, node : Nat64, key : Blob) : Nat {
    let count = nodeCount(state, node);
    var lo = 0; var hi = count;
    while (lo < hi) {
      let mid = (lo + hi) / 2;
      switch (compareKeys(internalKey(state, node, mid), key)) {
        case (#less) { lo := mid + 1 };
        case (#equal) { return mid + 1 }; // go right on exact match
        case (#greater) { hi := mid };
      };
    };
    lo
  };

  // ═══════════════════════════════════════════════════════
  //  SHIFT HELPERS (for insertion)
  // ═══════════════════════════════════════════════════════

  func shiftLeafRight(state : State, node : Nat64, from : Nat, count : Nat) {
    // Shift entries [from..count-1] right by one
    var i = count;
    while (i > from) {
      let src = leafKeyOff(node, i - 1);
      let dst = leafKeyOff(node, i);
      let entry = Region.loadBlob(state.region, src, ENTRY_SIZE);
      Region.storeBlob(state.region, dst, entry);
      i -= 1;
    };
  };

  func shiftInternalRight(state : State, node : Nat64, from : Nat, count : Nat) {
    // Shift keys [from..count-1] and children [from+1..count] right by one
    var i = count;
    while (i > from) {
      let srcKey = internalKeyOff(node, i - 1);
      let dstKey = internalKeyOff(node, i);
      Region.storeBlob(state.region, dstKey, Region.loadBlob(state.region, srcKey, KEY_SIZE));
      let srcChild = internalChildOff(node, i);
      let dstChild = internalChildOff(node, i + 1);
      let childBytes = Region.loadBlob(state.region, srcChild, CHILD_PTR);
      Region.storeBlob(state.region, dstChild, childBytes);
      i -= 1;
    };
  };

  // ═══════════════════════════════════════════════════════
  //  SPLIT
  // ═══════════════════════════════════════════════════════

  type SplitResult = { medianKey : Blob; rightNode : Nat64 };

  func splitLeaf(state : State, node : Nat64) : SplitResult {
    let count = nodeCount(state, node);
    let mid = count / 2;
    let right = allocNode(state, NODE_LEAF);

    // Copy entries [mid..count-1] to right node
    var i = mid;
    var ri = 0;
    while (i < count) {
      let entry = Region.loadBlob(state.region, leafKeyOff(node, i), ENTRY_SIZE);
      Region.storeBlob(state.region, leafKeyOff(right, ri), entry);
      i += 1; ri += 1;
    };
    setNodeCount(state, right, count - mid);
    setNodeCount(state, node, mid);

    { medianKey = leafKey(state, right, 0); rightNode = right }
  };

  func splitInternal(state : State, node : Nat64) : SplitResult {
    let count = nodeCount(state, node);
    let mid = count / 2;
    let right = allocNode(state, NODE_INTERNAL);

    // Median key is promoted to parent
    let median = internalKey(state, node, mid);

    // Copy keys [mid+1..count-1] to right
    var i = mid + 1;
    var ri = 0;
    while (i < count) {
      setInternalKey(state, right, ri, internalKey(state, node, i));
      i += 1; ri += 1;
    };

    // Copy children [mid+1..count] to right
    i := mid + 1;
    ri := 0;
    while (i <= count) {
      setChild(state, right, ri, getChild(state, node, i));
      i += 1; ri += 1;
    };

    setNodeCount(state, right, count - mid - 1);
    setNodeCount(state, node, mid);

    { medianKey = median; rightNode = right }
  };

  // ═══════════════════════════════════════════════════════
  //  PUBLIC API
  // ═══════════════════════════════════════════════════════

  /// Lookup a value by key. O(log n) with ~4 Region reads at 1B entries.
  public func get(state : State, key : Blob) : ?Blob {
    var node = state.root;
    while (node != NULL_NODE) {
      if (nodeType(state, node) == NODE_LEAF) {
        let (idx, found) = leafSearch(state, node, key);
        if (found) return ?leafVal(state, node, idx);
        return null;
      } else {
        let childIdx = internalSearch(state, node, key);
        node := getChild(state, node, childIdx);
      };
    };
    null
  };

  /// Insert or update a key-value pair. Returns the previous value if key existed.
  /// Uses proactive splitting (split full nodes on the way down).
  public func put(state : State, key : Blob, val : Blob) : ?Blob {
    if (state.root == NULL_NODE) {
      let root = allocNode(state, NODE_LEAF);
      setLeafEntry(state, root, 0, key, val);
      setNodeCount(state, root, 1);
      state.root := root;
      state.entryCount += 1;
      return null;
    };

    // Check if root needs split
    let rootCount = nodeCount(state, state.root);
    let rootCap = if (nodeType(state, state.root) == NODE_LEAF) LEAF_CAP else INTERNAL_CAP;
    if (rootCount >= rootCap) {
      let split = if (nodeType(state, state.root) == NODE_LEAF) splitLeaf(state, state.root)
                  else splitInternal(state, state.root);
      let newRoot = allocNode(state, NODE_INTERNAL);
      setChild(state, newRoot, 0, state.root);
      setInternalKey(state, newRoot, 0, split.medianKey);
      setChild(state, newRoot, 1, split.rightNode);
      setNodeCount(state, newRoot, 1);
      state.root := newRoot;
    };

    insertNonFull(state, state.root, key, val)
  };

  /// Insert into a node that is guaranteed not full
  func insertNonFull(state : State, node : Nat64, key : Blob, val : Blob) : ?Blob {
    if (nodeType(state, node) == NODE_LEAF) {
      let count = nodeCount(state, node);
      let (idx, found) = leafSearch(state, node, key);
      if (found) {
        // Update existing
        let old = leafVal(state, node, idx);
        Region.storeBlob(state.region, leafKeyOff(node, idx) + Nat64.fromNat(KEY_SIZE), val);
        return ?old;
      };
      // Insert at idx, shift right
      shiftLeafRight(state, node, idx, count);
      setLeafEntry(state, node, idx, key, val);
      setNodeCount(state, node, count + 1);
      state.entryCount += 1;
      null
    } else {
      let childIdx = internalSearch(state, node, key);
      var child = getChild(state, node, childIdx);

      // Proactive split if child is full
      let childCount = nodeCount(state, child);
      let childCap = if (nodeType(state, child) == NODE_LEAF) LEAF_CAP else INTERNAL_CAP;
      if (childCount >= childCap) {
        let split = if (nodeType(state, child) == NODE_LEAF) splitLeaf(state, child)
                    else splitInternal(state, child);
        let count = nodeCount(state, node);
        shiftInternalRight(state, node, childIdx, count);
        setInternalKey(state, node, childIdx, split.medianKey);
        setChild(state, node, childIdx + 1, split.rightNode);
        setNodeCount(state, node, count + 1);

        // Decide which child to descend into
        switch (compareKeys(key, split.medianKey)) {
          case (#less) {}; // stay with original child
          case _ { child := split.rightNode };
        };
      };

      insertNonFull(state, child, key, val)
    }
  };

  /// Total number of entries
  public func size(state : State) : Nat { state.entryCount };

  /// Scan entries whose key starts with `prefix`. Returns up to `maxResults` entries.
  /// O(k log n) where k = matching entries, instead of O(n) for full iteration.
  public func prefixScan(state : State, prefix : Blob, maxResults : Nat) : [(Blob, Blob)] {
    let result = List.empty<(Blob, Blob)>();
    if (state.root != NULL_NODE) {
      ignore prefixCollect(state, state.root, prefix, result, maxResults);
    };
    List.toArray(result)
  };

  /// Check if a key starts with the given prefix
  func hasPrefix(key : Blob, prefix : Blob) : Bool {
    if (prefix.size() > key.size()) return false;
    let ka = Blob.toArray(key);
    let pa = Blob.toArray(prefix);
    var i = 0;
    while (i < pa.size()) {
      if (ka[i] != pa[i]) return false;
      i += 1;
    };
    true
  };

  /// Check if any key with this prefix could exist at or after `key` in sort order
  func prefixCouldFollow(key : Blob, prefix : Blob) : Bool {
    // A key with `prefix` could follow `key` if prefix >= key[0..prefix.size()]
    let ka = Blob.toArray(key);
    let pa = Blob.toArray(prefix);
    var i = 0;
    while (i < pa.size() and i < ka.size()) {
      if (Nat8.toNat(pa[i]) > Nat8.toNat(ka[i])) return true;
      if (Nat8.toNat(pa[i]) < Nat8.toNat(ka[i])) return false;
      i += 1;
    };
    true // prefix == key prefix, so matches could follow
  };

  /// Returns count of entries collected (for early termination)
  func prefixCollect(state : State, node : Nat64, prefix : Blob, result : List.List<(Blob, Blob)>, maxResults : Nat) : Nat {
    let count = nodeCount(state, node);
    var collected : Nat = 0;
    if (nodeType(state, node) == NODE_LEAF) {
      var i = 0;
      while (i < count and collected < maxResults) {
        let key = leafKey(state, node, i);
        if (hasPrefix(key, prefix)) {
          List.add(result, (key, leafVal(state, node, i)));
          collected += 1;
        } else if (not prefixCouldFollow(key, prefix) and i > 0) {
          // Past the prefix range, stop scanning this leaf
          return collected;
        };
        i += 1;
      };
    } else {
      var i = 0;
      while (i <= count and collected < maxResults) {
        // Check if this subtree could contain prefix matches
        let shouldDescend = if (i < count) {
          let sepKey = internalKey(state, node, i);
          prefixCouldFollow(sepKey, prefix) or hasPrefix(sepKey, prefix)
        } else { true }; // always check last child
        if (shouldDescend) {
          collected += prefixCollect(state, getChild(state, node, i), prefix, result, maxResults - collected);
        };
        i += 1;
      };
    };
    collected
  };

  /// Memory stats
  public func memoryStats(state : State) : { nodes : Nat; entries : Nat; bytes : Nat; bytesPerEntry : Nat } {
    let nodes = Nat64.toNat(state.nodeCount);
    let bytes = nodes * 8192;
    {
      nodes;
      entries = state.entryCount;
      bytes;
      bytesPerEntry = if (state.entryCount == 0) 0 else bytes / state.entryCount;
    }
  };
};
