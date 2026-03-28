/// BTreeIndex.mo — B-tree backed account transaction index
///
/// Combines RegionBTree (sorted lookup) with CompactIndex-style block chains
/// (variable-length tx storage). The B-tree replaces the hash table for account
/// lookup; eliminating fixed bucket allocation and enabling sorted iteration.
///
/// Storage per account: ~72 bytes in B-tree leaf + 40 bytes first block = 112 bytes
/// (same as CompactIndex for light accounts; but no 80MB hash table overhead).
///
/// At 1B accounts: ~71GB B-tree + chain blocks = similar total to CompactIndex
/// but with sorted iteration, no load factor concerns, and natural growth.

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
import Principal "mo:core/Principal";

import T "Types";
import BTree "RegionBTree";

module {

  // Value stored in B-tree: [count:4][chain_head:6] = 10 bytes
  let NULL_PTR : Nat64 = 0xFFFF_FFFF_FFFF;
  let BLOCK_HEADER : Nat64 = 8; // [next:6][count:1][cap_code:1]
  let FIRST_CAP : Nat = 8;
  let OVERFLOW_HEADER : Nat64 = 14; // [next:6][count:1][cap_code:1][last_abs:4][byte_used:2]

  public type State = {
    btree : BTree.State;
    blockRegion : Region.Region;
    var blockOffset : Nat64;
  };

  public func newState() : State {
    {
      btree = BTree.newState();
      blockRegion = Region.new();
      var blockOffset : Nat64 = 0;
    }
  };

  // ── Block chain helpers (same as CompactIndex) ──

  func growIfNeeded(r : Region.Region, needed : Nat64) {
    let pages = (needed / 65536) + 1;
    let have = Region.size(r);
    if (pages > have) {
      let g = Region.grow(r, pages - have);
      if (g == 0xFFFF_FFFF_FFFF_FFFF) Runtime.trap("BTreeIndex: memory exhausted");
    };
  };

  func store48(r : Region.Region, off : Nat64, val : Nat64) {
    Region.storeNat32(r, off, Nat32.fromNat(Nat64.toNat(val) % 4294967296));
    Region.storeNat16(r, off + 4, Nat16.fromNat(Nat64.toNat(val) / 4294967296));
  };

  func load48(r : Region.Region, off : Nat64) : Nat64 {
    let lo = Nat32.toNat(Region.loadNat32(r, off));
    let hi = Nat16.toNat(Region.loadNat16(r, off + 4));
    Nat64.fromNat(lo + hi * 4294967296)
  };

  func allocRawBlock(state : State) : Nat64 {
    let size = BLOCK_HEADER + Nat64.fromNat(FIRST_CAP * 4);
    let off = state.blockOffset;
    state.blockOffset += size;
    growIfNeeded(state.blockRegion, state.blockOffset);
    store48(state.blockRegion, off, NULL_PTR);
    Region.storeNat8(state.blockRegion, off + 6, 0);
    Region.storeNat8(state.blockRegion, off + 7, 0); // cap_code=0 (raw, cap=8)
    off
  };

  func allocDeltaBlock(state : State, maxBytes : Nat) : Nat64 {
    let size = OVERFLOW_HEADER + Nat64.fromNat(maxBytes);
    let off = state.blockOffset;
    state.blockOffset += size;
    growIfNeeded(state.blockRegion, state.blockOffset);
    store48(state.blockRegion, off, NULL_PTR);
    Region.storeNat8(state.blockRegion, off + 6, 0);
    Region.storeNat8(state.blockRegion, off + 7, 4); // cap_code=4 (delta)
    Region.storeNat32(state.blockRegion, off + 8, 0);
    Region.storeNat16(state.blockRegion, off + 12, 0);
    off
  };

  func encodeValue(count : Nat, head : Nat64) : Blob {
    let h = Nat64.toNat(head);
    Blob.fromArray(Array.tabulate<Nat8>(10, func(i) {
      if (i < 4) Nat8.fromNat((count / (256 ** (3 - i))) % 256)
      else Nat8.fromNat((h / (256 ** (9 - i))) % 256)
    }))
  };

  func decodeValue(val : Blob) : (Nat, Nat64) {
    let b = Blob.toArray(val);
    var count : Nat = 0;
    var i = 0; while (i < 4) { count := count * 256 + Nat8.toNat(b[i]); i += 1 };
    var head : Nat = 0;
    i := 4; while (i < 10) { head := head * 256 + Nat8.toNat(b[i]); i += 1 };
    (count, Nat64.fromNat(head))
  };

  // ── Delta-gap encoding (same as CompactIndex) ──

  func deltaAppend(state : State, block : Nat64, txIdx : Nat, maxBytes : Nat) : Bool {
    let count = Nat8.toNat(Region.loadNat8(state.blockRegion, block + 6));
    let lastAbs = Nat32.toNat(Region.loadNat32(state.blockRegion, block + 8));
    let bytesUsed = Nat16.toNat(Region.loadNat16(state.blockRegion, block + 12));
    let gap = if (count == 0) txIdx else { if (txIdx < lastAbs) 0 else txIdx - lastAbs };
    var g = gap; var needed : Nat = 0;
    if (g == 0) { needed := 1 } else { var t = g; while (t > 0) { needed += 1; t /= 128 } };
    if (bytesUsed + needed > maxBytes) return false;
    let startOff = block + OVERFLOW_HEADER + Nat64.fromNat(bytesUsed);
    if (gap == 0) { Region.storeNat8(state.blockRegion, startOff, 0) }
    else {
      var ii = needed; while (ii > 0) {
        ii -= 1;
        let byte = Nat8.fromNat(g % 128);
        let flag : Nat8 = if (ii > 0) 128 else 0;
        Region.storeNat8(state.blockRegion, startOff + Nat64.fromNat(needed - 1 - ii), flag | byte);
        g /= 128;
      };
    };
    Region.storeNat8(state.blockRegion, block + 6, Nat8.fromNat(count + 1));
    Region.storeNat32(state.blockRegion, block + 8, Nat32.fromNat(txIdx % 4294967296));
    Region.storeNat16(state.blockRegion, block + 12, Nat16.fromNat(bytesUsed + needed));
    true
  };

  func deltaReadAll(state : State, block : Nat64) : [Nat] {
    let count = Nat8.toNat(Region.loadNat8(state.blockRegion, block + 6));
    let bytesUsed = Nat16.toNat(Region.loadNat16(state.blockRegion, block + 12));
    if (count == 0) return [];
    let result = List.empty<Nat>();
    var abs : Nat = 0; var pos : Nat = 0; var read : Nat = 0;
    while (read < count and pos < bytesUsed) {
      var gap : Nat = 0; var cont = true;
      while (cont and pos < bytesUsed) {
        let byte = Nat8.toNat(Region.loadNat8(state.blockRegion, block + OVERFLOW_HEADER + Nat64.fromNat(pos)));
        gap := gap * 128 + (byte % 128); cont := byte >= 128; pos += 1;
      };
      abs += gap; List.add(result, abs); read += 1;
    };
    List.toArray(result)
  };

  // ═══════════════════════════════════════════════════════
  //  PUBLIC API
  // ═══════════════════════════════════════════════════════

  public func addIndex(state : State, account : ?T.Account, txIdx : Nat) {
    switch (account) {
      case null {};
      case (?a) {
        let kb = T.accountKeyToBlob(T.accountKey(a));
        switch (BTree.get(state.btree, kb)) {
          case null {
            let block = allocRawBlock(state);
            Region.storeNat32(state.blockRegion, block + BLOCK_HEADER, Nat32.fromNat(txIdx % 4294967296));
            Region.storeNat8(state.blockRegion, block + 6, 1); // count=1
            ignore BTree.put(state.btree, kb, encodeValue(1, block));
          };
          case (?existingVal) {
            let (count, head) = decodeValue(existingVal);
            // Walk to tail block
            var block = head;
            var next = load48(state.blockRegion, block);
            while (next != NULL_PTR) { block := next; next := load48(state.blockRegion, block) };
            let capCode = Nat8.toNat(Region.loadNat8(state.blockRegion, block + 7));
            if (capCode < 4) {
              let bCount = Nat8.toNat(Region.loadNat8(state.blockRegion, block + 6));
              if (bCount < FIRST_CAP) {
                Region.storeNat32(state.blockRegion, block + BLOCK_HEADER + Nat64.fromNat(bCount * 4),
                  Nat32.fromNat(txIdx % 4294967296));
                Region.storeNat8(state.blockRegion, block + 6, Nat8.fromNat(bCount + 1));
              } else {
                let newBlock = allocDeltaBlock(state, 128);
                ignore deltaAppend(state, newBlock, txIdx, 128);
                store48(state.blockRegion, block, newBlock);
              };
            } else {
              if (not deltaAppend(state, block, txIdx, 128)) {
                let newBlock = allocDeltaBlock(state, 512);
                ignore deltaAppend(state, newBlock, txIdx, 512);
                store48(state.blockRegion, block, newBlock);
              };
            };
            ignore BTree.put(state.btree, kb, encodeValue(count + 1, head));
          };
        };
      };
    };
  };

  public func getIndices(state : State, account : T.Account, maxResults : Nat) : [Nat] {
    let kb = T.accountKeyToBlob(T.accountKey(account));
    switch (BTree.get(state.btree, kb)) {
      case null { [] };
      case (?val) {
        let (_, head) = decodeValue(val);
        let all = List.empty<Nat>();
        var block = head;
        while (block != NULL_PTR) {
          let capCode = Nat8.toNat(Region.loadNat8(state.blockRegion, block + 7));
          if (capCode < 4) {
            let bCount = Nat8.toNat(Region.loadNat8(state.blockRegion, block + 6));
            var i = 0;
            while (i < bCount) {
              List.add(all, Nat32.toNat(Region.loadNat32(state.blockRegion, block + BLOCK_HEADER + Nat64.fromNat(i * 4))));
              i += 1;
            };
          } else { for (e in deltaReadAll(state, block).vals()) { List.add(all, e) } };
          block := load48(state.blockRegion, block);
        };
        let arr = List.toArray(all);
        let n = Nat.min(arr.size(), maxResults);
        Array.tabulate<Nat>(n, func(i) { arr[arr.size() - 1 - i] })
      };
    };
  };

  /// Get the oldest (first) transaction index for an account. O(1) via the raw block.
  public func getOldestIndex(state : State, account : T.Account) : ?Nat {
    let kb = T.accountKeyToBlob(T.accountKey(account));
    switch (BTree.get(state.btree, kb)) {
      case null null;
      case (?val) {
        let (_, head) = decodeValue(val);
        // The first block's first entry is the oldest tx index
        let capCode = Nat8.toNat(Region.loadNat8(state.blockRegion, head + 7));
        if (capCode < 4) {
          let bCount = Nat8.toNat(Region.loadNat8(state.blockRegion, head + 6));
          if (bCount > 0) {
            ?Nat32.toNat(Region.loadNat32(state.blockRegion, head + BLOCK_HEADER))
          } else null;
        } else {
          let indices = deltaReadAll(state, head);
          if (indices.size() > 0) ?indices[0] else null;
        };
      };
    };
  };

  public func accountCount(state : State) : Nat { BTree.size(state.btree) };

  public func listSubaccounts(state : State, owner : Principal, maxResults : Nat) : [Blob] {
    // Build prefix: [principal_len:1][principal:padded_to_29]
    // This matches the first 30 bytes of accountKeyToBlob format
    let pBlob = Principal.toBlob(owner);
    let pArr = Blob.toArray(pBlob);
    let prefix = Blob.fromArray(Array.tabulate<Nat8>(30, func(i) {
      if (i == 0) Nat8.fromNat(pBlob.size())
      else if (i <= 29) { if (i - 1 < pArr.size()) pArr[i - 1] else 0 }
      else 0
    }));
    // Use B-tree prefix scan — O(k log n) instead of O(n)
    let entries = BTree.prefixScan(state.btree, prefix, maxResults);
    let results = List.empty<Blob>();
    for ((key, _) in entries.vals()) {
      let kb = Blob.toArray(key);
      List.add(results, Blob.fromArray(Array.tabulate<Nat8>(32, func(j) { kb[30 + j] })));
    };
    List.toArray(results)
  };

  public func memoryStats(state : State) : { btreeStats : { nodes : Nat; entries : Nat; bytes : Nat; bytesPerEntry : Nat }; blockBytes : Nat } {
    { btreeStats = BTree.memoryStats(state.btree); blockBytes = Nat64.toNat(state.blockOffset) }
  };
};
