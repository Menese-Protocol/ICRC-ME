/// RegionIndex.mo — Region-backed account transaction index (zero GC at scale)
///
/// Stores account→tx_indices entirely in stable memory (Region).
/// GC never scans this data — O(0) GC overhead regardless of account count.
///
/// Design: Hash table (64K buckets) → slot records with ring buffer of tx indices.
/// Each slot: [key:34][count:4][wpos:4][indices:4×1000] = 4042 bytes
/// All operations use Nat64 offsets for Region API compatibility.

import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Blob "mo:core/Blob";
import Array "mo:core/Array";
import List "mo:core/List";
import Region "mo:core/Region";
import Runtime "mo:core/Runtime";
import Principal "mo:core/Principal";

import T "Types";

module {

  let MAX_PER_ACCOUNT : Nat = 1000;
  let NUM_BUCKETS : Nat64 = 1048576;  // 2^20 = 1M buckets; <50% load at 500K accounts
  let KEY_LEN : Nat64 = 62;           // full principal + full subaccount; zero collision
  let SLOT_SIZE : Nat64 = 4070;       // 62 + 4 + 4 + 4*1000
  let BUCKET_BYTES : Nat64 = 5;       // [slot_idx:4][occupied:1]
  // HT total: 5 * 1048576 = 5,242,880 bytes = 81 pages

  public type State = {
    htRegion : Region.Region;
    dataRegion : Region.Region;
    var slotCount : Nat64;
  };

  public func newState() : State {
    let ht = Region.new();
    let data = Region.new();
    ignore Region.grow(ht, 81); // 81 pages = 5,242,880 bytes / 65536 + 1
    { htRegion = ht; dataRegion = data; var slotCount : Nat64 = 0 }
  };

  func hashKey(key : T.AccountKey) : Nat64 {
    let kb = T.accountKeyToBlob(key);
    var h : Nat32 = 2166136261;
    for (b in kb.vals()) { h := (h ^ Nat32.fromNat(Nat8.toNat(b))) *% 16777619 };
    Nat64.fromNat(Nat32.toNat(h)) % NUM_BUCKETS
  };

  /// Add a tx index for an account. Zero heap allocation.
  public func addIndex(state : State, account : ?T.Account, txIdx : Nat) {
    switch (account) {
      case null {};
      case (?a) {
        let key = T.accountKey(a);
        let slot = findOrCreate(state, key, hashKey(key));
        // Read count + wpos
        let cOff = slot + KEY_LEN;
        let wOff = slot + KEY_LEN + 4;
        let count = Nat32.toNat(Region.loadNat32(state.dataRegion, cOff));
        let wpos = Nat32.toNat(Region.loadNat32(state.dataRegion, wOff));
        // Write tx index into ring buffer
        let ringOff = slot + KEY_LEN + 8 + Nat64.fromNat(wpos * 4);
        Region.storeNat32(state.dataRegion, ringOff, Nat32.fromNat(txIdx % 4294967296));
        // Update wpos (wrap)
        Region.storeNat32(state.dataRegion, wOff, Nat32.fromNat((wpos + 1) % MAX_PER_ACCOUNT));
        // Update count
        if (count < MAX_PER_ACCOUNT) {
          Region.storeNat32(state.dataRegion, cOff, Nat32.fromNat(count + 1));
        };
      };
    };
  };

  /// Get recent tx indices (newest first).
  public func getIndices(state : State, account : T.Account, maxResults : Nat) : [Nat] {
    let key = T.accountKey(account);
    switch (findExisting(state, key, hashKey(key))) {
      case null { [] };
      case (?slot) {
        let count = Nat32.toNat(Region.loadNat32(state.dataRegion, slot + KEY_LEN));
        let wpos = Nat32.toNat(Region.loadNat32(state.dataRegion, slot + KEY_LEN + 4));
        let n = Nat.min(count, Nat.min(maxResults, MAX_PER_ACCOUNT));
        Array.tabulate<Nat>(n, func(i) {
          let pos = (wpos + MAX_PER_ACCOUNT - 1 - i) % MAX_PER_ACCOUNT;
          Nat32.toNat(Region.loadNat32(state.dataRegion, slot + KEY_LEN + 8 + Nat64.fromNat(pos * 4)))
        })
      };
    };
  };

  func findExisting(state : State, key : T.AccountKey, startBucket : Nat64) : ?Nat64 {
    let kb = T.accountKeyToBlob(key);
    var bucket = startBucket;
    var probes : Nat = 0;
    while (probes < 1000) {
      let htOff = bucket * BUCKET_BYTES;
      if (Region.loadNat8(state.htRegion, htOff + 4) == 0) return null;
      let slot = Nat64.fromNat(Nat32.toNat(Region.loadNat32(state.htRegion, htOff))) * SLOT_SIZE;
      if (Region.loadBlob(state.dataRegion, slot, 62) == kb) return ?slot;
      bucket := (bucket + 1) % NUM_BUCKETS;
      probes += 1;
    };
    null
  };

  func findOrCreate(state : State, key : T.AccountKey, startBucket : Nat64) : Nat64 {
    let kb = T.accountKeyToBlob(key);
    var bucket = startBucket;
    var probes : Nat = 0;
    while (probes < 1000) {
      let htOff = bucket * BUCKET_BYTES;
      if (Region.loadNat8(state.htRegion, htOff + 4) == 0) {
        // Allocate new slot
        let idx = state.slotCount;
        state.slotCount += 1;
        let slot = idx * SLOT_SIZE;
        // Grow data region if needed
        let need = (slot + SLOT_SIZE) / 65536 + 1;
        let have = Region.size(state.dataRegion);
        if (need > have) { ignore Region.grow(state.dataRegion, need - have) };
        // Write key
        Region.storeBlob(state.dataRegion, slot, kb);
        // Write HT entry
        Region.storeNat32(state.htRegion, htOff, Nat32.fromNat(Nat64.toNat(idx)));
        Region.storeNat8(state.htRegion, htOff + 4, 1);
        return slot;
      };
      let slot = Nat64.fromNat(Nat32.toNat(Region.loadNat32(state.htRegion, htOff))) * SLOT_SIZE;
      if (Region.loadBlob(state.dataRegion, slot, 62) == kb) return slot;
      bucket := (bucket + 1) % NUM_BUCKETS;
      probes += 1;
    };
    Runtime.trap("RegionIndex: hash table full");
  };

  public func accountCount(state : State) : Nat { Nat64.toNat(state.slotCount) };

  /// Scan all slots for subaccounts belonging to a principal.
  /// Extracts the subaccount (bytes 30–61) from each slot whose principal matches.
  public func listSubaccounts(state : State, owner : Principal, maxResults : Nat) : [Blob] {
    let pBlob = Principal.toBlob(owner);
    let pLen = pBlob.size();
    let results = List.empty<Blob>();
    var i : Nat64 = 0;
    var count = 0;
    while (i < state.slotCount and count < maxResults) {
      let slotOff = i * SLOT_SIZE;
      // Check principal length byte matches
      let storedPLen = Nat8.toNat(Region.loadNat8(state.dataRegion, slotOff));
      if (storedPLen == pLen) {
        let storedP = Region.loadBlob(state.dataRegion, slotOff + 1, pLen);
        if (storedP == pBlob) {
          // Extract subaccount (bytes 30–61)
          let sub = Region.loadBlob(state.dataRegion, slotOff + 30, 32);
          List.add(results, sub);
          count += 1;
        };
      };
      i += 1;
    };
    List.toArray(results)
  };
};
