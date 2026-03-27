/// StableLog.mo — Append-only log backed by Region stable memory
///
/// First-on-ICP: A Motoko equivalent of Rust's ic-stable-structures StableLog.
/// Survives upgrades, scales to gigabytes, O(1) append and O(1) random access.
///
/// Layout in Region:
///   [0..8)    : entry_count (Nat64)
///   [8..16)   : data_offset (Nat64) — next write position in data region
///   Each entry: [length:Nat32][data:Blob]
///
/// Uses TWO regions:
///   - Index region: entry_count + array of (offset, length) pairs
///   - Data region: raw entry bytes
///
/// This gives O(1) access to any entry by index.

import Region "mo:core/Region";
import Nat "mo:core/Nat";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Blob "mo:core/Blob";
import Array "mo:core/Array";
import Runtime "mo:core/Runtime";

module {

  let PAGE_SIZE : Nat64 = 65536; // 64KB per page

  // ═══════════════════════════════════════════════════════
  //  STABLE STATE (pure data — Region handles are stable)
  // ═══════════════════════════════════════════════════════

  public type State = {
    var indexRegion : Region.Region;
    var dataRegion : Region.Region;
    var entryCount : Nat64;
    var dataOffset : Nat64;
    var initialized : Bool;
  };

  public func newState() : State {
    {
      var indexRegion = Region.new();
      var dataRegion = Region.new();
      var entryCount : Nat64 = 0;
      var dataOffset : Nat64 = 0;
      var initialized = false;
    };
  };

  /// Initialize regions (call once after newState, idempotent via initialized flag)
  public func ensureInit(state : State) {
    if (state.initialized) return;
    ignore Region.grow(state.indexRegion, 1);
    ignore Region.grow(state.dataRegion, 1);
    Region.storeNat64(state.indexRegion, 0, 0);
    state.initialized := true;
  };

  // ═══════════════════════════════════════════════════════
  //  OPERATIONS
  // ═══════════════════════════════════════════════════════

  func ensureCapacity(region : Region.Region, needed : Nat64) {
    let currentBytes = Region.size(region) * PAGE_SIZE;
    if (needed > currentBytes) {
      let pagesNeeded = (needed - currentBytes + PAGE_SIZE - 1) / PAGE_SIZE;
      let result = Region.grow(region, pagesNeeded);
      if (result == 0xFFFF_FFFF_FFFF_FFFF) {
        Runtime.trap("StableLog: out of stable memory");
      };
    };
  };

  /// Append a blob entry. Returns the entry index.
  public func append(state : State, data : Blob) : Nat {
    ensureInit(state);
    let idx = Nat64.toNat(state.entryCount);
    let dataLen = Nat32.fromNat(data.size());
    let dataLen64 = Nat64.fromNat(data.size());

    ensureCapacity(state.dataRegion, state.dataOffset + dataLen64);
    Region.storeBlob(state.dataRegion, state.dataOffset, data);

    let indexNeeded : Nat64 = 8 + (state.entryCount + 1) * 12;
    ensureCapacity(state.indexRegion, indexNeeded);

    let indexEntryOffset : Nat64 = 8 + state.entryCount * 12;
    Region.storeNat64(state.indexRegion, indexEntryOffset, state.dataOffset);
    Region.storeNat32(state.indexRegion, indexEntryOffset + 8, dataLen);

    state.dataOffset += dataLen64;
    state.entryCount += 1;
    Region.storeNat64(state.indexRegion, 0, state.entryCount);

    idx
  };

  /// Get entry by index. Returns null if out of bounds.
  public func get(state : State, idx : Nat) : ?Blob {
    let idx64 = Nat64.fromNat(idx);
    if (idx64 >= state.entryCount) return null;

    let indexEntryOffset : Nat64 = 8 + idx64 * 12;
    let offset = Region.loadNat64(state.indexRegion, indexEntryOffset);
    let length = Region.loadNat32(state.indexRegion, indexEntryOffset + 8);

    ?Region.loadBlob(state.dataRegion, offset, Nat32.toNat(length))
  };

  /// Number of entries
  public func size(state : State) : Nat {
    Nat64.toNat(state.entryCount)
  };

  /// Get a range of entries [start, start+length)
  public func getRange(state : State, start : Nat, length : Nat) : [Blob] {
    let end = Nat.min(start + length, size(state));
    if (start >= end) return [];
    Array.tabulate<Blob>(end - start, func(i) {
      switch (get(state, start + i)) {
        case (?b) b;
        case null Blob.fromArray([]);
      };
    });
  };

  /// Total bytes used in data region
  public func dataSize(state : State) : Nat {
    Nat64.toNat(state.dataOffset)
  };

  /// Recover state from Region after upgrade.
  /// Call this if needed for disaster recovery (persistent actor handles it automatically).
  public func recover(state : State) {
    state.entryCount := Region.loadNat64(state.indexRegion, 0);
    if (state.entryCount > 0) {
      let lastIdx : Nat64 = state.entryCount - 1;
      let indexEntryOffset : Nat64 = 8 + lastIdx * 12;
      let lastOffset = Region.loadNat64(state.indexRegion, indexEntryOffset);
      let lastLength = Nat64.fromNat(Nat32.toNat(Region.loadNat32(state.indexRegion, indexEntryOffset + 8)));
      state.dataOffset := lastOffset + lastLength;
    } else {
      state.dataOffset := 0;
    };
    state.initialized := true;
  };
};
