/// Archive.mo — Read-only archive canister for overflow blocks
///
/// Port of dfinity/ic rs/ledger_suite/icrc1/archive/src/main.rs
///
/// When the main ledger's block log exceeds a threshold, it spawns
/// an Archive canister and moves old blocks there. The archive is
/// a simple read-only store — it only accepts blocks from the ledger principal.
///
/// Architecture:
///   - StableLog-backed (Region) — same as main ledger
///   - Only the parent ledger can append blocks
///   - Exposes get_blocks query for external tools
///   - ICRC-3 compatible: icrc3_get_blocks

import Principal "mo:core/Principal";
import Nat "mo:core/Nat";
import Nat64 "mo:core/Nat64";
import Blob "mo:core/Blob";
import Array "mo:core/Array";
import Runtime "mo:core/Runtime";

import SLog "StableLog";

shared(initMsg) persistent actor class Archive(ledgerPrincipal : Principal) {

  var logState : SLog.State = SLog.newState();
  let parentLedger = ledgerPrincipal;
  var blockOffset : Nat = 0;

  /// Set the starting block index for this archive.
  public shared ({ caller }) func init(startIndex : Nat) : async () {
    if (not Principal.equal(caller, parentLedger)) Runtime.trap("Not parent ledger");
    blockOffset := startIndex;
  };

  /// Append blocks from the parent ledger.
  public shared ({ caller }) func appendBlocks(blocks : [Blob]) : async Nat {
    if (not Principal.equal(caller, parentLedger)) Runtime.trap("Not parent ledger");
    var count : Nat = 0;
    for (block in blocks.vals()) {
      ignore SLog.append(logState, block);
      count += 1;
    };
    count
  };

  /// Get blocks by index range (absolute indices).
  public query func get_blocks(start : Nat, length : Nat) : async {
    blocks : [Blob];
    first_index : Nat;
    length : Nat;
  } {
    let totalBlocks = SLog.size(logState);
    if (totalBlocks == 0) return { blocks = []; first_index = blockOffset; length = 0 };

    let localStart = if (start >= blockOffset) { start - blockOffset } else { 0 };
    let localEnd = Nat.min(localStart + length, totalBlocks);

    if (localStart >= totalBlocks) return { blocks = []; first_index = blockOffset; length = 0 };

    let result = Array.tabulate<Blob>(localEnd - localStart, func(i) {
      switch (SLog.get(logState, localStart + i)) {
        case (?b) b;
        case null Blob.fromArray([]);
      };
    });

    { blocks = result; first_index = blockOffset + localStart; length = result.size() }
  };

  /// ICRC-3 compatible block access
  public query func icrc3_get_blocks(args : [{ start : Nat; length : Nat }]) : async {
    blocks : [{ id : Nat; block : Blob }];
    log_length : Nat;
  } {
    var allBlocks : [{ id : Nat; block : Blob }] = [];
    let totalBlocks = SLog.size(logState);

    for (range in args.vals()) {
      let localStart = if (range.start >= blockOffset) { range.start - blockOffset } else { 0 };
      let localEnd = Nat.min(localStart + range.length, totalBlocks);

      if (localStart < totalBlocks) {
        let batch = Array.tabulate<{ id : Nat; block : Blob }>(localEnd - localStart, func(i) {
          let idx = localStart + i;
          let data = switch (SLog.get(logState, idx)) { case (?b) b; case null "" : Blob };
          { id = blockOffset + idx; block = data }
        });
        allBlocks := Array.concat(allBlocks, batch);
      };
    };

    { blocks = allBlocks; log_length = blockOffset + totalBlocks }
  };

  /// Archive info
  public query func info() : async {
    first_index : Nat;
    block_count : Nat;
    data_size : Nat;
  } {
    {
      first_index = blockOffset;
      block_count = SLog.size(logState);
      data_size = SLog.dataSize(logState);
    }
  };
};
