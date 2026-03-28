/// Archive.mo — Read-only archive canister for overflow blocks
///
/// When the main ledger's block log exceeds a threshold, it spawns
/// an Archive canister and moves old blocks there. The archive is
/// a simple read-only store — it only accepts blocks from the ledger principal.
///
/// Architecture:
///   - StableLog-backed (Region) — same as main ledger
///   - Only the parent ledger can append blocks
///   - Exposes get_blocks query for external tools
///   - ICRC-3 compatible: icrc3_get_blocks returns Value (decoded CBOR)
///   - icrc3_get_blocks also serves as the callback for icrc3_get_transactions

import Principal "mo:core/Principal";
import Nat "mo:core/Nat";
import Blob "mo:core/Blob";
import Array "mo:core/Array";
import Runtime "mo:core/Runtime";

import SLog "StableLog";
import CBOR "CBOR";
import T "Types";

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

  /// Get raw blocks by index range (absolute indices).
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

    let result = Array.tabulate<Blob>(localEnd - localStart : Nat, func(i) {
      switch (SLog.get(logState, localStart + i)) {
        case (?b) b;
        case null "" : Blob;
      };
    });

    { blocks = result; first_index = blockOffset + localStart; length = result.size() }
  };

  /// Decode a raw CBOR block blob into a Value.
  /// Falls back to wrapping the raw blob if decoding fails.
  func blobToValue(data : Blob) : T.Value {
    switch (CBOR.decodeValue(data)) {
      case (?v) v;
      case null #Blob(data); // fallback: return raw blob if CBOR decode fails
    };
  };

  /// ICRC-3 compatible block access — returns decoded Value types.
  /// This function serves as the callback for icrc3_get_transactions.
  public query func icrc3_get_blocks(args : [{ start : Nat; length : Nat }]) : async {
    blocks : [T.Block];
    log_length : Nat;
  } {
    let totalBlocks = SLog.size(logState);
    var allBlocks : [T.Block] = [];

    for (range in args.vals()) {
      let localStart = if (range.start >= blockOffset) { range.start - blockOffset } else { 0 };
      let localEnd = Nat.min(localStart + range.length, totalBlocks);

      if (localStart < totalBlocks) {
        let batch = Array.tabulate<T.Block>(localEnd - localStart : Nat, func(i) {
          let idx = localStart + i;
          let data = switch (SLog.get(logState, idx)) { case (?b) b; case null "" : Blob };
          { id = blockOffset + idx; block = blobToValue(data) }
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
    parent_ledger : Principal;
  } {
    {
      first_index = blockOffset;
      block_count = SLog.size(logState);
      parent_ledger = parentLedger;
    }
  };
};
