/// BlockLog.mo — Append-only transaction log with cryptographic hash chain
///
/// Each block is SHA-256 chained to its predecessor; encoded in a compact
/// binary format (v3); and stored in Region-backed stable memory via StableLog.
/// Account transaction indices are maintained in RegionIndex; a structure that
/// resides entirely in stable memory and is therefore invisible to the garbage
/// collector. A Merkle Mountain Range is updated on each append to provide
/// O(log n) inclusion proofs for any historical block.

import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Nat64 "mo:core/Nat64";
import Int "mo:core/Int";
import Blob "mo:core/Blob";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import List "mo:core/List";
import Text "mo:core/Text";
import Time "mo:core/Time";
import Principal "mo:core/Principal";

import Sha256 "mo:sha2/Sha256";

import T "Types";
import SLog "StableLog";
import CBOR "CBOR";
import MMR "MerkleMMR";
import CIdx "BTreeIndex";

module {

  /// Block with hash chain linkage
  public type Block = {
    index : Nat;
    parentHash : ?Blob;
    hash : Blob;
    timestamp : Nat64;
    transaction : T.Transaction;
    effectiveFee : ?Nat;
  };

  /// Internal decoded block with parentHash from CBOR
  type DecodedBlock = {
    tx : T.Transaction;
    parentHash : ?Blob;
  };

  // ═══════════════════════════════════════════════════════
  //  BINARY ENCODING HELPERS (zero-allocation hash preimage)
  // ═══════════════════════════════════════════════════════

  /// Encode Nat as big-endian variable-length bytes (no text conversion)
  func natToBytes(digest : Sha256.Digest, n : Nat) {
    if (n == 0) { digest.writeArray([0]); return };
    // Count bytes needed
    var tmp = n;
    var byteCount : Nat = 0;
    while (tmp > 0) { tmp /= 256; byteCount += 1 };
    // Write big-endian
    let bytes = Array.tabulate<Nat8>(byteCount, func(i) {
      let shift = byteCount - 1 - i;
      Nat8.fromNat((n / (256 ** shift)) % 256)
    });
    digest.writeArray(bytes);
  };

  /// Encode Nat64 as fixed 8-byte big-endian (optimal for timestamps)
  func nat64ToBytes(digest : Sha256.Digest, n : Nat64) {
    let v = Nat64.toNat(n);
    digest.writeArray([
      Nat8.fromNat((v / 72057594037927936) % 256), // byte 7
      Nat8.fromNat((v / 281474976710656) % 256),   // byte 6
      Nat8.fromNat((v / 1099511627776) % 256),     // byte 5
      Nat8.fromNat((v / 4294967296) % 256),         // byte 4
      Nat8.fromNat((v / 16777216) % 256),           // byte 3
      Nat8.fromNat((v / 65536) % 256),              // byte 2
      Nat8.fromNat((v / 256) % 256),                // byte 1
      Nat8.fromNat(v % 256),                        // byte 0
    ]);
  };

  /// Compute SHA256 hash of block content using binary preimage (zero-copy)
  func computeBlockHash(
    parentHash : ?Blob,
    timestamp : Nat64,
    tx : T.Transaction,
    effectiveFee : ?Nat,
  ) : Blob {
    let digest = Sha256.Digest(#sha256);
    // Parent hash (32 bytes or absent — length-prefixed for domain separation)
    switch (parentHash) {
      case (?h) { digest.writeArray([0x01]); digest.writeBlob(h) };
      case null { digest.writeArray([0x00]) };
    };
    // Timestamp: fixed 8-byte big-endian
    nat64ToBytes(digest, timestamp);
    // Kind: length-prefixed UTF-8
    let kindBytes = Text.encodeUtf8(tx.kind);
    natToBytes(digest, kindBytes.size());
    digest.writeBlob(kindBytes);
    // Amount: variable-length big-endian
    natToBytes(digest, tx.amount);
    // Accounts: principal + subaccount with presence flags
    func hashAccount(d : Sha256.Digest, acc : ?T.Account) {
      switch (acc) {
        case (?a) {
          d.writeArray([0x01]); d.writeBlob(Principal.toBlob(a.owner));
          switch (a.subaccount) {
            case (?s) { d.writeArray([0x01]); d.writeBlob(s) };
            case null { d.writeArray([0x00]) };
          };
        };
        case null { d.writeArray([0x00]) };
      };
    };
    hashAccount(digest, tx.from);
    hashAccount(digest, tx.to);
    // Fee: presence flag + variable-length
    switch (effectiveFee) {
      case (?f) { digest.writeArray([0x01]); natToBytes(digest, f) };
      case null { digest.writeArray([0x00]) };
    };
    digest.sum()
  };

  // ═══════════════════════════════════════════════════════
  //  STABLE STATE (pure data — no closures)
  // ═══════════════════════════════════════════════════════

  public type State = {
    var blockCount : Nat;
    var lastHash : ?Blob;
    stableLog : SLog.State;
    mmr : MMR.State;
    compactIndex : CIdx.State;
  };

  public func newState() : State {
    {
      var blockCount = 0;
      var lastHash : ?Blob = null;
      stableLog = SLog.newState();
      mmr = MMR.newState();
      compactIndex = CIdx.newState();
    };
  };

  // ═══════════════════════════════════════════════════════
  //  OPERATIONS
  // ═══════════════════════════════════════════════════════

  /// Append a transaction. Returns block index.
  public func append(state : State, tx : T.Transaction, effectiveFee : ?Nat) : Nat {
    let idx = state.blockCount;
    let timestamp = Nat64.fromNat(Int.abs(Time.now()));
    let hash = computeBlockHash(state.lastHash, timestamp, tx, effectiveFee);
    let encoded = encodeBlock(idx, state.lastHash, hash, timestamp, tx, effectiveFee);
    ignore SLog.append(state.stableLog, encoded);
    // Use blockHash directly as MMR leaf (domain separation is in internal nodes)
    // Saves one full SHA256 per block vs MMR.hashLeaf(hash)
    ignore MMR.append(state.mmr, hash);
    state.blockCount += 1;
    state.lastHash := ?hash;
    // Index accounts in Region (stable memory; invisible to GC)
    CIdx.addIndex(state.compactIndex, tx.from, idx);
    CIdx.addIndex(state.compactIndex, tx.to, idx);
    CIdx.addIndex(state.compactIndex, tx.spender, idx);
    idx
  };

  // ═══════════════════════════════════════════════════════
  //  V3 COMPACT BINARY ENCODING (zero GC pressure)
  //  Pre-sized VarArray — no List.add, no intermediate allocations.
  //  CBOR is reconstructed lazily on get_blocks reads only.
  // ═══════════════════════════════════════════════════════

  func encodeBlock(_idx : Nat, parentHash : ?Blob, _hash : Blob, ts : Nat64, tx : T.Transaction, fee : ?Nat) : Blob {
    let buf = VarArray.repeat<Nat8>(0, 600);
    var len : Nat = 0;
    func w(b : Nat8) { buf[len] := b; len += 1 };
    func wBlob(b : Blob) { for (byte in b.vals()) { w(byte) } };
    func wNat(n : Nat) {
      if (n == 0) { w(1); w(0); return };
      var tmp = n; var bc : Nat = 0;
      while (tmp > 0) { tmp /= 256; bc += 1 };
      w(Nat8.fromNat(bc));
      let tmpArr = VarArray.repeat<Nat8>(0, bc);
      var rem = n; var j = bc;
      while (j > 0) { j -= 1; tmpArr[j] := Nat8.fromNat(rem % 256); rem /= 256 };
      j := 0; while (j < bc) { buf[len] := tmpArr[j]; len += 1; j += 1 };
    };
    func wAccount(acc : T.Account) {
      let pb = Principal.toBlob(acc.owner);
      w(Nat8.fromNat(pb.size())); wBlob(pb);
      switch (acc.subaccount) {
        case (?s) { w(Nat8.fromNat(s.size())); wBlob(s) };
        case null { w(0) };
      };
    };
    // Version
    w(0x03);
    // Timestamp: 8 bytes big-endian
    let tsN = Nat64.toNat(ts);
    buf[len] := Nat8.fromNat((tsN / 72057594037927936) % 256); len += 1;
    buf[len] := Nat8.fromNat((tsN / 281474976710656) % 256); len += 1;
    buf[len] := Nat8.fromNat((tsN / 1099511627776) % 256); len += 1;
    buf[len] := Nat8.fromNat((tsN / 4294967296) % 256); len += 1;
    buf[len] := Nat8.fromNat((tsN / 16777216) % 256); len += 1;
    buf[len] := Nat8.fromNat((tsN / 65536) % 256); len += 1;
    buf[len] := Nat8.fromNat((tsN / 256) % 256); len += 1;
    buf[len] := Nat8.fromNat(tsN % 256); len += 1;
    // Flags
    var flags : Nat8 = 0;
    switch (tx.from) { case (?_) flags := flags | 0x01; case null {} };
    switch (tx.to) { case (?_) flags := flags | 0x02; case null {} };
    switch (tx.spender) { case (?_) flags := flags | 0x04; case null {} };
    switch (fee) { case (?_) flags := flags | 0x08; case null {} };
    switch (tx.memo) { case (?_) flags := flags | 0x10; case null {} };
    switch (parentHash) { case (?_) flags := flags | 0x20; case null {} };
    w(flags);
    // Kind
    let kindBytes = Text.encodeUtf8(tx.kind);
    w(Nat8.fromNat(kindBytes.size())); wBlob(kindBytes);
    // Amount
    wNat(tx.amount);
    // Accounts
    switch (tx.from) { case (?a) wAccount(a); case null {} };
    switch (tx.to) { case (?a) wAccount(a); case null {} };
    switch (tx.spender) { case (?a) wAccount(a); case null {} };
    // Fee
    switch (fee) { case (?f) wNat(f); case null {} };
    // Memo
    switch (tx.memo) {
      case (?m) { w(Nat8.fromNat(m.size() / 256)); w(Nat8.fromNat(m.size() % 256)); wBlob(m) };
      case null {};
    };
    // Parent hash
    switch (parentHash) { case (?h) wBlob(h); case null {} };
    Blob.fromArray(Array.tabulate<Nat8>(len, func(i) { buf[i] }))
  };

  /// Decode block — auto-detects v1 (pipe text) / v2 (CBOR) / v3 (compact binary)
  func decodeBlock(idx : Nat, data : Blob) : ?DecodedBlock {
    let bytes = Blob.toArray(data);
    if (bytes.size() == 0) return null;

    // v3: compact binary
    if (bytes[0] == 0x03) return decodeBlockV3(bytes, idx);

    // v2: starts with 0x02 version byte
    if (bytes[0] == 0x02) {
      let rest = Array.tabulate<Nat8>(bytes.size() - 1, func(i) { bytes[i + 1] });
      switch (CBOR.decodeBlockV2(rest, idx)) {
        case (?btx) {
          ?{
            tx = {
              kind = btx.kind; from = btx.from; to = btx.to; spender = btx.spender;
              amount = btx.amount; fee = btx.fee; memo = btx.memo;
              timestamp = btx.timestamp; index = btx.index;
            };
            parentHash = btx.parentHash;
          }
        };
        case null null;
      };
    } else {
      // v1 fallback: pipe-delimited text (backward compatible)
      switch (decodeBlockV1(idx, data)) {
        case (?tx) ?{ tx; parentHash = null };
        case null null;
      };
    };
  };

  /// V3 compact binary decoder
  func decodeBlockV3(bytes : [Nat8], idx : Nat) : ?DecodedBlock {
    var p : Nat = 1;
    if (bytes.size() < 11) return null;
    // Timestamp
    var ts : Nat = 0;
    var i = 0; while (i < 8) { ts := ts * 256 + Nat8.toNat(bytes[p + i]); i += 1 }; p += 8;
    // Flags
    let flags = bytes[p]; p += 1;
    // Kind
    let kLen = Nat8.toNat(bytes[p]); p += 1;
    if (p + kLen > bytes.size()) return null;
    let kind = switch (Text.decodeUtf8(Blob.fromArray(Array.tabulate<Nat8>(kLen, func(j) { bytes[p + j] })))) {
      case (?t) t; case null return null
    }; p += kLen;
    // Amount
    let aLen = Nat8.toNat(bytes[p]); p += 1;
    var amount : Nat = 0;
    i := 0; while (i < aLen) { amount := amount * 256 + Nat8.toNat(bytes[p + i]); i += 1 }; p += aLen;
    // Account reader
    func readAcc() : ?T.Account {
      if (p >= bytes.size()) return null;
      let pLen = Nat8.toNat(bytes[p]); p += 1;
      if (p + pLen > bytes.size()) return null;
      let owner = Principal.fromBlob(Blob.fromArray(Array.tabulate<Nat8>(pLen, func(j) { bytes[p + j] })));
      p += pLen;
      let sLen = Nat8.toNat(bytes[p]); p += 1;
      let sub = if (sLen == 0) null else {
        if (p + sLen > bytes.size()) return null;
        let s = Blob.fromArray(Array.tabulate<Nat8>(sLen, func(j) { bytes[p + j] }));
        p += sLen; ?s
      };
      ?{ owner; subaccount = sub }
    };
    let from = if ((flags & 0x01) != 0) readAcc() else null;
    let to = if ((flags & 0x02) != 0) readAcc() else null;
    let spender = if ((flags & 0x04) != 0) readAcc() else null;
    let fee = if ((flags & 0x08) != 0) {
      let fLen = Nat8.toNat(bytes[p]); p += 1;
      var f : Nat = 0;
      i := 0; while (i < fLen) { f := f * 256 + Nat8.toNat(bytes[p + i]); i += 1 }; p += fLen; ?f
    } else null;
    let memo = if ((flags & 0x10) != 0) {
      let mLen = Nat8.toNat(bytes[p]) * 256 + Nat8.toNat(bytes[p + 1]); p += 2;
      if (p + mLen > bytes.size()) return null;
      let m = Blob.fromArray(Array.tabulate<Nat8>(mLen, func(j) { bytes[p + j] }));
      p += mLen; ?m
    } else null;
    let parentHash = if ((flags & 0x20) != 0) {
      if (p + 32 > bytes.size()) return null;
      let h = Blob.fromArray(Array.tabulate<Nat8>(32, func(j) { bytes[p + j] }));
      p += 32; ?h
    } else null;
    ?{
      tx = { kind; from; to; spender; amount; fee; memo; timestamp = Nat64.fromNat(ts); index = idx };
      parentHash;
    }
  };

  /// Legacy v1 decoder for pre-CBOR blocks
  func decodeBlockV1(idx : Nat, data : Blob) : ?T.Transaction {
    switch (Text.decodeUtf8(data)) {
      case null null;
      case (?text) {
        let collected = List.empty<Text>();
        var current = "";
        for (c in text.chars()) {
          if (c == '|') {
            List.add(collected, current);
            current := "";
          } else {
            current #= Text.fromChar(c);
          };
        };
        List.add(collected, current);
        let parts = List.toArray(collected);
        if (parts.size() < 7) return null;
        let kind = parts[2];
        let amount = switch (Nat.fromText(parts[3])) { case (?n) n; case null 0 };
        let from = if (parts[4] == "") { null } else {
          ?({ owner = Principal.fromText(parts[4]); subaccount = null } : T.Account)
        };
        let to = if (parts[5] == "") { null } else {
          ?({ owner = Principal.fromText(parts[5]); subaccount = null } : T.Account)
        };
        let fee = if (parts[6] == "") { null } else {
          switch (Nat.fromText(parts[6])) { case (?n) ?n; case null null }
        };
        let ts = switch (Nat.fromText(parts[1])) { case (?n) Nat64.fromNat(n); case null 0 : Nat64 };
        ?{
          kind; from; to; spender = null; amount; fee; memo = null;
          timestamp = ts; index = idx;
        }
      };
    };
  };

  // ═══════════════════════════════════════════════════════
  //  INDEX QUERIES
  // ═══════════════════════════════════════════════════════

  public func getAccountTransactions(state : State, account : T.Account, start : ?Nat, maxResults : Nat) : [T.Transaction] {
    let indices = CIdx.getIndices(state.compactIndex, account, Nat.min(maxResults, 100));
    // indices are newest-first from RegionIndex; apply start filter
    let result = List.empty<T.Transaction>();
    label scan for (txIdx in indices.vals()) {
      switch (start) { case (?s) { if (txIdx > s) { continue scan } }; case null {} };
      switch (SLog.get(state.stableLog, txIdx)) {
        case (?data) {
          switch (decodeBlock(txIdx, data)) {
            case (?decoded) { List.add(result, decoded.tx) };
            case null {};
          };
        };
        case null {};
      };
    };
    List.toArray(result)
  };

  public func getOldestTxId(state : State, account : T.Account) : ?Nat {
    let indices = CIdx.getIndices(state.compactIndex, account, 1000);
    if (indices.size() == 0) null else ?indices[indices.size() - 1]
  };

  public func listSubaccounts(state : State, owner : Principal, start : ?Blob) : [Blob] {
    ignore start;
    CIdx.listSubaccounts(state.compactIndex, owner, 1000)
  };

  // ═══════════════════════════════════════════════════════
  //  BLOCK ACCESS
  // ═══════════════════════════════════════════════════════

  public func getBlocks(state : State, start : Nat, length : Nat) : [Block] {
    let end = Nat.min(start + length, state.blockCount);
    if (start >= state.blockCount) return [];
    let result = List.empty<Block>();
    var i = start;
    while (i < end) {
      switch (SLog.get(state.stableLog,i)) {
        case (?data) {
          switch (decodeBlock(i, data)) {
            case (?decoded) {
              List.add(result, {
                index = i;
                parentHash = decoded.parentHash;
                hash = Sha256.fromBlob(#sha256, data);
                timestamp = decoded.tx.timestamp;
                transaction = decoded.tx;
                effectiveFee = decoded.tx.fee;
              });
            };
            case null {};
          };
        };
        case null {};
      };
      i += 1;
    };
    List.toArray(result)
  };

  public func length(state : State) : Nat { state.blockCount };
  public func tipHash(state : State) : ?Blob { state.lastHash };
  public func dataSize(state : State) : Nat { SLog.dataSize(state.stableLog) };

  // ═══════════════════════════════════════════════════════
  //  MERKLE MOUNTAIN RANGE — O(log n) inclusion proofs
  // ═══════════════════════════════════════════════════════

  /// Get the MMR root hash (covers all blocks)
  public func mmrRoot(state : State) : ?Blob { MMR.rootHash(state.mmr) };

  /// Number of MMR peaks (= popcount of leafCount)
  public func mmrPeakCount(state : State) : Nat { MMR.peakCount(state.mmr) };

  /// Generate an inclusion proof for a block at the given index.
  /// Returns sibling hashes needed to verify the block is in the MMR.
  public func mmrProof(state : State, blockIndex : Nat) : ?{
    siblings : [Blob];
    peakIndex : Nat;
    peaks : [Blob];
  } {
    MMR.generateProof(state.mmr, blockIndex)
  };

  /// Query the Region-backed index for an account's tx indices
  public func regionGetIndices(state : State, account : T.Account, maxResults : Nat) : [Nat] {
    CIdx.getIndices(state.compactIndex, account, maxResults)
  };

  /// Number of accounts in the Region index
  public func regionAccountCount(state : State) : Nat {
    CIdx.accountCount(state.compactIndex)
  };
};
