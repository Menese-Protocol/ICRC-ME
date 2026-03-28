/// CertifiedTree.mo — Merkle hash tree for IC certified data
///
/// Provides verifiable query responses via the IC's BLS certification mechanism.
/// The canister maintains a hash tree over key data (last_block_hash, total_supply).
/// On each state change, the root hash is updated via CertifiedData.set().
/// Query responses include the subnet certificate + Merkle witness.
///
/// Architecture (matching DFINITY ICRC-3 icrc3_get_tip_certificate):
///   - Root hash = SHA256(labeled "last_block_index" || labeled "last_block_hash")
///   - CertifiedData.set(root_hash) on every transfer
///   - icrc3_get_tip_certificate returns { certificate, hash_tree }
///
/// The IC subnet signs the root hash with BLS. Clients verify:
///   1. BLS signature on the certificate is valid (subnet key)
///   2. Certificate contains the canister's certified_data = root_hash
///   3. Hash tree witnesses the specific value they queried

import Blob "mo:core/Blob";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Array "mo:core/Array";
import Text "mo:core/Text";
import CertifiedData "mo:core/CertifiedData";

import Sha256 "mo:sha2/Sha256";

module {

  // ═══════════════════════════════════════════════════════
  //  STABLE STATE (pure data — no closures)
  // ═══════════════════════════════════════════════════════

  public type State = {
    var lastBlockIndex : Nat;
    var lastBlockHash : Blob;
  };

  public func newState() : State {
    { var lastBlockIndex = 0; var lastBlockHash = "" : Blob };
  };

  // ═══════════════════════════════════════════════════════
  //  CBOR HASH TREE ENCODING (IC spec)
  // ═══════════════════════════════════════════════════════

  // IC hash tree node types (CBOR tag values):
  // 0 = Empty
  // 1 = Fork(left, right)
  // 2 = Labeled(label, subtree)
  // 3 = Leaf(data)
  // 4 = Pruned(hash)

  /// Hash tree node
  public type HashTree = {
    #empty;
    #fork : (HashTree, HashTree);
    #labeled : (Blob, HashTree);
    #leaf : Blob;
    #pruned : Blob;
  };

  /// Compute hash of a hash tree node per IC Interface Spec §Certificate.
  /// domain_sep(s) = SHA256(|s| as single byte ∥ s ∥ ...).
  /// Reference: https://internetcomputer.org/docs/references/ic-interface-spec/#hash-tree
  public func hashTree(tree : HashTree) : Blob {
    switch (tree) {
      case (#empty) {
        domainHash("ic-hashtree-empty", [])
      };
      case (#fork(left, right)) {
        domainHash("ic-hashtree-fork", [hashTree(left), hashTree(right)])
      };
      case (#labeled(lbl, subtree)) {
        domainHash("ic-hashtree-labeled", [lbl, hashTree(subtree)])
      };
      case (#leaf(data)) {
        domainHash("ic-hashtree-leaf", [data])
      };
      case (#pruned(hash)) {
        hash
      };
    };
  };

  /// IC domain separation: H( len_byte ∥ domain_string ∥ parts... )
  func domainHash(domain : Text, parts : [Blob]) : Blob {
    let digest = Sha256.Digest(#sha256);
    let domainBytes = Text.encodeUtf8(domain);
    digest.writeArray([Nat8.fromNat(domainBytes.size())]); // length prefix byte
    digest.writeBlob(domainBytes);
    for (p in parts.vals()) { digest.writeBlob(p) };
    digest.sum()
  };

  // ═══════════════════════════════════════════════════════
  //  CBOR ENCODING for hash_tree response
  // ═══════════════════════════════════════════════════════

  /// Encode a hash tree as CBOR bytes (for icrc3_get_tip_certificate response)
  public func encodeCBOR(tree : HashTree) : Blob {
    let bytes = encodeCBORInner(tree);
    Blob.fromArray(bytes)
  };

  func encodeCBORInner(tree : HashTree) : [Nat8] {
    switch (tree) {
      case (#empty) {
        [0x81, 0x00] // array(1) [0]
      };
      case (#fork(left, right)) {
        let l = encodeCBORInner(left);
        let r = encodeCBORInner(right);
        // array(3) [1, left, right]
        let header : [Nat8] = [0x83, 0x01];
        Array.concat(Array.concat(header, l), r)
      };
      case (#labeled(lbl, subtree)) {
        let sub = encodeCBORInner(subtree);
        // array(3) [2, label_bytes, subtree]
        let header : [Nat8] = [0x83, 0x02];
        let labelBytes = encodeCBORBlob(lbl);
        Array.concat(Array.concat(header, labelBytes), sub)
      };
      case (#leaf(data)) {
        // array(2) [3, data_bytes]
        let header : [Nat8] = [0x82, 0x03];
        Array.concat(header, encodeCBORBlob(data))
      };
      case (#pruned(hash)) {
        // array(2) [4, hash_bytes]
        let header : [Nat8] = [0x82, 0x04];
        Array.concat(header, encodeCBORBlob(hash))
      };
    };
  };

  func encodeCBORBlob(b : Blob) : [Nat8] {
    let bytes = Blob.toArray(b);
    let len = bytes.size();
    if (len < 24) {
      Array.concat([Nat8.fromNat(0x40 + len)], bytes)
    } else if (len < 256) {
      Array.concat([0x58 : Nat8, Nat8.fromNat(len)], bytes)
    } else {
      // 2-byte length
      Array.concat([0x59 : Nat8, Nat8.fromNat(len / 256), Nat8.fromNat(len % 256)], bytes)
    };
  };

  // ═══════════════════════════════════════════════════════
  //  CERTIFIED LEDGER STATE OPERATIONS
  // ═══════════════════════════════════════════════════════

  /// Encode Nat as big-endian bytes (LEB128-like: minimal encoding)
  func natToBeBytes(n : Nat) : Blob {
    if (n == 0) return Blob.fromArray([0]);
    var tmp = n;
    var bc : Nat = 0;
    while (tmp > 0) { tmp /= 256; bc += 1 };
    Blob.fromArray(Array.tabulate<Nat8>(bc, func(i) {
      Nat8.fromNat((n / (256 ** (bc - 1 - i))) % 256)
    }))
  };

  func buildTipTree(blockIndex : Nat, blockHash : Blob) : HashTree {
    let indexBlob = natToBeBytes(blockIndex);
    #labeled(
      Text.encodeUtf8("tip"),
      #fork(
        #labeled(Text.encodeUtf8("last_block_index"), #leaf(indexBlob)),
        #labeled(Text.encodeUtf8("last_block_hash"), #leaf(blockHash)),
      )
    )
  };

  /// Update the certified state after a new block is appended.
  /// Builds hash tree and sets CertifiedData.
  public func updateTip(state : State, blockIndex : Nat, blockHash : Blob) {
    state.lastBlockIndex := blockIndex;
    state.lastBlockHash := blockHash;

    // Build hash tree: labeled "tip" → fork(labeled "last_block_index", labeled "last_block_hash")
    let tree = buildTipTree(blockIndex, blockHash);
    let rootHash = hashTree(tree);

    // Truncate to 32 bytes (CertifiedData.set requires ≤ 32 bytes)
    let hashBytes = Blob.toArray(rootHash);
    let truncated = if (hashBytes.size() > 32) {
      Blob.fromArray(Array.tabulate<Nat8>(32, func(i) { hashBytes[i] }))
    } else { rootHash };

    CertifiedData.set(truncated);
  };

  /// Get the tip certificate for icrc3_get_tip_certificate response.
  /// Returns null if called outside a query (no certificate available in update calls).
  public func getTipCertificate(state : State) : ?{ certificate : Blob; hash_tree : Blob } {
    switch (CertifiedData.getCertificate()) {
      case (?cert) {
        let tree = buildTipTree(state.lastBlockIndex, state.lastBlockHash);
        let encoded = encodeCBOR(tree);
        ?{ certificate = cert; hash_tree = encoded }
      };
      case null null; // Not in a query context
    };
  };

  /// Current tip info
  public func getLastBlockIndex(state : State) : Nat { state.lastBlockIndex };
  public func getLastBlockHash(state : State) : Blob { state.lastBlockHash };
};
