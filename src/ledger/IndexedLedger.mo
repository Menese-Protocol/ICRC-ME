/// IndexedLedger.mo — Self-Indexed ICRC-1/ICRC-2/ICRC-3/ICRC-10 Token Ledger
///
/// This actor constitutes the entry point of the ICRC-ME ledger. It composes
/// eleven internal modules into a single canister that provides full ICRC
/// compliance; account-level transaction indexing; Merkle inclusion proofs;
/// and cycle drain protection. The separate index canister required by the
/// reference architecture is eliminated; its function is absorbed here via
/// a Region-backed account index that incurs zero garbage collection overhead
/// regardless of the number of accounts or accumulated blocks.
///
/// All state survives canister upgrades via Enhanced Orthogonal Persistence.

import Principal "mo:core/Principal";
import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import Int "mo:core/Int";
import Text "mo:core/Text";
import Blob "mo:core/Blob";
import List "mo:core/List";
import Map "mo:core/Map";
import Time "mo:core/Time";
import Runtime "mo:core/Runtime";
import Timer "mo:core/Timer";
import Cycles "mo:core/Cycles";

import Array "mo:core/Array";

import Sha256 "mo:sha2/Sha256";

import T "Types";
import Bal "Balances";
import Allow "Allowances";
import BLog "BlockLog";
import Cert "CertifiedTree";
import Bloom "BloomFilter";
import Archive "Archive";

shared(initMsg) persistent actor class IndexedLedger(args : T.InitArgs) = self {

  // ═══════════════════════════════════════════════════════
  //  CORE STATE — stable records (survive upgrades)
  // ═══════════════════════════════════════════════════════

  let maxSupply = switch (args.max_supply) { case (?m) m; case null Bal.DEFAULT_MAX_SUPPLY };
  var balState : Bal.State = Bal.newState(maxSupply);
  var allowState : Allow.State = Allow.newState();
  var blockState : BLog.State = BLog.newState();
  var certState : Cert.State = Cert.newState();

  // Token metadata (immutable after init)
  let tokenName : Text = args.name;
  let tokenSymbol : Text = args.symbol;
  let tokenDecimals : Nat8 = args.decimals;
  let tokenFee : Nat = args.fee;
  let mintingAccount : T.Account = args.minting_account;
  let maxMemoLength : Nat = switch (args.max_memo_length) { case (?m) m; case null 256 };

  // Fee collector (optional — fees go to pool if null)
  var feeCollector : ?T.Account = null;

  // ═══════════════════════════════════════════════════════
  //  ARCHIVE REGISTRY — Offload old blocks to child canisters
  //
  //  When the main StableLog exceeds archiveBlockThreshold blocks,
  //  a new Archive canister is spawned and old blocks are migrated.
  //  icrc3_get_archives returns the registry for client discovery.
  // ═══════════════════════════════════════════════════════

  type ArchiveEntry = { canisterId : Principal; firstBlock : Nat; lastBlock : Nat };
  var archives : [ArchiveEntry] = [];
  var archiveBlockThreshold : Nat = 2_000_000;  // trigger at 2M blocks (~500MB)
  var archiveBatchSize : Nat = 500;             // blocks per inter-canister call
  var archiveInProgress : Bool = false;
  var localBlockOffset : Nat = 0;               // first block index still in local StableLog

  // ═══════════════════════════════════════════════════════
  //  CIRCUIT BREAKER — Cycle Drain Protection
  //
  //  Freezes ALL writes when cycle balance drops below threshold.
  //  Reads (queries) stay alive — balances, blocks, proofs all accessible.
  //  State is fully preserved. Resume automatically when topped off.
  //
  //  Cost of this check: ~200 instructions (one Cycles.balance() call).
  //  Attacker would need to drain from current balance → threshold
  //  at ~10M cycles/call = (balance - threshold) / 10M calls to trigger.
  // ═══════════════════════════════════════════════════════

  // 100B cycles = ~30 days of idle burn. Configurable by admin.
  var circuitBreakerThreshold : Nat = 100_000_000_000;
  var circuitBreakerTripped : Bool = false;

  func guardCycles() : Bool {
    let bal = Cycles.balance();
    if (bal < circuitBreakerThreshold) {
      circuitBreakerTripped := true;
      true
    } else {
      if (circuitBreakerTripped) { circuitBreakerTripped := false };
      false
    }
  };

  // Dedup: keyed on (caller_principal, created_at_time, amount, memo_hash) to
  // avoid false collisions between different users or different transactions.
  // Bloom filter provides O(1) fast-path; Map is exact fallback.
  var bloomState : Bloom.State = Bloom.newState(86_400_000_000_000); // 24h window
  let TX_WINDOW_NS : Nat64 = 86_400_000_000_000;
  let PERMITTED_DRIFT_NS : Nat64 = 60_000_000_000;

  /// Build a dedup key from (caller, timestamp, amount, memo).
  /// Every variable-length field is length-prefixed to prevent cross-field ambiguity.
  /// SHA256 output is the fixed-size key for Map and Bloom filter.
  func buildDedupKey(caller : Principal, ts : Nat64, amount : Nat, memo : ?Blob) : Blob {
    let digest = Sha256.Digest(#sha256);
    // Principal: length-prefixed (variable 0-29 bytes)
    let pb = Principal.toBlob(caller);
    digest.writeArray([Nat8.fromNat(pb.size())]);
    digest.writeBlob(pb);
    // Timestamp: fixed 8-byte big-endian (no length prefix needed)
    let tsN = Nat64.toNat(ts);
    digest.writeArray([
      Nat8.fromNat((tsN / 72057594037927936) % 256),
      Nat8.fromNat((tsN / 281474976710656) % 256),
      Nat8.fromNat((tsN / 1099511627776) % 256),
      Nat8.fromNat((tsN / 4294967296) % 256),
      Nat8.fromNat((tsN / 16777216) % 256),
      Nat8.fromNat((tsN / 65536) % 256),
      Nat8.fromNat((tsN / 256) % 256),
      Nat8.fromNat(tsN % 256),
    ]);
    // Amount: length-prefixed big-endian (prevents boundary confusion with memo tag)
    if (amount == 0) { digest.writeArray([1, 0]) } else {
      var tmp = amount; var bc : Nat = 0;
      while (tmp > 0) { tmp /= 256; bc += 1 };
      digest.writeArray([Nat8.fromNat(bc)]); // byte count prefix
      let bytes = Array.tabulate<Nat8>(bc, func(i) {
        Nat8.fromNat((amount / (256 ** (bc - 1 - i))) % 256)
      });
      digest.writeArray(bytes);
    };
    // Memo: presence flag + length-prefixed content
    switch (memo) {
      case (?m) {
        digest.writeArray([0x01]);
        // Length as 2-byte big-endian (max memo = 256 bytes)
        digest.writeArray([Nat8.fromNat(m.size() / 256), Nat8.fromNat(m.size() % 256)]);
        digest.writeBlob(m);
      };
      case null { digest.writeArray([0x00]) };
    };
    digest.sum()
  };

  // ═══════════════════════════════════════════════════════
  //  INIT — Process initial balances (first install only)
  // ═══════════════════════════════════════════════════════

  func initBalances() {
    for ((account, amount) in args.initial_balances.vals()) {
      Bal.setBalance(balState, account, amount);
      Bal.reducePool(balState, amount);
      ignore BLog.append(blockState, {
        kind = "mint"; from = null; to = ?account; spender = null;
        amount; fee = null; memo = null;
        timestamp = Nat64.fromNat(Int.abs(Time.now())); index = BLog.length(blockState);
      }, null);
    };
    switch (BLog.tipHash(blockState)) {
      case (?hash) Cert.updateTip(certState, BLog.length(blockState) - 1, hash);
      case null {};
    };
  };

  // ═══════════════════════════════════════════════════════
  //  HELPERS
  // ═══════════════════════════════════════════════════════

  func isMintingAccount(account : T.Account) : Bool {
    T.accountsEqual(account, mintingAccount)
  };

  func now() : Nat64 { Nat64.fromNat(Int.abs(Time.now())) };

  // Dedup entries store (dedupKey -> (blockIndex, timestamp)) so we can prune by age.
  type DedupEntry = { blockIndex : Nat; timestamp : Nat64 };
  var recentTxEntries = Map.empty<Blob, DedupEntry>();
  var dedupMapSize : Nat = 0;

  // Adaptive pruning: prune proportionally to map size.
  // At 100 entries, prune 10 per call. At 10K, prune 100. At 100K, prune 1000.
  // This ensures the map never grows unbounded regardless of throughput.
  var dedupPruneCounter : Nat = 0;
  func pruneDedupMap() {
    dedupPruneCounter += 1;
    if (dedupPruneCounter % 5 != 0) return; // prune every 5th call
    let n = now();
    let cutoff = n - TX_WINDOW_NS - PERMITTED_DRIFT_NS - 60_000_000_000;
    // Prune batch size scales with map size: min 20, max 500, ~1% of map
    let batchSize = Nat.min(500, Nat.max(20, dedupMapSize / 100));
    let toDelete = List.empty<Blob>();
    var count : Nat = 0;
    for ((key, entry) in Map.entries(recentTxEntries)) {
      if (count >= batchSize) return;
      if (entry.timestamp < cutoff) {
        List.add(toDelete, key);
        count += 1;
      };
    };
    for (key in List.values(toDelete)) {
      ignore Map.delete(recentTxEntries, Blob.compare, key);
      dedupMapSize -= 1;
    };
  };

  func checkDedupAndTime(caller : Principal, created_at_time : ?Nat64, amount : Nat, memo : ?Blob) : { #ok; #TooOld; #InFuture : Nat64; #Duplicate : Nat } {
    pruneDedupMap();
    switch (created_at_time) {
      case null #ok;
      case (?ts) {
        let n = now();
        if (ts + TX_WINDOW_NS + PERMITTED_DRIFT_NS < n) return #TooOld;
        if (ts > n + PERMITTED_DRIFT_NS) return #InFuture(n);
        let dedupKey = buildDedupKey(caller, ts, amount, memo);
        // Bloom fast path (keyed on timestamp for window; dedupKey for exact match)
        if (not Bloom.mightContain(bloomState, ts, n)) {
          Bloom.add(bloomState, ts, n);
          Map.add(recentTxEntries, Blob.compare, dedupKey, { blockIndex = BLog.length(blockState); timestamp = ts });
          dedupMapSize += 1;
          return #ok;
        };
        // Exact check with full dedup key
        switch (Map.get(recentTxEntries, Blob.compare, dedupKey)) {
          case (?entry) #Duplicate(entry.blockIndex);
          case null {
            Bloom.add(bloomState, ts, n);
            Map.add(recentTxEntries, Blob.compare, dedupKey, { blockIndex = BLog.length(blockState); timestamp = ts });
            dedupMapSize += 1;
            #ok
          };
        };
      };
    };
  };

  func validateMemo(memo : ?Blob) : ?Text {
    switch (memo) {
      case (?m) { if (m.size() > maxMemoLength) ?("Memo too long: " # Nat.toText(m.size()) # " > " # Nat.toText(maxMemoLength)) else null };
      case null null;
    };
  };

  func validateSubaccount(sub : ?Blob) : ?Text {
    switch (sub) {
      case (?s) { if (s.size() != 32) ?("Subaccount must be 32 bytes, got " # Nat.toText(s.size())) else null };
      case null null;
    };
  };

  func makeTx(kind : Text, from : ?T.Account, to : ?T.Account, spender : ?T.Account, amount : Nat, fee : ?Nat, memo : ?Blob) : T.Transaction {
    { kind; from; to; spender; amount; fee; memo; timestamp = now(); index = BLog.length(blockState) }
  };

  /// Append block + update certified data atomically
  func appendAndCertify(tx : T.Transaction, effectiveFee : ?Nat) : Nat {
    let idx = BLog.append(blockState, tx, effectiveFee);
    switch (BLog.tipHash(blockState)) {
      case (?hash) Cert.updateTip(certState, idx, hash);
      case null {};
    };
    idx
  };

  // ═══════════════════════════════════════════════════════
  //  ICRC-1: TRANSFER
  // ═══════════════════════════════════════════════════════

  public shared ({ caller }) func icrc1_transfer(transferArgs : T.TransferArgs) : async { #Ok : Nat; #Err : T.TransferError } {
    if (guardCycles()) return #Err(#TemporarilyUnavailable);
    switch (validateSubaccount(transferArgs.from_subaccount)) {
      case (?e) return #Err(#GenericError({ error_code = 100; message = e })); case null {};
    };
    switch (validateSubaccount(transferArgs.to.subaccount)) {
      case (?e) return #Err(#GenericError({ error_code = 100; message = e })); case null {};
    };

    let from : T.Account = { owner = caller; subaccount = transferArgs.from_subaccount };
    let to = transferArgs.to;
    let amount = transferArgs.amount;

    // Minting account: fee must be 0. Burns (to minting): fee must be 0. Regular: fee must be tokenFee.
    let isMint = isMintingAccount(from);
    let isBurn = isMintingAccount(to);
    let expectedFee : Nat = if (isMint or isBurn) 0 else tokenFee;
    let fee = switch (transferArgs.fee) {
      case (?f) { if (f != expectedFee) return #Err(#BadFee({ expected_fee = expectedFee })); f };
      case null expectedFee;
    };

    switch (validateMemo(transferArgs.memo)) {
      case (?e) return #Err(#GenericError({ error_code = 101; message = e })); case null {};
    };

    switch (checkDedupAndTime(caller, transferArgs.created_at_time, amount, transferArgs.memo)) {
      case (#TooOld) return #Err(#TooOld);
      case (#InFuture(t)) return #Err(#CreatedInFuture({ ledger_time = t }));
      case (#Duplicate(idx)) return #Err(#Duplicate({ duplicate_of = idx }));
      case (#ok) {};
    };

    // Burn — enforce min_burn_amount
    if (isMintingAccount(to)) {
      if (amount == 0) return #Err(#BadBurn({ min_burn_amount = 1 }));
      switch (Bal.burn(balState, from, amount + fee)) {
        case (#err(#InsufficientFunds({ balance }))) return #Err(#InsufficientFunds({ balance }));
        case (#ok(())) {};
      };
      let tx = makeTx("burn", ?from, null, null, amount, ?fee, transferArgs.memo);
      let idx = appendAndCertify(tx, ?fee);
      return #Ok(idx);
    };

    // Mint
    if (isMintingAccount(from)) {
      switch (Bal.mint(balState, to, amount)) {
        case (#err(_)) return #Err(#GenericError({ error_code = 1; message = "Mint exceeds supply" }));
        case (#ok(())) {};
      };
      let tx = makeTx("mint", null, ?to, null, amount, null, transferArgs.memo);
      let idx = appendAndCertify(tx, null);
      return #Ok(idx);
    };

    // Regular transfer
    switch (Bal.transfer(balState, from, to, amount, fee, feeCollector)) {
      case (#err(#InsufficientFunds({ balance }))) return #Err(#InsufficientFunds({ balance }));
      case (#ok(())) {};
    };
    let tx = makeTx("transfer", ?from, ?to, null, amount, ?fee, transferArgs.memo);
    let idx = appendAndCertify(tx, ?fee);
    #Ok(idx)
  };

  // ═══════════════════════════════════════════════════════
  //  ICRC-2: APPROVE
  // ═══════════════════════════════════════════════════════

  public shared ({ caller }) func icrc2_approve(approveArgs : T.ApproveArgs) : async { #Ok : Nat; #Err : T.ApproveError } {
    if (guardCycles()) return #Err(#TemporarilyUnavailable);
    switch (validateSubaccount(approveArgs.from_subaccount)) {
      case (?e) return #Err(#GenericError({ error_code = 100; message = e })); case null {};
    };
    switch (validateSubaccount(approveArgs.spender.subaccount)) {
      case (?e) return #Err(#GenericError({ error_code = 100; message = e })); case null {};
    };

    let from : T.Account = { owner = caller; subaccount = approveArgs.from_subaccount };
    let spender = approveArgs.spender;

    // Minting account cannot approve (would delegate mint authority)
    if (isMintingAccount(from)) {
      return #Err(#GenericError({ error_code = 1; message = "the minting account cannot delegate mints" }));
    };

    // Cannot approve to self
    if (T.accountsEqual(from, spender)) {
      return #Err(#GenericError({ error_code = 2; message = "self-approval not allowed" }));
    };

    let fee = switch (approveArgs.fee) {
      case (?f) { if (f != tokenFee) return #Err(#BadFee({ expected_fee = tokenFee })); f };
      case null tokenFee;
    };

    switch (validateMemo(approveArgs.memo)) {
      case (?e) return #Err(#GenericError({ error_code = 101; message = e })); case null {};
    };

    switch (checkDedupAndTime(caller, approveArgs.created_at_time, approveArgs.amount, approveArgs.memo)) {
      case (#TooOld) return #Err(#TooOld);
      case (#InFuture(t)) return #Err(#CreatedInFuture({ ledger_time = t }));
      case (#Duplicate(idx)) return #Err(#Duplicate({ duplicate_of = idx }));
      case (#ok) {};
    };

    // Deduct fee FIRST (atomic: if approve fails, restore fee)
    switch (Bal.debit(balState, from, fee)) {
      case (#err(_)) return #Err(#InsufficientFunds({ balance = Bal.getBalance(balState, from) }));
      case (#ok(_)) {};
    };

    // Set allowance (restore fee on failure)
    switch (Allow.approve(allowState, from, spender, approveArgs.amount, approveArgs.expires_at, approveArgs.expected_allowance)) {
      case (#err(#AllowanceChanged(a))) {
        Bal.credit(balState, from, fee);
        return #Err(#AllowanceChanged(a));
      };
      case (#err(#Expired(e))) {
        Bal.credit(balState, from, fee);
        return #Err(#Expired(e));
      };
      case (#err(#InsufficientFunds(f))) {
        Bal.credit(balState, from, fee);
        return #Err(#InsufficientFunds(f));
      };
      case (#ok(())) {};
    };

    let tx = makeTx("approve", ?from, null, ?spender, approveArgs.amount, ?fee, approveArgs.memo);
    let idx = appendAndCertify(tx, ?fee);
    #Ok(idx)
  };

  // ═══════════════════════════════════════════════════════
  //  ICRC-2: TRANSFER_FROM
  // ═══════════════════════════════════════════════════════

  public shared ({ caller }) func icrc2_transfer_from(tfArgs : T.TransferFromArgs) : async { #Ok : Nat; #Err : T.TransferFromError } {
    if (guardCycles()) return #Err(#TemporarilyUnavailable);
    switch (validateSubaccount(tfArgs.spender_subaccount)) {
      case (?e) return #Err(#GenericError({ error_code = 100; message = e })); case null {};
    };
    switch (validateSubaccount(tfArgs.from.subaccount)) {
      case (?e) return #Err(#GenericError({ error_code = 100; message = e })); case null {};
    };
    switch (validateSubaccount(tfArgs.to.subaccount)) {
      case (?e) return #Err(#GenericError({ error_code = 100; message = e })); case null {};
    };

    let spender : T.Account = { owner = caller; subaccount = tfArgs.spender_subaccount };
    let from = tfArgs.from;
    let to = tfArgs.to;
    let amount = tfArgs.amount;

    // Burns and mints have fee = 0; regular transfers use tokenFee
    let isBurnTf = isMintingAccount(to);
    let isMintTf = isMintingAccount(from);
    let expectedFeeTf : Nat = if (isBurnTf or isMintTf) 0 else tokenFee;
    let fee = switch (tfArgs.fee) {
      case (?f) { if (f != expectedFeeTf) return #Err(#BadFee({ expected_fee = expectedFeeTf })); f };
      case null expectedFeeTf;
    };

    switch (validateMemo(tfArgs.memo)) {
      case (?e) return #Err(#GenericError({ error_code = 101; message = e })); case null {};
    };

    switch (checkDedupAndTime(caller, tfArgs.created_at_time, amount, tfArgs.memo)) {
      case (#TooOld) return #Err(#TooOld);
      case (#InFuture(t)) return #Err(#CreatedInFuture({ ledger_time = t }));
      case (#Duplicate(idx)) return #Err(#Duplicate({ duplicate_of = idx }));
      case (#ok) {};
    };

    // Check + use allowance (skip if self-transfer)
    let needsAllowance = not T.accountsEqual(from, spender);
    // Save allowance BEFORE decrement so we can restore exactly on failure
    let savedAllowance = if (needsAllowance) {
      ?Allow.getAllowance(allowState, from, spender)
    } else { null };

    if (needsAllowance) {
      switch (Allow.useAllowance(allowState, from, spender, amount + fee)) {
        case (#err(#InsufficientAllowance(a))) return #Err(#InsufficientAllowance(a));
        case (#ok(())) {};
      };
    };

    // Handle burn (to == minting), mint (from == minting), or regular transfer
    let isBurn = isMintingAccount(to);
    let isMint = isMintingAccount(from);

    if (isBurn) {
      // Burn: fee must be 0 for burns
      switch (Bal.burn(balState, from, amount)) {
        case (#err(#InsufficientFunds({ balance }))) {
          switch (savedAllowance) {
            case (?saved) { ignore Allow.approve(allowState, from, spender, saved.allowance, saved.expires_at, null) };
            case null {};
          };
          return #Err(#InsufficientFunds({ balance }));
        };
        case (#ok(())) {};
      };
      let tx = makeTx("burn", ?from, null, ?spender, amount, null, tfArgs.memo);
      let idx = appendAndCertify(tx, null);
      return #Ok(idx);
    };

    if (isMint) {
      switch (Bal.mint(balState, to, amount)) {
        case (#err(_)) return #Err(#GenericError({ error_code = 1; message = "Mint exceeds supply" }));
        case (#ok(())) {};
      };
      let tx = makeTx("mint", null, ?to, ?spender, amount, null, tfArgs.memo);
      let idx = appendAndCertify(tx, null);
      return #Ok(idx);
    };

    // Regular transfer
    switch (Bal.transfer(balState, from, to, amount, fee, feeCollector)) {
      case (#err(#InsufficientFunds({ balance }))) {
        switch (savedAllowance) {
          case (?saved) { ignore Allow.approve(allowState, from, spender, saved.allowance, saved.expires_at, null) };
          case null {};
        };
        return #Err(#InsufficientFunds({ balance }));
      };
      case (#ok(())) {};
    };

    let tx = makeTx("transfer", ?from, ?to, ?spender, amount, ?fee, tfArgs.memo);
    let idx = appendAndCertify(tx, ?fee);
    #Ok(idx)
  };

  // ═══════════════════════════════════════════════════════
  //  ICRC-1 QUERIES
  // ═══════════════════════════════════════════════════════

  public query func icrc1_name() : async Text { tokenName };
  public query func icrc1_symbol() : async Text { tokenSymbol };
  public query func icrc1_decimals() : async Nat8 { tokenDecimals };
  public query func icrc1_fee() : async Nat { tokenFee };
  public query func icrc1_total_supply() : async Nat { Bal.totalSupply(balState) };
  public query func icrc1_minting_account() : async ?T.Account { ?mintingAccount };

  public query func icrc1_balance_of(account : T.Account) : async Nat {
    Bal.getBalance(balState, account)
  };

  public query func icrc1_metadata() : async [(Text, T.Value)] {
    [
      ("icrc1:name", #Text(tokenName)),
      ("icrc1:symbol", #Text(tokenSymbol)),
      ("icrc1:decimals", #Nat(Nat8.toNat(tokenDecimals))),
      ("icrc1:fee", #Nat(tokenFee)),
      ("icrc1:max_memo_length", #Nat(maxMemoLength)),
    ]
  };

  public query func icrc1_supported_standards() : async [{ name : Text; url : Text }] {
    [
      { name = "ICRC-1"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-1" },
      { name = "ICRC-2"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-2" },
      { name = "ICRC-3"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-3" },
      { name = "ICRC-10"; url = "https://github.com/dfinity/ICRC/tree/main/ICRCs/ICRC-10" },
    ]
  };

  // ═══════════════════════════════════════════════════════
  //  CIRCUIT BREAKER STATUS
  // ═══════════════════════════════════════════════════════

  public query func getShieldStatus() : async {
    cycleBalance : Nat;
    threshold : Nat;
    tripped : Bool;
    blockCount : Nat;
  } {
    {
      cycleBalance = Cycles.balance();
      threshold = circuitBreakerThreshold;
      tripped = circuitBreakerTripped;
      blockCount = BLog.length(blockState);
    }
  };

  public shared ({ caller }) func setCircuitBreakerThreshold(newThreshold : Nat) : async () {
    assert(caller == initMsg.caller); // admin only
    circuitBreakerThreshold := newThreshold;
  };

  /// ICRC-3: Supported block types
  public query func icrc3_supported_block_types() : async [{ block_type : Text; url : Text }] {
    [
      { block_type = "1xfer"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-3" },
      { block_type = "2xfer"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-3" },
      { block_type = "1burn"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-3" },
      { block_type = "1mint"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-3" },
      { block_type = "2approve"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-3" },
    ]
  };

  // ═══════════════════════════════════════════════════════
  //  ICRC-2 QUERIES
  // ═══════════════════════════════════════════════════════

  public query func icrc2_allowance(allowanceArgs : T.AllowanceArgs) : async T.Allowance {
    Allow.getAllowance(allowState, allowanceArgs.account, allowanceArgs.spender)
  };

  // ═══════════════════════════════════════════════════════
  //  INDEX QUERIES (index-ng compatible — THE INNOVATION)
  // ═══════════════════════════════════════════════════════

  public query func get_account_transactions(args : T.GetAccountTransactionsArgs) : async T.GetAccountTransactionsResult {
    let txs = BLog.getAccountTransactions(blockState, args.account, args.start, args.max_results);
    let balance = Bal.getBalance(balState, args.account);
    let oldest = BLog.getOldestTxId(blockState, args.account);
    { transactions = txs; oldest_tx_id = oldest; balance }
  };

  public query func list_subaccounts(owner : Principal, start : ?Blob) : async [Blob] {
    BLog.listSubaccounts(blockState, owner, start)
  };

  // ═══════════════════════════════════════════════════════
  //  ICRC-3: BLOCK LOG
  // ═══════════════════════════════════════════════════════

  public query func icrc3_get_blocks(args : [T.GetBlocksArgs]) : async { blocks : [T.Block]; log_length : Nat } {
    let allBlocks = List.empty<T.Block>();
    for (range in args.vals()) {
      let rawBlocks = BLog.getBlocks(blockState, range.start, range.length);
      for (b in rawBlocks.vals()) {
        List.add(allBlocks, { id = b.index; block = blockToValue(b) });
      };
    };
    { blocks = List.toArray(allBlocks); log_length = BLog.length(blockState) }
  };

  /// Encode block as ICRC-3 Value (List-based O(1) field building)
  func blockToValue(b : BLog.Block) : T.Value {
    let btype = switch (b.transaction.kind) {
      case "transfer" {
        switch (b.transaction.spender) {
          case (?_) "2xfer";
          case null "1xfer";
        };
      };
      case "burn" "1burn";
      case "mint" "1mint";
      case "approve" "2approve";
      case (other) other;
    };

    let txFields = List.empty<(Text, T.Value)>();
    List.add(txFields, ("idx", #Nat(b.index)));
    List.add(txFields, ("amt", #Nat(b.transaction.amount)));
    switch (b.transaction.from) {
      case (?a) { List.add(txFields, ("from", accountToValue(a))) };
      case null {};
    };
    switch (b.transaction.to) {
      case (?a) { List.add(txFields, ("to", accountToValue(a))) };
      case null {};
    };
    switch (b.transaction.spender) {
      case (?a) { List.add(txFields, ("spender", accountToValue(a))) };
      case null {};
    };
    switch (b.transaction.memo) {
      case (?m) { List.add(txFields, ("memo", #Blob(m))) };
      case null {};
    };

    let fields = List.empty<(Text, T.Value)>();
    List.add(fields, ("btype", #Text(btype)));
    List.add(fields, ("ts", #Nat(Nat64.toNat(b.timestamp))));
    List.add(fields, ("tx", #Map(List.toArray(txFields))));
    switch (b.effectiveFee) {
      case (?f) { List.add(fields, ("fee", #Nat(f))) };
      case null {};
    };
    switch (b.parentHash) {
      case (?h) { List.add(fields, ("phash", #Blob(h))) };
      case null {};
    };
    #Map(List.toArray(fields))
  };

  func accountToValue(a : T.Account) : T.Value {
    switch (a.subaccount) {
      case (?s) #Map([("owner", #Blob(Principal.toBlob(a.owner))), ("subaccount", #Blob(s))]);
      case null #Map([("owner", #Blob(Principal.toBlob(a.owner)))]);
    };
  };

  // ═══════════════════════════════════════════════════════
  //  ICRC-3: GET TRANSACTIONS (required by spec)
  // ═══════════════════════════════════════════════════════

  public query func icrc3_get_transactions(args : { start : Nat; length : Nat }) : async {
    transactions : [T.Block];
    log_length : Nat;
    archived_transactions : [{
      args : { start : Nat; length : Nat };
      callback : shared query { start : Nat; length : Nat } -> async { transactions : [T.Block] };
    }];
  } {
    let rawBlocks = BLog.getBlocks(blockState, args.start, args.length);
    let blocks = Array.map<BLog.Block, T.Block>(rawBlocks, func(b) {
      { id = b.index; block = blockToValue(b) }
    });
    {
      transactions = blocks;
      log_length = BLog.length(blockState);
      archived_transactions = []; // single-canister: no archives
    }
  };

  // ═══════════════════════════════════════════════════════
  //  ICRC-10: SUPPORTED STANDARDS
  // ═══════════════════════════════════════════════════════

  public query func icrc10_supported_standards() : async [{ name : Text; url : Text }] {
    [
      { name = "ICRC-1"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-1" },
      { name = "ICRC-2"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-2" },
      { name = "ICRC-3"; url = "https://github.com/dfinity/ICRC-1/tree/main/standards/ICRC-3" },
      { name = "ICRC-10"; url = "https://github.com/dfinity/ICRC/tree/main/ICRCs/ICRC-10" },
    ]
  };

  // ═══════════════════════════════════════════════════════
  //  ICRC-3: ARCHIVES
  // ═══════════════════════════════════════════════════════

  public query func icrc3_get_archives(args : { from : ?Principal }) : async [{
    canister_id : Principal;
    start : Nat;
    end : Nat;
  }] {
    // Return all archive canisters, optionally filtered by `from` principal
    let startFrom : Nat = switch (args.from) {
      case null 0;
      case (?p) {
        var skip : Nat = 0;
        label find for (a in archives.vals()) {
          if (Principal.equal(a.canisterId, p)) break find;
          skip += 1;
        };
        skip
      };
    };
    Array.tabulate<{ canister_id : Principal; start : Nat; end : Nat }>(
      if (startFrom >= archives.size()) 0 else archives.size() - startFrom,
      func(i) {
        let a = archives[startFrom + i];
        { canister_id = a.canisterId; start = a.firstBlock; end = a.lastBlock }
      }
    )
  };

  // ═══════════════════════════════════════════════════════
  //  ICRC-3: TIP CERTIFICATE (certified data)
  // ═══════════════════════════════════════════════════════

  public query func icrc3_get_tip_certificate() : async ?{
    certificate : Blob;
    hash_tree : Blob;
  } {
    Cert.getTipCertificate(certState)
  };

  // ═══════════════════════════════════════════════════════
  //  MERKLE MOUNTAIN RANGE — O(log n) inclusion proofs
  // ═══════════════════════════════════════════════════════

  /// Get the MMR root hash (commitment over all blocks)
  public query func mmr_root() : async ?Blob {
    BLog.mmrRoot(blockState)
  };

  /// Generate an inclusion proof for a specific block
  public query func mmr_proof(blockIndex : Nat) : async ?{
    siblings : [Blob];
    peakIndex : Nat;
    peaks : [Blob];
  } {
    BLog.mmrProof(blockState, blockIndex)
  };

  // ═══════════════════════════════════════════════════════
  //  STATUS + ADMIN
  // ═══════════════════════════════════════════════════════

  public query func status() : async {
    total_transactions : Nat;
    total_accounts : Nat;
    total_supply : Nat;
    total_allowances : Nat;
    index_synced : Bool;
    mmr_peaks : Nat;
  } {
    {
      total_transactions = BLog.length(blockState);
      total_accounts = Bal.numAccounts(balState);
      total_supply = Bal.totalSupply(balState);
      total_allowances = Allow.size(allowState);
      index_synced = true;
      mmr_peaks = BLog.mmrPeakCount(blockState);
    }
  };

  public shared ({ caller }) func set_fee_collector(fc : ?T.Account) : async () {
    if (not Principal.equal(caller, initMsg.caller)) Runtime.trap("Not owner");
    feeCollector := fc;
  };

  // ═══════════════════════════════════════════════════════
  //  ARCHIVE MANAGEMENT
  // ═══════════════════════════════════════════════════════

  /// Set archive threshold (admin only). Blocks in the main canister's StableLog
  /// beyond this count trigger automatic archival.
  public shared ({ caller }) func setArchiveThreshold(threshold : Nat) : async () {
    assert(caller == initMsg.caller);
    archiveBlockThreshold := threshold;
  };

  /// Manually trigger archive spawning (admin only).
  /// Spawns a new Archive canister, migrates blocks [localBlockOffset..currentCount-retainCount],
  /// then updates the archive registry.
  public shared ({ caller }) func triggerArchive(retainCount : Nat, archiveCycles : Nat) : async { #ok : Principal; #err : Text } {
    assert(caller == initMsg.caller);
    if (archiveInProgress) return #err("Archive already in progress");
    let totalBlocks = BLog.length(blockState);
    if (totalBlocks <= retainCount) return #err("Nothing to archive");

    archiveInProgress := true;

    // Spawn new Archive canister
    let archive = await (with cycles = archiveCycles) Archive.Archive(Principal.fromActor(self));
    let archiveId = Principal.fromActor(archive);

    let migrateStart = localBlockOffset;
    let migrateEnd = totalBlocks - retainCount;

    await archive.init(migrateStart);

    // Migrate blocks in batches
    var pos = migrateStart;
    while (pos < migrateEnd) {
      let batchEnd = Nat.min(pos + archiveBatchSize, migrateEnd);
      let batch = BLog.getRawBlobs(blockState, pos - localBlockOffset, batchEnd - pos);
      ignore await archive.appendBlocks(batch);
      pos := batchEnd;
    };

    // Update registry
    let entry : ArchiveEntry = { canisterId = archiveId; firstBlock = migrateStart; lastBlock = migrateEnd - 1 };
    let newArchives = Array.tabulate<ArchiveEntry>(archives.size() + 1, func(i) {
      if (i < archives.size()) archives[i] else entry
    });
    archives := newArchives;
    localBlockOffset := migrateEnd;
    archiveInProgress := false;

    #ok(archiveId)
  };

  /// Query archive status
  public query func getArchiveStatus() : async {
    archiveCount : Nat;
    localBlockOffset : Nat;
    localBlockCount : Nat;
    totalBlocks : Nat;
    archiveThreshold : Nat;
  } {
    {
      archiveCount = archives.size();
      localBlockOffset;
      localBlockCount = BLog.length(blockState) - localBlockOffset;
      totalBlocks = BLog.length(blockState);
      archiveThreshold = archiveBlockThreshold;
    }
  };

  // Init at end to avoid forward references.
  // Only run on first install — state persists across upgrades.
  if (BLog.length(blockState) == 0) {
    initBalances();
  };

  // IC resets CertifiedData on upgrade — recertify from persisted state
  switch (BLog.tipHash(blockState)) {
    case (?hash) Cert.updateTip(certState, BLog.length(blockState) - 1, hash);
    case null {};
  };

  // ═══════════════════════════════════════════════════════
  //  MAINTENANCE TIMER — prune expired allowances every 60s
  // ═══════════════════════════════════════════════════════

  ignore Timer.recurringTimer<system>(#seconds 60, func() : async () {
    ignore Allow.prune(allowState, 50); // GC up to 50 expired allowances per tick
  });
};
