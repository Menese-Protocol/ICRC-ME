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

import T "Types";
import Bal "Balances";
import Allow "Allowances";
import BLog "BlockLog";
import Cert "CertifiedTree";
import Bloom "BloomFilter";

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

  // Dedup: Bloom filter (O(1) fast path) + Map (exact fallback)
  var recentTxs = Map.empty<Nat64, Nat>();
  var bloomState : Bloom.State = Bloom.newState(86_400_000_000_000); // 24h window
  let TX_WINDOW_NS : Nat64 = 86_400_000_000_000;
  let PERMITTED_DRIFT_NS : Nat64 = 60_000_000_000;

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
        timestamp = Nat64.fromNat(Int.abs(Time.now())); index = 0;
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

  // Prune up to 20 expired entries per call (amortized GC)
  var dedupPruneCounter : Nat = 0;
  func pruneDedupMap() {
    dedupPruneCounter += 1;
    if (dedupPruneCounter % 10 != 0) return; // prune every 10th call
    let n = now();
    let cutoff = n - TX_WINDOW_NS - PERMITTED_DRIFT_NS - 60_000_000_000; // 1 min margin
    let toDelete = List.empty<Nat64>();
    var count : Nat = 0;
    for ((ts, _) in Map.entries(recentTxs)) {
      if (count >= 20) return;
      if (ts < cutoff) {
        List.add(toDelete, ts);
        count += 1;
      };
    };
    for (ts in List.values(toDelete)) {
      ignore Map.delete(recentTxs, Nat64.compare, ts);
    };
  };

  func checkDedupAndTime(created_at_time : ?Nat64) : { #ok; #TooOld; #InFuture : Nat64; #Duplicate : Nat } {
    pruneDedupMap();
    switch (created_at_time) {
      case null #ok;
      case (?ts) {
        let n = now();
        if (ts + TX_WINDOW_NS + PERMITTED_DRIFT_NS < n) return #TooOld;
        if (ts > n + PERMITTED_DRIFT_NS) return #InFuture(n);
        // Bloom fast path (keyed on timestamp; false positives fall through to Map)
        if (not Bloom.mightContain(bloomState, ts, n)) {
          Bloom.add(bloomState, ts, n);
          Map.add(recentTxs, Nat64.compare, ts, BLog.length(blockState));
          return #ok;
        };
        // Exact check: timestamp match means potential duplicate
        switch (Map.get(recentTxs, Nat64.compare, ts)) {
          case (?idx) #Duplicate(idx);
          case null {
            Bloom.add(bloomState, ts, n);
            Map.add(recentTxs, Nat64.compare, ts, BLog.length(blockState));
            #ok
          };
        };
      };
    };
  };

  func validateMemo(memo : ?Blob) {
    switch (memo) {
      case (?m) { if (m.size() > maxMemoLength) Runtime.trap("Memo too long") };
      case null {};
    };
  };

  func validateSubaccount(sub : ?Blob) {
    switch (sub) {
      case (?s) { if (s.size() != 32) Runtime.trap("Subaccount must be 32 bytes") };
      case null {};
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
    validateSubaccount(transferArgs.from_subaccount);
    validateSubaccount(transferArgs.to.subaccount);

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

    validateMemo(transferArgs.memo);

    switch (checkDedupAndTime(transferArgs.created_at_time)) {
      case (#TooOld) return #Err(#TooOld);
      case (#InFuture(t)) return #Err(#CreatedInFuture({ ledger_time = t }));
      case (#Duplicate(idx)) return #Err(#Duplicate({ duplicate_of = idx }));
      case (#ok) {};
    };

    // Burn
    if (isMintingAccount(to)) {
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
    validateSubaccount(approveArgs.from_subaccount);
    validateSubaccount(approveArgs.spender.subaccount);

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

    validateMemo(approveArgs.memo);

    switch (checkDedupAndTime(approveArgs.created_at_time)) {
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
    validateSubaccount(tfArgs.spender_subaccount);
    validateSubaccount(tfArgs.from.subaccount);
    validateSubaccount(tfArgs.to.subaccount);

    let spender : T.Account = { owner = caller; subaccount = tfArgs.spender_subaccount };
    let from = tfArgs.from;
    let to = tfArgs.to;
    let amount = tfArgs.amount;

    let fee = switch (tfArgs.fee) {
      case (?f) { if (f != tokenFee) return #Err(#BadFee({ expected_fee = tokenFee })); f };
      case null tokenFee;
    };

    validateMemo(tfArgs.memo);

    switch (checkDedupAndTime(tfArgs.created_at_time)) {
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
  //  ICRC-3: ARCHIVES
  // ═══════════════════════════════════════════════════════

  public query func icrc3_get_archives(args : { from : ?Principal }) : async [{
    canister_id : Principal;
    start : Nat;
    end : Nat;
  }] {
    [{
      canister_id = Principal.fromActor(self);
      start = 0;
      end = BLog.length(blockState);
    }]
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
