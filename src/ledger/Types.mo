/// Types.mo — ICRC-1/ICRC-2/ICRC-3 compliant types for self-indexed ledger
///
/// Matches the official Candid spec exactly. Compatible with all existing
/// ICRC tooling (wallets, explorers, DEXes).

import Principal "mo:core/Principal";
import Nat8 "mo:core/Nat8";
import Nat32 "mo:core/Nat32";
import Blob "mo:core/Blob";
import Array "mo:core/Array";

module {

  // ═══════════════════════════════════════════════════════
  //  ICRC-1 CORE TYPES
  // ═══════════════════════════════════════════════════════

  public type Account = { owner : Principal; subaccount : ?Blob };

  public type TransferArgs = {
    from_subaccount : ?Blob;
    to : Account;
    amount : Nat;
    fee : ?Nat;
    memo : ?Blob;
    created_at_time : ?Nat64;
  };

  public type TransferError = {
    #BadFee : { expected_fee : Nat };
    #BadBurn : { min_burn_amount : Nat };
    #InsufficientFunds : { balance : Nat };
    #TooOld;
    #CreatedInFuture : { ledger_time : Nat64 };
    #Duplicate : { duplicate_of : Nat };
    #TemporarilyUnavailable;
    #GenericError : { error_code : Nat; message : Text };
  };

  // ═══════════════════════════════════════════════════════
  //  ICRC-2 APPROVE + TRANSFER_FROM TYPES
  // ═══════════════════════════════════════════════════════

  public type ApproveArgs = {
    from_subaccount : ?Blob;
    spender : Account;
    amount : Nat;
    expected_allowance : ?Nat;
    expires_at : ?Nat64;
    fee : ?Nat;
    memo : ?Blob;
    created_at_time : ?Nat64;
  };

  public type ApproveError = {
    #BadFee : { expected_fee : Nat };
    #InsufficientFunds : { balance : Nat };
    #AllowanceChanged : { current_allowance : Nat };
    #Expired : { ledger_time : Nat64 };
    #TooOld;
    #CreatedInFuture : { ledger_time : Nat64 };
    #Duplicate : { duplicate_of : Nat };
    #TemporarilyUnavailable;
    #GenericError : { error_code : Nat; message : Text };
  };

  public type TransferFromArgs = {
    spender_subaccount : ?Blob;
    from : Account;
    to : Account;
    amount : Nat;
    fee : ?Nat;
    memo : ?Blob;
    created_at_time : ?Nat64;
  };

  public type TransferFromError = {
    #BadFee : { expected_fee : Nat };
    #BadBurn : { min_burn_amount : Nat };
    #InsufficientFunds : { balance : Nat };
    #InsufficientAllowance : { allowance : Nat };
    #TooOld;
    #CreatedInFuture : { ledger_time : Nat64 };
    #Duplicate : { duplicate_of : Nat };
    #TemporarilyUnavailable;
    #GenericError : { error_code : Nat; message : Text };
  };

  public type AllowanceArgs = { account : Account; spender : Account };
  public type Allowance = { allowance : Nat; expires_at : ?Nat64 };

  // ═══════════════════════════════════════════════════════
  //  ICRC-3 BLOCK LOG TYPES (for external compatibility)
  // ═══════════════════════════════════════════════════════

  public type Value = {
    #Nat : Nat;
    #Int : Int;
    #Text : Text;
    #Blob : Blob;
    #Array : [Value];
    #Map : [(Text, Value)];
  };

  public type Block = {
    id : Nat;
    block : Value; // ICRC-3 generic block
  };

  public type GetBlocksArgs = { start : Nat; length : Nat };
  public type GetBlocksResult = { blocks : [Block]; log_length : Nat };

  // ═══════════════════════════════════════════════════════
  //  INDEX TYPES (compatible with index-ng query API)
  // ═══════════════════════════════════════════════════════

  public type Transaction = {
    kind : Text;       // "transfer", "approve", "burn", "mint"
    from : ?Account;
    to : ?Account;
    spender : ?Account;
    amount : Nat;
    fee : ?Nat;
    memo : ?Blob;
    timestamp : Nat64;
    index : Nat;       // block index
  };

  public type GetAccountTransactionsArgs = {
    account : Account;
    start : ?Nat;      // start index (newest first if null)
    max_results : Nat;
  };

  public type GetAccountTransactionsResult = {
    transactions : [Transaction];
    oldest_tx_id : ?Nat;
    balance : Nat;
  };

  // ═══════════════════════════════════════════════════════
  //  LEDGER INIT ARGS
  // ═══════════════════════════════════════════════════════

  public type InitArgs = {
    name : Text;
    symbol : Text;
    decimals : Nat8;
    fee : Nat;
    minting_account : Account;
    initial_balances : [(Account, Nat)];
    max_memo_length : ?Nat;
    max_supply : ?Nat;
  };

  // ═══════════════════════════════════════════════════════
  //  ACCOUNT HELPERS
  // ═══════════════════════════════════════════════════════

  public func accountsEqual(a : Account, b : Account) : Bool {
    Principal.equal(a.owner, b.owner) and subaccountsEqual(a.subaccount, b.subaccount)
  };

  func subaccountsEqual(a : ?Blob, b : ?Blob) : Bool {
    switch (a, b) {
      case (null, null) true;
      case (?sa, null) isDefaultSubaccount(sa);
      case (null, ?sb) isDefaultSubaccount(sb);
      case (?sa, ?sb) sa == sb;
    };
  };

  func isDefaultSubaccount(s : Blob) : Bool {
    // Default subaccount is 32 zero bytes or empty
    if (s.size() == 0) return true;
    if (s.size() != 32) return false;
    for (b in s.vals()) { if (b != 0) return false };
    true;
  };

  public type AccountKey = (Principal, Blob);

  /// Canonical account key for Map lookups — (principal, subaccount_or_empty)
  public func accountKey(a : Account) : AccountKey {
    let sub = switch (a.subaccount) {
      case (?s) { if (isDefaultSubaccount(s)) { "" : Blob } else { s } };
      case null { "" : Blob };
    };
    (a.owner, sub)
  };

  /// Serialize AccountKey to a fixed 62-byte blob for Region storage.
  /// Format: [principal_len:1][principal:29 padded][subaccount:32]
  /// No hash; full subaccount stored; zero collision risk.
  public func accountKeyToBlob(key : AccountKey) : Blob {
    let pBlob = Principal.toBlob(key.0);
    let sub = key.1;
    let pArr = Blob.toArray(pBlob);
    let sArr = Blob.toArray(sub);
    Blob.fromArray(Array.tabulate<Nat8>(62, func(i) {
      if (i == 0) Nat8.fromNat(pBlob.size())
      else if (i <= 29) {
        if (i - 1 < pArr.size()) pArr[i - 1] else 0
      }
      else {
        let si = i - 30;
        if (si < sArr.size()) sArr[si] else 0
      }
    }))
  };

  public func accountKeyCompare(a : (Principal, Blob), b : (Principal, Blob)) : { #less; #equal; #greater } {
    switch (Principal.compare(a.0, b.0)) {
      case (#equal) {
        // Compare blobs
        let ab = a.1;
        let bb = b.1;
        if (ab < bb) #less else if (ab > bb) #greater else #equal
      };
      case (other) other;
    };
  };
};
