/// Balances.mo — Account balance management (port of balances.rs)
///
/// Mechanical port of dfinity/ic rs/ledger_suite/common/ledger_core/src/balances.rs
///
/// Key behaviors matching Rust:
///   - debit auto-removes account from map when balance reaches zero
///   - credit auto-adds account to map
///   - token_pool tracks unminted supply (starts at MAX, decreases on mint)
///   - transfer routes fee to fee_collector or back to token_pool
///   - total_supply = MAX - token_pool

import Map "mo:core/Map";
import Nat "mo:core/Nat";
import Result "mo:core/Result";
import Runtime "mo:core/Runtime";
import Principal "mo:core/Principal";

import T "Types";

module {

  /// MAX_SUPPLY: Motoko Nat is unbounded, but for token_pool accounting
  /// we need a finite max. Default: 2^128 (same magnitude as Rust Tokens::max_value for u128).
  /// Override via initArgs.max_supply if needed.
  public let DEFAULT_MAX_SUPPLY : Nat = 340_282_366_920_938_463_463_374_607_431_768_211_455; // 2^128 - 1

  public type BalanceError = {
    #InsufficientFunds : { balance : Nat };
  };

  public type AccountKey = (Principal, Blob);

  // ═══════════════════════════════════════════════════════
  //  STABLE STATE (pure data — no closures)
  // ═══════════════════════════════════════════════════════

  public type State = {
    var store : Map.Map<AccountKey, Nat>;
    var tokenPool : Nat;
    maxSupply : Nat;
  };

  public func newState(maxSupply : Nat) : State {
    { var store = Map.empty<AccountKey, Nat>(); var tokenPool = maxSupply; maxSupply };
  };

  // ═══════════════════════════════════════════════════════
  //  OPERATIONS
  // ═══════════════════════════════════════════════════════

  /// Get balance for an account. Returns 0 if not found.
  public func getBalance(state : State, account : T.Account) : Nat {
    let key = T.accountKey(account);
    switch (Map.get(state.store, T.accountKeyCompare, key)) {
      case (?bal) bal;
      case null 0;
    };
  };

  /// Credit an account (add tokens). Auto-creates entry if new.
  public func credit(state : State, account : T.Account, amount : Nat) {
    if (amount == 0) return;
    let key = T.accountKey(account);
    let current = switch (Map.get(state.store, T.accountKeyCompare, key)) {
      case (?bal) bal;
      case null 0;
    };
    Map.add(state.store, T.accountKeyCompare, key, current + amount);
  };

  /// Debit an account (remove tokens). Auto-removes entry if balance reaches zero.
  public func debit(state : State, account : T.Account, amount : Nat) : Result.Result<Nat, BalanceError> {
    let key = T.accountKey(account);
    let current = switch (Map.get(state.store, T.accountKeyCompare, key)) {
      case (?bal) bal;
      case null return #err(#InsufficientFunds({ balance = 0 }));
    };
    if (current < amount) return #err(#InsufficientFunds({ balance = current }));

    let newBalance : Nat = current - amount;
    if (newBalance == 0) {
      ignore Map.delete(state.store, T.accountKeyCompare, key);
    } else {
      Map.add(state.store, T.accountKeyCompare, key, newBalance);
    };
    #ok(newBalance)
  };

  /// Transfer tokens between accounts with fee handling.
  public func transfer(
    state : State,
    from : T.Account,
    to : T.Account,
    amount : Nat,
    fee : Nat,
    feeCollector : ?T.Account,
  ) : Result.Result<(), BalanceError> {
    let debitAmount = amount + fee;
    switch (debit(state, from, debitAmount)) {
      case (#err(e)) return #err(e);
      case (#ok(_)) {};
    };
    credit(state, to, amount);
    switch (feeCollector) {
      case (?fc) { credit(state, fc, fee) };
      case null { state.tokenPool += fee }; // Fee returns to unminted pool
    };
    #ok(())
  };

  /// Burn tokens from an account (transfer to minting account = burn).
  public func burn(state : State, from : T.Account, amount : Nat) : Result.Result<(), BalanceError> {
    switch (debit(state, from, amount)) {
      case (#err(e)) return #err(e);
      case (#ok(_)) {};
    };
    state.tokenPool += amount;
    #ok(())
  };

  /// Mint tokens to an account.
  public func mint(state : State, to : T.Account, amount : Nat) : Result.Result<(), BalanceError> {
    if (amount > state.tokenPool) {
      Runtime.trap("Mint exceeds total token supply");
    };
    state.tokenPool -= amount;
    credit(state, to, amount);
    #ok(())
  };

  /// Total supply = maxSupply - tokenPool (unminted)
  public func totalSupply(state : State) : Nat {
    state.maxSupply - state.tokenPool
  };

  /// Number of accounts with non-zero balance
  public func numAccounts(state : State) : Nat {
    Map.size(state.store)
  };

  /// Set balance directly (for init)
  public func setBalance(state : State, account : T.Account, amount : Nat) {
    let key = T.accountKey(account);
    if (amount == 0) {
      ignore Map.delete(state.store, T.accountKeyCompare, key);
    } else {
      Map.add(state.store, T.accountKeyCompare, key, amount);
    };
  };

  /// Reduce token pool by amount (for init when setting initial balances)
  public func reducePool(state : State, amount : Nat) {
    state.tokenPool -= amount;
  };
};
