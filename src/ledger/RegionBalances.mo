/// RegionBalances.mo — Account balance storage in Region stable memory
///
/// Replaces the heap-resident Map<AccountKey, Nat> with a Region-backed B-tree.
/// At 10M accounts, this uses ~780MB of stable memory (cheap) instead of
/// ~1.5GB of GC-visible heap (dangerous).
///
/// Uses the same RegionBTree with KEY_SIZE=62, VAL_SIZE=16.
/// Balance is encoded as 16-byte big-endian Nat (supports up to 2^128).

import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Blob "mo:core/Blob";
import Array "mo:core/Array";
import Result "mo:core/Result";
import Runtime "mo:core/Runtime";

import T "Types";
import BTree "RegionBTree";

module {

  public let DEFAULT_MAX_SUPPLY : Nat = 340_282_366_920_938_463_463_374_607_431_768_211_455;

  public type BalanceError = {
    #InsufficientFunds : { balance : Nat };
  };

  public type State = {
    btree : BTree.State;
    var tokenPool : Nat;
    maxSupply : Nat;
  };

  public func newState(maxSupply : Nat) : State {
    { btree = BTree.newState(); var tokenPool = maxSupply; maxSupply };
  };

  // ── Nat <-> 16-byte big-endian Blob ──

  func encodeNat(n : Nat) : Blob {
    Blob.fromArray(Array.tabulate<Nat8>(16, func(i) {
      Nat8.fromNat((n / (256 ** (15 - i))) % 256)
    }))
  };

  func decodeNat(b : Blob) : Nat {
    let arr = Blob.toArray(b);
    var n : Nat = 0;
    var i = 0;
    while (i < arr.size()) {
      n := n * 256 + Nat8.toNat(arr[i]);
      i += 1;
    };
    n
  };

  // ── Public API (same interface as old Balances.mo) ──

  public func getBalance(state : State, account : T.Account) : Nat {
    let kb = T.accountKeyToBlob(T.accountKey(account));
    switch (BTree.get(state.btree, kb)) {
      case (?val) { let n = decodeNat(val); if (n == 0) 0 else n }; // zero-entries treated as absent
      case null 0;
    };
  };

  public func credit(state : State, account : T.Account, amount : Nat) {
    if (amount == 0) return;
    let kb = T.accountKeyToBlob(T.accountKey(account));
    let current = switch (BTree.get(state.btree, kb)) {
      case (?val) decodeNat(val);
      case null 0;
    };
    ignore BTree.put(state.btree, kb, encodeNat(current + amount));
  };

  public func debit(state : State, account : T.Account, amount : Nat) : Result.Result<Nat, BalanceError> {
    let kb = T.accountKeyToBlob(T.accountKey(account));
    let current = switch (BTree.get(state.btree, kb)) {
      case (?val) decodeNat(val);
      case null return #err(#InsufficientFunds({ balance = 0 }));
    };
    if (current < amount) return #err(#InsufficientFunds({ balance = current }));
    let newBalance = current - amount;
    if (newBalance == 0) {
      // Remove zero-balance entries to save space
      // BTree doesn't support delete, so store 0 (will be treated as absent on read)
      ignore BTree.put(state.btree, kb, encodeNat(0));
    } else {
      ignore BTree.put(state.btree, kb, encodeNat(newBalance));
    };
    #ok(newBalance)
  };

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
      case null { state.tokenPool += fee };
    };
    #ok(())
  };

  public func burn(state : State, from : T.Account, amount : Nat) : Result.Result<(), BalanceError> {
    switch (debit(state, from, amount)) {
      case (#err(e)) return #err(e);
      case (#ok(_)) {};
    };
    state.tokenPool += amount;
    #ok(())
  };

  public func mint(state : State, to : T.Account, amount : Nat) : Result.Result<(), BalanceError> {
    if (amount > state.tokenPool) {
      Runtime.trap("Mint exceeds total token supply");
    };
    state.tokenPool -= amount;
    credit(state, to, amount);
    #ok(())
  };

  public func totalSupply(state : State) : Nat {
    state.maxSupply - state.tokenPool
  };

  public func numAccounts(state : State) : Nat {
    BTree.size(state.btree)
  };

  public func setBalance(state : State, account : T.Account, amount : Nat) {
    let kb = T.accountKeyToBlob(T.accountKey(account));
    ignore BTree.put(state.btree, kb, encodeNat(amount));
  };

  public func reducePool(state : State, amount : Nat) {
    state.tokenPool -= amount;
  };
};
