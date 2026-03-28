/// Allowances.mo — ICRC-2 allowance table (port of approvals.rs)
///
/// Mechanical port of dfinity/ic rs/ledger_suite/common/ledger_core/src/approvals.rs
///
/// Key behaviors matching Rust:
///   - AllowanceTable manages (owner, spender) → Allowance
///   - Supports expiration (expires_at field)
///   - prune() GCs expired allowances (called periodically)
///   - use_allowance() decrements on transfer_from
///   - expected_allowance check for CAS-style approve

import Map "mo:core/Map";
import Nat "mo:core/Nat";
import Nat64 "mo:core/Nat64";
import Int "mo:core/Int";
import Time "mo:core/Time";
import Principal "mo:core/Principal";
import Array "mo:core/Array";
import List "mo:core/List";
import Result "mo:core/Result";

import T "Types";

module {

  public type AllowanceRecord = {
    var allowance : Nat;
    var expires_at : ?Nat64;
    arrived_at : Nat64; // timestamp when approve was called
  };

  // Key: (owner_key, spender_key)
  public type AllowanceKey = (T.AccountKey, T.AccountKey);

  func allowanceKeyCompare(a : AllowanceKey, b : AllowanceKey) : { #less; #equal; #greater } {
    switch (T.accountKeyCompare(a.0, b.0)) {
      case (#equal) T.accountKeyCompare(a.1, b.1);
      case (other) other;
    };
  };

  public type ApproveError = {
    #AllowanceChanged : { current_allowance : Nat };
    #Expired : { ledger_time : Nat64 };
    #InsufficientFunds : { balance : Nat };
  };

  public type UseAllowanceError = {
    #InsufficientAllowance : { allowance : Nat };
  };

  // ═══════════════════════════════════════════════════════
  //  STABLE STATE (pure data — no closures)
  // ═══════════════════════════════════════════════════════

  public type State = {
    var table : Map.Map<AllowanceKey, AllowanceRecord>;
    var expirationQueue : List.List<(Nat64, AllowanceKey)>;
  };

  public func newState() : State {
    { var table = Map.empty<AllowanceKey, AllowanceRecord>(); var expirationQueue = List.empty<(Nat64, AllowanceKey)>() };
  };

  // ═══════════════════════════════════════════════════════
  //  OPERATIONS
  // ═══════════════════════════════════════════════════════

  /// Get current allowance, accounting for expiration. Deletes expired records inline.
  public func getAllowance(state : State, owner : T.Account, spender : T.Account) : T.Allowance {
    let key : AllowanceKey = (T.accountKey(owner), T.accountKey(spender));
    switch (Map.get(state.table, allowanceKeyCompare, key)) {
      case (?record) {
        switch (record.expires_at) {
          case (?exp) {
            let now = Nat64.fromNat(Int.abs(Time.now()));
            if (exp <= now) {
              ignore Map.delete(state.table, allowanceKeyCompare, key);
              return { allowance = 0; expires_at = null };
            };
          };
          case null {};
        };
        { allowance = record.allowance; expires_at = record.expires_at }
      };
      case null ({ allowance = 0; expires_at = null } : T.Allowance);
    };
  };

  /// Set allowance. Matches Rust: approve(account, spender, amount, expires_at, now, expected_allowance)
  public func approve(
    state : State,
    owner : T.Account,
    spender : T.Account,
    amount : Nat,
    expires_at : ?Nat64,
    expectedAllowance : ?Nat,
  ) : Result.Result<(), ApproveError> {
    let key : AllowanceKey = (T.accountKey(owner), T.accountKey(spender));
    let now = Nat64.fromNat(Int.abs(Time.now()));

    // Check expiry of new allowance
    switch (expires_at) {
      case (?exp) {
        if (exp <= now) return #err(#Expired({ ledger_time = now }));
      };
      case null {};
    };

    // Check expected_allowance (CAS)
    switch (expectedAllowance) {
      case (?expected) {
        let current = getAllowance(state, owner, spender).allowance;
        if (current != expected) return #err(#AllowanceChanged({ current_allowance = current }));
      };
      case null {};
    };

    // Set/update allowance
    let record : AllowanceRecord = {
      var allowance = amount;
      var expires_at = expires_at;
      arrived_at = now;
    };
    Map.add(state.table, allowanceKeyCompare, key, record);

    // Track in expiration queue (duplicates are harmless — prune handles them)
    switch (expires_at) {
      case (?exp) { List.add(state.expirationQueue, (exp, key)) };
      case null {};
    };

    #ok(())
  };

  /// Use (decrement) allowance during transfer_from.
  public func useAllowance(
    state : State,
    owner : T.Account,
    spender : T.Account,
    amount : Nat,
  ) : Result.Result<(), UseAllowanceError> {
    let key : AllowanceKey = (T.accountKey(owner), T.accountKey(spender));
    let now = Nat64.fromNat(Int.abs(Time.now()));

    switch (Map.get(state.table, allowanceKeyCompare, key)) {
      case (?record) {
        // Check expiry
        switch (record.expires_at) {
          case (?exp) {
            if (exp <= now) return #err(#InsufficientAllowance({ allowance = 0 }));
          };
          case null {};
        };

        if (record.allowance < amount) {
          return #err(#InsufficientAllowance({ allowance = record.allowance }));
        };

        record.allowance -= amount;

        // Remove if zero
        if (record.allowance == 0) {
          ignore Map.delete(state.table, allowanceKeyCompare, key);
        };

        #ok(())
      };
      case null #err(#InsufficientAllowance({ allowance = 0 }));
    };
  };

  /// Prune expired allowances. Scans from the front of the queue (oldest expiry first)
  /// and stops after `limit` deletions OR when hitting a non-expired entry.
  /// Queue entries are kept sorted by expiry time (approvals append to tail).
  /// Stale entries (re-approved, deleted) are dropped in O(1) as encountered.
  public func prune(state : State, limit : Nat) : Nat {
    let now = Nat64.fromNat(Int.abs(Time.now()));
    var pruned : Nat = 0;
    var scanned : Nat = 0;
    let maxScan = limit * 5; // scan up to 5x limit to clear stale entries
    var remaining = List.empty<(Nat64, AllowanceKey)>();
    var hitLiveEntry = false;

    for ((exp, key) in List.values(state.expirationQueue)) {
      if (hitLiveEntry or (pruned >= limit and scanned >= maxScan)) {
        // Past our budget — keep the rest as-is
        List.add(remaining, (exp, key));
      } else {
        scanned += 1;
        switch (Map.get(state.table, allowanceKeyCompare, key)) {
          case null {}; // Already gone — drop silently
          case (?record) {
            if (exp <= now) {
              // Check if this queue entry still matches the record
              switch (record.expires_at) {
                case (?currentExp) {
                  if (currentExp == exp) {
                    ignore Map.delete(state.table, allowanceKeyCompare, key);
                    pruned += 1;
                  };
                  // else: stale duplicate — drop
                };
                case null {}; // No longer expires — drop
              };
            } else {
              // Not expired yet — keep and stop scanning (queue is ~sorted)
              List.add(remaining, (exp, key));
              hitLiveEntry := true;
            };
          };
        };
      };
    };

    state.expirationQueue := remaining;
    pruned
  };

  /// Number of active allowances
  public func size(state : State) : Nat {
    Map.size(state.table)
  };

  public type AccountKey = T.AccountKey;
};
