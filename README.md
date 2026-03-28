# ICRC-ME: Self-Indexed ICRC Token Ledger

A fully ICRC-1/ICRC-2/ICRC-3/ICRC-10 compliant token ledger for the Internet Computer; written in Motoko. The ledger integrates an account transaction index, a Merkle Mountain Range for inclusion proofs, and a Bloom filter for probabilistic deduplication directly into the canister. This eliminates the separate index canister that the reference architecture requires; removing its idle cycle drain entirely while maintaining full compatibility with existing wallets, explorers, and DEX infrastructure.

## Motivation

The standard ICRC deployment pairs a ledger canister with a dedicated index canister. The index canister polls the ledger at short intervals to replicate transaction data for account-level queries. On mainnet, this polling consumes approximately 3.32 trillion cycles per day; roughly $1,618 per year per token; regardless of whether any transactions occur. The ICRC-ME ledger absorbs the indexing function into the ledger itself, removing this cost at the source.

The resulting canister operates at 94-114% of the Rust ICRC reference ledger's per-operation compute cost. Transfers are 6% faster than the Rust reference; approvals are 14% slower due to SHA-256 dedup key computation; and block queries are 37x faster thanks to the v3 compact binary encoding with lazy CBOR reconstruction.

## Architecture

| Module | Purpose |
|--------|---------|
| `IndexedLedger.mo` | ICRC-1/2/3/10 actor; orchestrates all subsystems; circuit breaker for cycle drain protection |
| `BlockLog.mo` | Append-only transaction log with SHA-256 hash chain; delegates storage to StableLog and indexing to BTreeIndex |
| `BTreeIndex.mo` | Account transaction index combining B-tree lookup with block chain storage; O(k log n) prefix scan for subaccount queries |
| `RegionBTree.mo` | Region-backed B-tree for sorted stable memory storage; 113-entry leaf nodes; prefix scan for targeted queries |
| `Balances.mo` | Account balance tracking; functional state pattern over `Map` |
| `Allowances.mo` | ICRC-2 approval management with timer-based expiry pruning |
| `CertifiedTree.mo` | IC BLS-certified Merkle hash tree for trustless query verification; IC-spec compliant domain separators |
| `MerkleMMR.mo` | Merkle Mountain Range; provides O(log n) inclusion proofs for any historical block |
| `BloomFilter.mo` | Time-windowed Bloom filter; eliminates 99%+ of Map lookups for transaction deduplication |
| `CBOR.mo` | CBOR encoder and decoder for ICRC-3 block serialisation; pre-allocated buffer writer to minimise GC pressure |
| `StableLog.mo` | Region-backed append-only byte log; O(1) append and random access; scales to gigabytes |
| `Archive.mo` | Overflow block storage for ledgers exceeding single-canister capacity |
| `Types.mo` | ICRC-compliant type definitions; account key serialisation for Region storage |

## Performance

Measured on a local IC replica against the Rust ICRC reference ledger (`ic-icrc1-ledger`). Cycles obtained from canister status balance differentials over batches of 20-50 operations.

| Operation | ICRC-ME (Motoko) | Rust ICRC Reference | Ratio |
|-----------|-----------------|---------------------|-------|
| Transfer | 7.7M cycles | 8.1M cycles | **94% (6% faster)** |
| Approve | 8.6M cycles | 7.5M cycles | 114% |
| Balance query | 40K cycles | 39K cycles | 102% (parity) |
| get_blocks(50) | 194K cycles | 7.2M cycles | **2% (37x faster)** |
| Account index query | 100K cycles | N/A (separate canister) | Built-in |
| Index canister daily cost | 0 | ~3.32T cycles | Eliminated |
| Estimated annual saving | — | ~$1,618 per token | — |

### Storage

| Metric | ICRC-ME | Rust Reference |
|--------|---------|----------------|
| WASM size | 715 KB | 1,245 KB |
| Per-account overhead | ~112 bytes (B-tree leaf + chain block) | N/A (no built-in index) |
| B-tree depth at 1B accounts | ~4 levels | N/A |
| Scaling capacity | 10M accounts within 64GB | N/A |

## Security

### Transaction Deduplication

Deduplication uses a composite key: `SHA256(caller_principal, created_at_time, amount, memo)`. This prevents two different users from colliding on timestamp alone and eliminates the front-running DoS vector present in timestamp-only dedup schemes. A time-windowed Bloom filter provides O(1) fast-path rejection for 99%+ of non-duplicate transactions; false positives fall through to exact Map lookup.

### Circuit Breaker

The ledger includes a configurable circuit breaker that freezes all write operations when the canister's cycle balance falls below a threshold (default: 100 billion cycles). Read operations (balance queries, block queries, proofs) remain available. The canister resumes normal operation automatically when cycles are replenished.

```
dfx canister call <canister_id> getShieldStatus '()'
dfx canister call <canister_id> setCircuitBreakerThreshold '(200_000_000_000)'
```

### Certified Data

The `icrc3_get_tip_certificate` endpoint returns a BLS-certified hash tree over the last block index and hash. Domain separators follow the IC specification (`"ic-hashtree-empty"`, `"ic-hashtree-fork"`, `"ic-hashtree-labeled"`, `"ic-hashtree-leaf"`). Block indices are encoded as big-endian bytes for client interoperability.

## Feature Comparison

| Feature | ICRC-ME | Rust ICRC + Index |
|---------|---------|-------------------|
| ICRC-1 transfers | Yes | Yes |
| ICRC-2 approvals | Yes | Yes |
| ICRC-3 block queries | Yes | Yes |
| ICRC-3 `get_transactions` | Yes | Yes |
| ICRC-10 supported standards | Yes | No |
| Account transaction index | Built-in (B-tree + block chain) | Separate canister |
| Subaccount listing | B-tree prefix scan O(k log n) | N/A |
| Merkle inclusion proofs | Yes (MMR) | No |
| Bloom filter deduplication | Yes | No |
| SHA-256 hash chain | Yes | Yes |
| IC-certified queries | Yes | Yes |
| Circuit breaker (cycle drain) | Yes | No |
| Min burn amount enforcement | Yes | Yes |
| Validation errors (no traps) | Yes | Partial |
| Idle cycle burn | ~0 | ~3.32T/day |
| GC scaling with accounts | Constant (Region) | N/A (Rust) |

## Getting Started

```bash
mops install
dfx start --background
dfx deploy token_a --argument '(record {
  name = "MyToken";
  symbol = "MTK";
  decimals = 8 : nat8;
  fee = 10_000 : nat;
  minting_account = record { owner = principal "<YOUR_PRINCIPAL>"; subaccount = null };
  initial_balances = vec { record { record { owner = principal "<YOUR_PRINCIPAL>"; subaccount = null }; 1_000_000_000_000 : nat } };
  max_memo_length = null;
  max_supply = null;
})'
```

## Dependencies

- `mo:core` 2.3.1 (Motoko core library)
- `mo:sha2` 0.1.9 (SHA-256 implementation)
- dfx 0.31.0+ with Motoko compiler 1.1.0+
- Enhanced Orthogonal Persistence enabled

## License

MIT

---

Co-authored by Engineer Jumana Nehad, Nour Ahmed, and Kareem Younes; with research assistance from ICP Hub Egypt and Mercatura Forum. We invite community feedback.
