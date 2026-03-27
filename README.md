# ICRC-ME: Self-Indexed ICRC Token Ledger

A fully ICRC-1/ICRC-2/ICRC-3/ICRC-10 compliant token ledger for the Internet Computer; written in Motoko. The ledger integrates an account transaction index, a Merkle Mountain Range for inclusion proofs, and a Bloom filter for probabilistic deduplication directly into the canister. This eliminates the separate index canister that the reference architecture requires; removing its idle cycle drain entirely while maintaining full compatibility with existing wallets, explorers, and DEX infrastructure.

## Motivation

The standard ICRC deployment pairs a ledger canister with a dedicated index canister. The index canister polls the ledger at short intervals to replicate transaction data for account-level queries. On mainnet, this polling consumes approximately 3.32 trillion cycles per day; roughly $1,618 per year per token; regardless of whether any transactions occur. The ICRC-ME ledger absorbs the indexing function into the ledger itself, removing this cost at the source.

The resulting canister operates at 116–118% of the Rust ICRC reference ledger's per-transfer compute cost; a margin that reflects the additional work performed on each operation (account indexing, Merkle proof maintenance, Bloom filter updates, certified tree synchronisation) which the reference ledger does not provide.

## Architecture

| Module | Purpose |
|--------|---------|
| `IndexedLedger.mo` | ICRC-1/2/3/10 actor; orchestrates all subsystems; circuit breaker for cycle drain protection |
| `BlockLog.mo` | Append-only transaction log with SHA-256 hash chain; delegates storage to StableLog and indexing to RegionIndex |
| `RegionIndex.mo` | Account transaction index stored in Region (stable memory); invisible to the garbage collector; constant cost at any account count |
| `Balances.mo` | Account balance tracking; functional state pattern over `Map` |
| `Allowances.mo` | ICRC-2 approval management with timer-based expiry pruning |
| `CertifiedTree.mo` | IC BLS-certified Merkle hash tree for trustless query verification |
| `MerkleMMR.mo` | Merkle Mountain Range; provides O(log n) inclusion proofs for any historical block |
| `BloomFilter.mo` | Time-windowed Bloom filter; eliminates 99%+ of Map lookups for transaction deduplication |
| `CBOR.mo` | CBOR encoder and decoder for ICRC-3 block serialisation; pre-allocated buffer writer to minimise GC pressure |
| `StableLog.mo` | Region-backed append-only byte log; O(1) append and random access; scales to gigabytes |
| `Archive.mo` | Overflow block storage for ledgers exceeding single-canister capacity |
| `Types.mo` | ICRC-compliant type definitions; account key serialisation for Region storage |

## Performance

Measured on a local IC replica; 30 operations per batch; cycles obtained from canister status balance differentials.

| Metric | ICRC-ME (Motoko) | Rust ICRC Reference | Ratio |
|--------|-----------------|-------------------|-------|
| Per-transfer compute | ~9.66M cycles | ~8.17M cycles | 118% |
| Per-transfer (cold start) | ~9.54M cycles | ~8.17M cycles | 116% |
| Index canister daily cost | 0 | ~3.32T cycles | — |
| Estimated annual saving | — | ~$1,618 per token | — |
| Scaling (50→550 accounts) | Flat (~11M/op) | — | — |

### Cost decomposition per transfer (measured via `performanceCounter`)

| Component | Instructions | Share |
|-----------|-------------|-------|
| Block encoding (v3 compact binary) | 311,000 | 37% |
| IC certified tree update | 265,000 | 32% |
| SHA-256 block hash | 173,000 | 21% |
| Account indexing (Region) | 11,000 | 1.3% |
| Bloom filter deduplication | 456 | <0.1% |
| Stable memory write | 4,400 | 0.5% |
| Balance operation | 6,800 | 0.8% |

## Feature Comparison

| Feature | ICRC-ME | Rust ICRC + Index |
|---------|---------|-------------------|
| ICRC-1 transfers | Yes | Yes |
| ICRC-2 approvals | Yes | Yes |
| ICRC-3 block queries | Yes | Yes |
| ICRC-10 supported standards | Yes | No |
| Account transaction index | Built-in (Region) | Separate canister |
| Merkle inclusion proofs | Yes (MMR) | No |
| Bloom filter deduplication | Yes | No |
| SHA-256 hash chain | Yes | Yes |
| IC-certified queries | Yes | Yes |
| Circuit breaker (cycle drain) | Yes | No |
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

## Circuit Breaker

The ledger includes a configurable circuit breaker that freezes all write operations when the canister's cycle balance falls below a threshold (default: 100 billion cycles). Read operations (balance queries, block queries, proofs) remain available. The canister resumes normal operation automatically when cycles are replenished. This protects the ledger's state; including the transaction log, account index, and Merkle tree; from being lost to a cycle drain attack.

```
dfx canister call <canister_id> getShieldStatus '()'
dfx canister call <canister_id> setCircuitBreakerThreshold '(200_000_000_000)'
```

## License

MIT

---

Co-authored by Engineer Jumana Nehad, Nour Ahmed, and Kareem Younes; with research assistance from ICP Hub Egypt and Mercatura Forum. We invite community feedback.
