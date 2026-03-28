# Experimental Index Variants

These modules are alternative implementations of the account transaction index that were developed during the ICRC-ME design process. They are preserved here for reference. The production ledger uses `BTreeIndex.mo` + `RegionBTree.mo`.

## Modules

### RegionIndex.mo — Hash Table Index (v1)
The first index implementation. Uses a fixed-size open-addressing hash table in Region stable memory with linear probing. Each account maps to a ring buffer of the most recent transaction indices.

- **Pros**: O(1) average lookup, simple implementation
- **Cons**: Fixed bucket allocation (80MB upfront for 16M buckets), load factor degradation, no sorted iteration, ring buffer loses old transactions
- **Replaced by**: CompactIndex (for variable-length chains), then BTreeIndex

### CompactIndex.mo — Variable Block Chain Index (v2)
Replaced the fixed ring buffer with a geometric block chain per account. First block stores 8 raw Nat32 indices; overflow blocks use delta-gap varint encoding for 36x compression.

- **Pros**: No fixed allocation, grows naturally, excellent compression for sequential indices
- **Cons**: Still uses hash table for account lookup (fixed bucket overhead), no sorted iteration
- **Replaced by**: BTreeIndex (which reuses the block chain but replaces the hash table with a B-tree)

### TrieIndex.mo — Stable Trie Index (v3, abandoned)
Attempted integration with the `stable-trie` mops package for a trie-based index. Abandoned because stable-trie lacked range query and prefix scan capabilities needed for `listSubaccounts`.

- **Pros**: Potential for prefix-based queries
- **Cons**: No range queries, dependency on external package with version conflicts
- **Replaced by**: BTreeIndex

### EliasFano.mo + Succinct.mo — Compressed Bit Vectors (research)
Research implementations of Elias-Fano encoding and succinct rank/select data structures for compressing monotonically increasing transaction index sequences. Never integrated into the index pipeline.

- **Pros**: Near-optimal compression for sorted integer sequences
- **Cons**: Complex, query overhead, not worth it given delta-gap encoding already achieves good compression

### Archive.mo — Archive Canister (stub)
A standalone actor class intended to receive overflow blocks when the main ledger exceeds a threshold. Never connected to the ledger. The current design stores all blocks in the main canister's Region memory.

- **Status**: Stub only. Would need: spawning logic in IndexedLedger, block migration, archive tracking in `icrc3_get_archives`
- **Future**: Required for ledgers exceeding ~500GB of block data

## Production Index

The production ledger uses:
- **BTreeIndex.mo** — Combines B-tree lookup with block chain storage
- **RegionBTree.mo** — Region-backed B-tree with 8KB page-aligned nodes, 113-entry leaves, prefix scan
