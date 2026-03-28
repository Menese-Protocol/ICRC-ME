/// CBOR.mo — CBOR encoder + decoder for ICRC-3 block encoding
///
/// Implements the subset of CBOR needed for IC hash trees and ICRC-3 blocks:
///   - Unsigned integers (major type 0)
///   - Negative integers (major type 1)
///   - Byte strings (major type 2)
///   - Text strings (major type 3)
///   - Arrays (major type 4)
///   - Maps (major type 5)
///   - Tag 55799 (self-describe CBOR — required by ICRC-3)
///
/// Matches the encoding used by the Rust `ciborium` crate in the DFINITY ledger.

import Nat "mo:core/Nat";
import Nat8 "mo:core/Nat8";
import Nat64 "mo:core/Nat64";
import Int "mo:core/Int";
import Blob "mo:core/Blob";
import Text "mo:core/Text";
import Array "mo:core/Array";
import VarArray "mo:core/VarArray";
import List "mo:core/List";
import Principal "mo:core/Principal";

module {

  // ═══════════════════════════════════════════════════════
  //  CBOR WRITER (append-only byte buffer)
  // ═══════════════════════════════════════════════════════

  /// CBOR Writer — Pre-allocated byte buffer for minimal GC pressure.
  /// Typical ICRC blocks encode to 80-250 bytes.
  public class Writer() {
    var buf : [var Nat8] = VarArray.repeat<Nat8>(0, 256);
    var len : Nat = 0;

    func grow() {
      let newSize = buf.size() * 2;
      let newBuf = VarArray.repeat<Nat8>(0, newSize);
      var i = 0;
      while (i < len) { newBuf[i] := buf[i]; i += 1 };
      buf := newBuf;
    };

    public func writeByte(b : Nat8) {
      if (len >= buf.size()) grow();
      buf[len] := b;
      len += 1;
    };

    public func writeBytes(bs : [Nat8]) {
      for (b in bs.vals()) { writeByte(b) };
    };

    public func writeBlob(b : Blob) {
      for (byte in b.vals()) { writeByte(byte) };
    };

    public func toBytes() : [Nat8] { Array.tabulate<Nat8>(len, func(i) { buf[i] }) };
    public func toBlob() : Blob { Blob.fromArray(Array.tabulate<Nat8>(len, func(i) { buf[i] })) };
  };

  // ═══════════════════════════════════════════════════════
  //  CBOR ENCODING PRIMITIVES
  // ═══════════════════════════════════════════════════════

  /// Encode CBOR header: major type (3 bits) + argument
  func encodeHead(w : Writer, majorType : Nat8, arg : Nat) {
    let mt = majorType * 32; // shift left 5 bits
    if (arg < 24) {
      w.writeByte(mt + Nat8.fromNat(arg));
    } else if (arg < 256) {
      w.writeByte(mt + 24);
      w.writeByte(Nat8.fromNat(arg));
    } else if (arg < 65536) {
      w.writeByte(mt + 25);
      w.writeByte(Nat8.fromNat(arg / 256));
      w.writeByte(Nat8.fromNat(arg % 256));
    } else if (arg < 4294967296) {
      w.writeByte(mt + 26);
      w.writeByte(Nat8.fromNat((arg / 16777216) % 256));
      w.writeByte(Nat8.fromNat((arg / 65536) % 256));
      w.writeByte(Nat8.fromNat((arg / 256) % 256));
      w.writeByte(Nat8.fromNat(arg % 256));
    } else {
      w.writeByte(mt + 27);
      let bytes = Array.tabulate<Nat8>(8, func(i) {
        let shift = 7 - i;
        let divisor = 256 ** shift;
        let byte = (arg / divisor) % 256;
        Nat8.fromNat(byte)
      });
      w.writeBytes(bytes);
    };
  };

  /// Encode unsigned integer (major type 0)
  public func encodeNat(w : Writer, n : Nat) {
    encodeHead(w, 0, n);
  };

  /// Encode signed integer (major type 0 or 1)
  public func encodeInt(w : Writer, n : Int) {
    if (n >= 0) {
      encodeHead(w, 0, Int.abs(n));
    } else {
      encodeHead(w, 1, Int.abs(n) - 1);
    };
  };

  /// Encode byte string (major type 2)
  public func encodeBytes(w : Writer, b : Blob) {
    encodeHead(w, 2, b.size());
    w.writeBlob(b);
  };

  /// Encode text string (major type 3)
  public func encodeText(w : Writer, t : Text) {
    let b = Text.encodeUtf8(t);
    encodeHead(w, 3, b.size());
    w.writeBlob(b);
  };

  /// Encode array header (major type 4)
  public func encodeArrayHeader(w : Writer, length : Nat) {
    encodeHead(w, 4, length);
  };

  /// Encode map header (major type 5)
  public func encodeMapHeader(w : Writer, length : Nat) {
    encodeHead(w, 5, length);
  };

  /// Encode CBOR tag
  public func encodeTag(w : Writer, tag : Nat) {
    encodeHead(w, 6, tag);
  };

  // ═══════════════════════════════════════════════════════
  //  CBOR READER (cursor-based byte stream decoder)
  // ═══════════════════════════════════════════════════════

  public class Reader(data : [Nat8]) {
    var pos : Nat = 0;

    public func remaining() : Nat {
      if (pos >= data.size()) 0 else data.size() - pos;
    };

    public func readByte() : ?Nat8 {
      if (pos >= data.size()) return null;
      let b = data[pos];
      pos += 1;
      ?b
    };

    public func readBytes(n : Nat) : ?[Nat8] {
      if (pos + n > data.size()) return null;
      let result = Array.tabulate<Nat8>(n, func(i) { data[pos + i] });
      pos += n;
      ?result
    };

    /// Decode CBOR header → (major type, argument value)
    public func decodeHead() : ?(Nat8, Nat) {
      switch (readByte()) {
        case null null;
        case (?b) {
          let majorType = b / 32;
          let additional = Nat8.toNat(b % 32);
          if (additional < 24) {
            ?(majorType, additional)
          } else if (additional == 24) {
            switch (readByte()) {
              case null null;
              case (?v) ?(majorType, Nat8.toNat(v));
            };
          } else if (additional == 25) {
            switch (readBytes(2)) {
              case null null;
              case (?bs) ?(majorType, Nat8.toNat(bs[0]) * 256 + Nat8.toNat(bs[1]));
            };
          } else if (additional == 26) {
            switch (readBytes(4)) {
              case null null;
              case (?bs) {
                ?(majorType,
                  Nat8.toNat(bs[0]) * 16777216 +
                  Nat8.toNat(bs[1]) * 65536 +
                  Nat8.toNat(bs[2]) * 256 +
                  Nat8.toNat(bs[3]))
              };
            };
          } else if (additional == 27) {
            switch (readBytes(8)) {
              case null null;
              case (?bs) {
                var v : Nat = 0;
                for (i in bs.keys()) {
                  v := v * 256 + Nat8.toNat(bs[i]);
                };
                ?(majorType, v)
              };
            };
          } else { null }; // indefinite/reserved — not supported
        };
      };
    };

    /// Decode unsigned integer
    public func decodeNat() : ?Nat {
      switch (decodeHead()) {
        case (?(0, n)) ?n;
        case _ null;
      };
    };

    /// Decode text string
    public func decodeText() : ?Text {
      switch (decodeHead()) {
        case (?(3, len)) {
          switch (readBytes(len)) {
            case null null;
            case (?bs) Text.decodeUtf8(Blob.fromArray(bs));
          };
        };
        case _ null;
      };
    };

    /// Decode byte string
    public func decodeBytes() : ?Blob {
      switch (decodeHead()) {
        case (?(2, len)) {
          switch (readBytes(len)) {
            case null null;
            case (?bs) ?Blob.fromArray(bs);
          };
        };
        case _ null;
      };
    };

    /// Decode map header → number of entries
    public func decodeMapHeader() : ?Nat {
      switch (decodeHead()) {
        case (?(5, n)) ?n;
        case _ null;
      };
    };

    /// Skip a tag (e.g., 55799) and return the tag value
    public func decodeTag() : ?Nat {
      switch (decodeHead()) {
        case (?(6, t)) ?t;
        case _ null;
      };
    };

    /// Peek at next byte without consuming
    public func peek() : ?Nat8 {
      if (pos >= data.size()) null else ?data[pos];
    };

    let MAX_DEPTH : Nat = 128; // prevents stack overflow from malicious nesting

    /// Skip any CBOR value (recursive, depth-limited)
    public func skipValue() : Bool { skipValueDepth(0) };

    func skipValueDepth(depth : Nat) : Bool {
      if (depth > MAX_DEPTH) return false;
      switch (decodeHead()) {
        case null false;
        case (?(mt, arg)) {
          if (mt == 0 or mt == 1) { true }
          else if (mt == 2 or mt == 3) {
            switch (readBytes(arg)) { case null false; case _ true };
          } else if (mt == 4) {
            var i = 0;
            while (i < arg) {
              if (not skipValueDepth(depth + 1)) return false;
              i += 1;
            };
            true
          } else if (mt == 5) {
            var i = 0;
            while (i < arg) {
              if (not skipValueDepth(depth + 1)) return false;
              if (not skipValueDepth(depth + 1)) return false;
              i += 1;
            };
            true
          } else if (mt == 6) { skipValueDepth(depth + 1) }
          else { false };
        };
      };
    };
  };

  // ═══════════════════════════════════════════════════════
  //  ICRC-3 VALUE ENCODING
  // ═══════════════════════════════════════════════════════

  /// The ICRC-3 Value type
  public type Value = {
    #Nat : Nat;
    #Int : Int;
    #Text : Text;
    #Blob : Blob;
    #Array : [Value];
    #Map : [(Text, Value)];
  };

  /// Encode an ICRC-3 Value as CBOR with self-describe tag 55799
  public func encodeValue(v : Value) : Blob {
    let w = Writer();
    encodeTag(w, 55799);
    encodeValueInner(w, v);
    w.toBlob()
  };

  /// Encode Value without the self-describe tag (for nested values)
  public func encodeValueRaw(v : Value) : Blob {
    let w = Writer();
    encodeValueInner(w, v);
    w.toBlob()
  };

  func encodeValueInner(w : Writer, v : Value) {
    switch (v) {
      case (#Nat(n)) { encodeNat(w, n) };
      case (#Int(n)) { encodeInt(w, n) };
      case (#Text(t)) { encodeText(w, t) };
      case (#Blob(b)) { encodeBytes(w, b) };
      case (#Array(arr)) {
        encodeArrayHeader(w, arr.size());
        for (elem in arr.vals()) { encodeValueInner(w, elem) };
      };
      case (#Map(entries)) {
        encodeMapHeader(w, entries.size());
        for ((key, val) in entries.vals()) {
          encodeText(w, key);
          encodeValueInner(w, val);
        };
      };
    };
  };

  // ═══════════════════════════════════════════════════════
  //  BLOCK ENCODING/DECODING (v2 — full fidelity CBOR)
  // ═══════════════════════════════════════════════════════

  public type Account = { owner : Principal; subaccount : ?Blob };

  public type BlockTx = {
    kind : Text;
    from : ?Account;
    to : ?Account;
    spender : ?Account;
    amount : Nat;
    fee : ?Nat;
    memo : ?Blob;
    parentHash : ?Blob;
    timestamp : Nat64;
    index : Nat;
  };

  /// Encode a transaction as v2 CBOR block.
  /// Format: [0x02 version byte][CBOR map]
  /// CBOR map keys: "k"=kind, "ts"=timestamp, "a"=amount, "f"=from, "t"=to,
  ///   "s"=spender, "fe"=fee, "m"=memo, "ph"=parentHash
  /// Account encoding: CBOR map {"o"=owner_blob, "s"=subaccount_blob}
  public func encodeBlockV2(tx : BlockTx, effectiveFee : ?Nat) : Blob {
    let w = Writer();
    w.writeByte(0x02); // version marker

    // Count map fields
    var count : Nat = 3; // kind, timestamp, amount always present
    switch (tx.from) { case (?_) count += 1; case null {} };
    switch (tx.to) { case (?_) count += 1; case null {} };
    switch (tx.spender) { case (?_) count += 1; case null {} };
    switch (effectiveFee) { case (?_) count += 1; case null {} };
    switch (tx.memo) { case (?_) count += 1; case null {} };
    switch (tx.parentHash) { case (?_) count += 1; case null {} };

    encodeMapHeader(w, count);

    // kind
    encodeText(w, "k");
    encodeText(w, tx.kind);

    // timestamp (as Nat)
    encodeText(w, "ts");
    encodeNat(w, Nat64.toNat(tx.timestamp));

    // amount
    encodeText(w, "a");
    encodeNat(w, tx.amount);

    // from
    switch (tx.from) {
      case (?acc) { encodeText(w, "f"); encodeAccount(w, acc) };
      case null {};
    };

    // to
    switch (tx.to) {
      case (?acc) { encodeText(w, "t"); encodeAccount(w, acc) };
      case null {};
    };

    // spender
    switch (tx.spender) {
      case (?acc) { encodeText(w, "s"); encodeAccount(w, acc) };
      case null {};
    };

    // fee
    switch (effectiveFee) {
      case (?f) { encodeText(w, "fe"); encodeNat(w, f) };
      case null {};
    };

    // memo
    switch (tx.memo) {
      case (?m) { encodeText(w, "m"); encodeBytes(w, m) };
      case null {};
    };

    // parentHash (chain linkage)
    switch (tx.parentHash) {
      case (?h) { encodeText(w, "ph"); encodeBytes(w, h) };
      case null {};
    };

    w.toBlob()
  };

  func encodeAccount(w : Writer, acc : Account) {
    let hasSubaccount = switch (acc.subaccount) { case (?_) true; case null false };
    encodeMapHeader(w, if (hasSubaccount) 2 else 1);
    encodeText(w, "o");
    encodeBytes(w, Principal.toBlob(acc.owner));
    switch (acc.subaccount) {
      case (?s) { encodeText(w, "s"); encodeBytes(w, s) };
      case null {};
    };
  };

  /// Decode a v2 CBOR block (assumes version byte already consumed).
  public func decodeBlockV2(data : [Nat8], idx : Nat) : ?BlockTx {
    let r = Reader(data);

    switch (r.decodeMapHeader()) {
      case null return null;
      case (?mapLen) {
        var kind : Text = "";
        var timestamp : Nat64 = 0;
        var amount : Nat = 0;
        var from : ?Account = null;
        var to : ?Account = null;
        var spender : ?Account = null;
        var fee : ?Nat = null;
        var memo : ?Blob = null;
        var parentHash : ?Blob = null;

        var i = 0;
        while (i < mapLen) {
          switch (r.decodeText()) {
            case null return null;
            case (?key) {
              if (key == "k") {
                switch (r.decodeText()) { case (?v) kind := v; case null return null };
              } else if (key == "ts") {
                switch (r.decodeNat()) { case (?v) timestamp := Nat64.fromNat(v); case null return null };
              } else if (key == "a") {
                switch (r.decodeNat()) { case (?v) amount := v; case null return null };
              } else if (key == "f") {
                switch (decodeAccount(r)) { case (?v) from := ?v; case null return null };
              } else if (key == "t") {
                switch (decodeAccount(r)) { case (?v) to := ?v; case null return null };
              } else if (key == "s") {
                switch (decodeAccount(r)) { case (?v) spender := ?v; case null return null };
              } else if (key == "fe") {
                switch (r.decodeNat()) { case (?v) fee := ?v; case null return null };
              } else if (key == "m") {
                switch (r.decodeBytes()) { case (?v) memo := ?v; case null return null };
              } else if (key == "ph") {
                switch (r.decodeBytes()) { case (?v) parentHash := ?v; case null return null };
              } else {
                if (not r.skipValue()) return null;
              };
            };
          };
          i += 1;
        };

        ?{ kind; from; to; spender; amount; fee; memo; parentHash; timestamp; index = idx }
      };
    };
  };

  func decodeAccount(r : Reader) : ?Account {
    switch (r.decodeMapHeader()) {
      case null null;
      case (?mapLen) {
        var owner : ?Principal = null;
        var subaccount : ?Blob = null;
        var i = 0;
        while (i < mapLen) {
          switch (r.decodeText()) {
            case null return null;
            case (?key) {
              if (key == "o") {
                switch (r.decodeBytes()) {
                  case (?b) owner := ?Principal.fromBlob(b);
                  case null return null;
                };
              } else if (key == "s") {
                switch (r.decodeBytes()) {
                  case (?b) subaccount := ?b;
                  case null return null;
                };
              } else {
                if (not r.skipValue()) return null;
              };
            };
          };
          i += 1;
        };
        switch (owner) {
          case (?o) ?{ owner = o; subaccount };
          case null null;
        };
      };
    };
  };
};
