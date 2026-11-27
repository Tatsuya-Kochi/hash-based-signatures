# 改善点一覧

> 対象: 実装済みモジュールのみ（anemoi_hash / arion_hash / threshold_sig を除く）
> 調査日: 2026-11-13

---

## 凡例

| 重要度 | 意味 |
|--------|------|
| **高** | バグ・クラッシュ・セキュリティ欠陥。現在または近い将来に問題が発生する |
| **中** | 誤動作のリスクや設計上の欠陥。放置すると将来的に問題になる |
| **低** | 保守性・可読性の問題。機能には影響しないが改善が望ましい |

---

## カテゴリ1: バグ（動作が誤っている）

### BUG-1 `right_pb` の `'0'` 分岐で `LEFT_SIGNATURE_ACC_RANGE` に誤書き込み
- **重要度**: 高
- **場所**: [lamport_plus.rs:311](../mylib/src/lamport_plus.rs#L311)
- **問題**: `right_pb` を計算する `'0'` ブランチで、トレースの書き込み先が `RIGHT_SIGNATURE_ACC_RANGE` ではなく `LEFT_SIGNATURE_ACC_RANGE` になっている。コピー＆ペースト時のミスと思われる。これにより生成トレースのレジスタ割り当てが崩れ、STARK 証明が正しく生成されない。

  ```rust
  // 現状（バグ）— lamport_plus.rs:311
  step_trace[j][Self::LEFT_SIGNATURE_ACC_RANGE].copy_from_slice(&trace[j]);
  //                   ^^^^
  // 修正後
  step_trace[j][Self::RIGHT_SIGNATURE_ACC_RANGE].copy_from_slice(&trace[j]);
  ```

---

### BUG-2 `2^i` が XOR 演算になっており累積インデックスが誤って計算される
- **重要度**: 高
- **場所**: [merkle.rs:189](../mylib/src/merkle.rs#L189)
- **問題**: Rust の `^` はビット XOR。`2^i` は「2 の i 乗」ではなく「2 XOR i」になる。例えば `i=3` のとき `2^3 == 1`（XOR）であり、期待値の `8` と異なる。`total_index` が誤った値になるため、`traces` の内容も壊れる。

  ```rust
  // 現状（バグ）— merkle.rs:189
  total_index = total_index + (little_endian[i] as u128 * ((i+1) as u128) * (2^i as u128));
  //                                                                          ^ XOR!
  // 修正後
  total_index += little_endian[i] as u128 * (i + 1) as u128 * (1u128 << i);
  ```

---

### BUG-3 `stark::verify` で `boundary_zerofiers[s]` が境界外アクセスしてパニック
- **重要度**: 高
- **場所**: [stark.rs:436-444](../mylib/src/stark.rs#L436)
- **問題**: `boundary_zerofiers()` / `boundary_interpolants()` は、境界制約のないレジスタを `continue` でスキップして詰めた `Vec` を返す（要素数 ≤ `num_registers`）。一方 `verify` ではレジスタ番号 `s`（0 以上 `num_registers` 未満）で直接インデックスするため、例えば 22 レジスタのうち一部にしか制約がない AggSig では実行時パニックが確定している。

  ```rust
  // 現状（バグ）— stark.rs:439
  for s in 0..self.num_registers {
      let zerofier = &boundary_zerofiers[s]; // ← s が Vec の長さを超えてパニック
  ```

  **修正方針**: `boundary_zerofiers` / `boundary_interpolants` の戻り値を `Vec<Polynomial>` から `HashMap<usize, Polynomial>` に変更し、`verify` 側でも `get(&s)` でアクセスする（制約のないレジスタは `None` として処理）。

---

### BUG-4 `test_mpolynomial_pow` に `#[test]` が欠落しており実行されない
- **重要度**: 中（テスト品質）
- **場所**: [mpolynomial.rs:584](../mylib/src/mpolynomial.rs#L584)
- **問題**: 多項式の冪乗テストが一切実行されておらず、リグレッションを検出できない。

  ```rust
  // 修正前
  fn test_mpolynomial_pow() { ... }
  // 修正後
  #[test]
  fn test_mpolynomial_pow() { ... }
  ```

---

## カテゴリ2: パニック / 堅牢性

### ROB-1 `ProofStream::pull` / `deserialize` が不正入力でパニック（潜在的 DoS）
- **重要度**: 高
- **場所**: [proofstream.rs:26](../mylib/src/proofstream.rs#L26), [proofstream.rs:29](../mylib/src/proofstream.rs#L29), [proofstream.rs:39](../mylib/src/proofstream.rs#L39)
- **問題**: 外部から受け取った proof バイト列を `deserialize` → `pull` する経路は、不正なデータで `expect` / `panic!` を起こす。ライブラリの公開 API がパニックするのは設計として不適切であり、特に検証者側に不正な proof を送ることで意図的にクラッシュさせられる。

  ```rust
  // 修正方針: 戻り値を Result に変更
  pub fn pull<T: for<'de> Deserialize<'de>>(&mut self) -> Result<T, bincode::Error> {
      if self.read_index >= self.objects.len() {
          return Err(/* custom error */);
      }
      let obj = bincode::deserialize(&self.objects[self.read_index])?;
      self.read_index += 1;
      Ok(obj)
  }
  ```

---

### ROB-2 `stark::prove` 内で `fri.prove(...).unwrap()` が無条件にパニック
- **重要度**: 高
- **場所**: [stark.rs:347](../mylib/src/stark.rs#L347)（要確認: 行番号は調査時点）
- **問題**: `Fri::prove` は `Result<_, String>` を返すが `.unwrap()` しているため、FRI のエラー条件でクラッシュする。
- **修正方針**: `stark::prove` の戻り値も `Result` に変更し `?` で伝播する。

---

### ROB-3 `Polynomial::leading_coefficient()` をゼロ多項式に使うとパニック
- **重要度**: 高
- **場所**: [polynomial.rs](../mylib/src/polynomial.rs)（`leading_coefficient` / `degree` 付近）
- **問題**: `degree()` はゼロ多項式に対して `-1isize` を返す。`-1isize as usize` はリリースビルドで `usize::MAX` にラップされ、`coefficients[usize::MAX]` で境界外パニックになる。`divide` 内で内部的に呼ばれており、ゼロ除算相当のパニックが起きる。

  ```rust
  // 修正後
  pub fn leading_coefficient(&self) -> Option<FieldElement> {
      let d = self.degree();
      if d < 0 { None } else { Some(self.coefficients[d as usize]) }
  }
  ```

---

### ROB-4 `fri::sample_indices` の `counter` が `i32` でオーバーフロー
- **重要度**: 中
- **場所**: [fri.rs:67](../mylib/src/fri.rs#L67)（要確認）
- **問題**: インデックス探索のカウンタが `i32` のため、探索が長引くとデバッグビルドでパニック、リリースビルドで wrap-around が起きる。
- **修正方針**: `counter` を `u64` に変更する。

---

### ROB-5 `fri::sample_indices` に到達不能な 2 番目のエラー条件（Dead Code）
- **重要度**: 低
- **場所**: [fri.rs:57-62](../mylib/src/fri.rs#L57)
- **問題**: `number > reduced_size` で Err を返した後に `number > 2 * reduced_size` を再チェックしており、後者は常に偽。コードが混乱を招く。
- **修正方針**: 2 番目の条件を削除する。

---

## カテゴリ3: セキュリティ

### SEC-1 署名検証の最終比較が非定数時間（タイミング攻撃）
- **重要度**: 高
- **場所**: [lamport_plus.rs:329](../mylib/src/lamport_plus.rs#L329), [merkle.rs:192](../mylib/src/merkle.rs#L192)
- **問題**: `FieldElement` は `#[derive(PartialEq)]` のため通常の短絡評価による比較となり、値によって処理時間が変わる。タイミング攻撃で秘密鍵の一部が漏えいする可能性がある。

  ```toml
  # Cargo.toml に追加
  subtle = "2"
  ```
  ```rust
  use subtle::ConstantTimeEq;
  let ok = acc_verify[0].value.ct_eq(&pub_acc[0].value)
      & acc_verify[1].value.ct_eq(&pub_acc[1].value);
  bool::from(ok)
  ```

---

### SEC-2 セキュリティパラメータのアサーションがコメントアウト
- **重要度**: 高
- **場所**: [stark.rs:40](../mylib/src/stark.rs#L40)
- **問題**: `num_colinearity_checks * 2 >= security_level` のチェックがコメントアウトされており、STARK の健全性パラメータが不正な値でも例外が起きない。攻撃者が意図的に小さい `colinearity_checks` を使って偽の証明を生成できる余地がある。

  ```rust
  // コメントを外す
  assert!(num_colinearity_checks * 2 >= security_level,
      "number of colinearity checks must be at least half of security level");
  ```

---

### SEC-3 `alphainv` の正しさを実行時に検証する assertion がない
- **重要度**: 低
- **場所**: [rescue_prime.rs](../mylib/src/rescue_prime.rs)（`alphainv` 定義箇所）
- **問題**: `alphainv` は `alpha * alphainv ≡ 1 (mod p−1)` を満たす値だが、コードにこの関係性の検証がない。将来パラメータを変更した際に誤りが見逃される恐れがある。

  ```rust
  debug_assert_eq!((alpha * alphainv) % (p - 1), 1,
      "alphainv must be the modular inverse of alpha mod p-1");
  ```

---

## カテゴリ4: API 設計

### API-1 `substract` のスペルミス（全モジュール共通）
- **重要度**: 低
- **場所**: [polynomial.rs:85](../mylib/src/polynomial.rs#L85), [mpolynomial.rs:40](../mylib/src/mpolynomial.rs#L40) 他
- **問題**: 正しくは `subtract`。演算子オーバーロード (`Sub`) から呼ばれているため外部への影響は限定的だが、公開メソッドとして露出している。

---

### API-2 公開 API で `Vec<u8>` を値渡しし不要なコピーを強制
- **重要度**: 中
- **場所**: [modulus.rs](../mylib/src/modulus.rs) `Field::sample`, [stark.rs](../mylib/src/stark.rs) `sample_weights`, [fri.rs](../mylib/src/fri.rs) `sample_indices`
- **問題**: 所有権移転を強制するため呼び出し側で clone が必要になるケースがある（`stark.rs` 内で実際に `randomness.clone()` している）。
- **修正方針**: 引数を `&[u8]` に変更する。

---

### API-3 `&Vec<T>` 引数（Clippy `ptr_arg` 警告）
- **重要度**: 低
- **場所**: [merkle.rs:146](../mylib/src/merkle.rs#L146), [stark.rs:108](../mylib/src/stark.rs#L108) 他多数
- **問題**: `&Vec<T>` は `&[T]` に変更すべき。スライスのほうが柔軟で Rust の慣例に合っている。

---

### API-4 `rescue_open_thereshold` のスペルミス
- **重要度**: 低
- **場所**: [merkle.rs:89](../mylib/src/merkle.rs#L89)
- **問題**: `threshold` が `thereshold` になっている公開メソッド名のタイポ。早期に修正しないと呼び出し元も修正が必要になる。

---

### API-5 `generator()` が特定の素数 `p` にのみ有効な `3` を決め打ち
- **重要度**: 中
- **場所**: [modulus.rs:30](../mylib/src/modulus.rs#L30)（要確認）
- **問題**: `generator()` は `3` を返すが、これは `p = 2¹²⁸ - 45·2⁴⁰ + 1` に対してのみ正しい原始根。`Field::new(other_prime)` で別の素数を使った場合に `primitive_nth_root` が誤った結果を返す。
- **修正方針**: `Field::new` の中で `p` のバリデーションを行うか、ドキュメントに使用可能な素数を明示する。

---

### API-6 異なる体の `FieldElement` 同士を演算してもエラーにならない
- **重要度**: 中
- **場所**: [modulus.rs](../mylib/src/modulus.rs)（`FieldElement::add` 等）
- **問題**: `self.field.p ≠ other.field.p` でも演算が黙って通り、誤った結果が返る。

  ```rust
  // add の冒頭に追加
  debug_assert_eq!(self.field.p, other.field.p, "operands belong to different fields");
  ```

---

## カテゴリ5: テスト

### TEST-1 署名スキームの中核テストがコメントアウトされている
- **重要度**: 高
- **場所**: [lamport_plus.rs:450,468,489](../mylib/src/lamport_plus.rs#L450)
- **問題**: `keygen`, `sign_and_verify`, `verify_with_trace` の各テストが `//` でコメントアウトされており、継続的インテグレーションでリグレッションを検出できない。

---

### TEST-2 FRI の prove/verify 結合テストがコメントアウト
- **重要度**: 高
- **場所**: [fri.rs:513](../mylib/src/fri.rs#L513)（`//#[test]`）
- **問題**: FRI の prove/verify を通じた end-to-end テストが実行されておらず、BUG-3 のような実行時バグが見逃される。

---

### TEST-3 STARK の prove/verify 結合テストが存在しない
- **重要度**: 高
- **場所**: [stark.rs](../mylib/src/stark.rs)
- **問題**: `test_boundary_zerofiers` / `test_boundary_interpolants` のみ存在し、`prove` と `verify` を通した end-to-end テストがない。BUG-3 はこのテストがあれば早期発見できた。

---

### TEST-4 `AggSig::verify` の呼び出しがテストでコメントアウト
- **重要度**: 高
- **場所**: [agg_sig.rs](../mylib/src/agg_sig.rs)（`test_agg_sig` の最終行）
- **問題**: `assert!(agg_sig.verify(...))` がコメントアウトされており、STARK 証明の検証が一切テストされていない。`prove` のみ実行して正しさを確認していない状態。

---

### TEST-5 `rescue_prime::test_speed` に `#[test]` が欠落
- **重要度**: 低
- **場所**: [rescue_prime.rs:487](../mylib/src/rescue_prime.rs#L487)（要確認）
- **問題**: 意図的に無効化するなら `#[ignore]` を使うべき。

---

## カテゴリ6: 保守性

### MAINT-1 `rand` のバージョンが root と mylib で不一致
- **重要度**: 高
- **場所**: [Cargo.toml](../Cargo.toml) `rand = "0.9.1"` / [mylib/Cargo.toml](../mylib/Cargo.toml) `rand = "0.8.3"`
- **問題**: rand 0.8 と 0.9 では `thread_rng()` の API が変更されている。ワークスペース内で 2 つのバージョンがリンクされ、型が合わない・挙動が異なる可能性がある。

  ```toml
  # mylib/Cargo.toml を統一
  rand = "0.9"
  ```

---

### MAINT-2 ライブラリ本番コードに多数の `println!` / `print!` が混在
- **重要度**: 低
- **場所**: [stark.rs](../mylib/src/stark.rs), [fri.rs](../mylib/src/fri.rs), [agg_sig.rs](../mylib/src/agg_sig.rs) 各所
- **問題**: ライブラリクレートの `println!` は呼び出し元がログを制御できない。本番使用時に不要な出力が発生する。
- **修正方針**: `log` または `tracing` クレートに差し替えるか、`#[cfg(debug_assertions)]` で囲む。

---

### MAINT-3 未使用 import による Rust コンパイル警告
- **重要度**: 低
- **場所**: [rescue_prime.rs:1-2](../mylib/src/rescue_prime.rs#L1) (`use core::num`, `use std::vec`), [polynomial.rs:505](../mylib/src/polynomial.rs#L505) (`use serde::de::value`) 他
- **問題**: `unused_imports` 警告が出ており、ビルドログのノイズになる。

---

## 優先度別まとめ

対処すべき優先度の目安:

| 優先度 | ID | 概要 |
|--------|-----|------|
| 1 | BUG-1 | `right_pb` の LEFT_RANGE 誤書き込み → トレース破損 |
| 2 | BUG-2 | `2^i` が XOR → Merkle インデックス誤計算 |
| 3 | BUG-3 | `boundary_zerofiers[s]` 境界外アクセスで verify が必ずパニック |
| 4 | BUG-4 | `test_mpolynomial_pow` に `#[test]` 欠落 |
| 5 | ROB-1 | `ProofStream::pull` / `deserialize` が不正入力でパニック (DoS) |
| 6 | SEC-1 | 署名比較が非定数時間（タイミング攻撃） |
| 7 | SEC-2 | セキュリティアサーションのコメントアウト |
| 8 | MAINT-1 | `rand` バージョン不一致 (0.8 vs 0.9) |
| 9 | TEST-1〜4 | Lamport+ / FRI / STARK / AggSig の結合テスト欠如 |
| 10 | ROB-2/3 | `stark::prove` / `leading_coefficient` のパニック |
