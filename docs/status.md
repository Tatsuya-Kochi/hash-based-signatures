# プロジェクト現状分析

> 作成日: 2026-11-27
> 対象: `mylib` クレート全体
> 前提: `improvements.md` に記載された改善作業の途中経過

---

## 1. テスト実行結果（最新）

```
cargo test -p mylib
→ 57 passed; 3 failed; 0 ignored; finished in ~70s
```

### 失敗しているテスト

| テスト | 場所 | 分類 | 理由 |
|--------|------|------|------|
| `test_mpolynomial_pow` | mpolynomial.rs | BUG-4 | テスト本体のバグ（`.pow(2)` 呼び出し漏れ） |
| `test_stark_prove_verify_e2e` | stark.rs | TEST-3 | STARK verify が false を返す（FRI colinearity 失敗） |
| `test_agg_sig` | agg_sig.rs | TEST-4 | prove 内で多項式除算が余りを返しパニック |

---

## 2. 完了した作業

### BUG 修正（BUG-1〜4）

| ID | 内容 | コミット | 状態 |
|----|------|---------|------|
| BUG-1 | `right_pb` の `'0'` 分岐で `LEFT_SIGNATURE_ACC_RANGE` に誤書き込み → `RIGHT_SIGNATURE_ACC_RANGE` に修正 | `4e04deb` | ✅ 完了・テストPASS |
| BUG-2 | `2^i` が XOR 演算 → `1u128 << i` にビットシフト修正（Merkle インデックス計算） | `0cc52de` | ✅ 完了・テストPASS |
| BUG-3 | `stark::verify` で `boundary_zerofiers[s]` が境界外アクセス → `register_to_index` HashMap で compact index に変換 | `7aa0dc9` | ✅ 完了・パニック解消確認 |
| BUG-4 | `test_mpolynomial_pow` に `#[test]` 欠落 → `#[test]` 追加 | `2b1def5` | ✅ 属性追加済み（テスト本体にバグあり・別途要対応） |

### テスト有効化（TEST-1〜4）

| ID | 内容 | コミット | 状態 |
|----|------|---------|------|
| TEST-1 | `lamport_plus.rs`: `test_keygen` / `test_sign_and_verify` / `test_verify_with_trace` の `#[test]` を有効化 | `051b746` | ✅ 3テストすべてPASS |
| TEST-2 | `fri.rs`: `test_prove_and_verify_success` の `#[test]` を有効化 | `051b746` | ✅ PASS |
| TEST-3 | `stark.rs`: `test_stark_prove_verify_e2e` を新規追加 | `051b746` | ❌ 失敗（後述） |
| TEST-4 | `agg_sig.rs`: `assert!(agg_sig.verify(...))` のコメントを解除 | `051b746` | ❌ 失敗（後述） |

---

## 3. 失敗テストの詳細分析

### 3-1. `test_stark_prove_verify_e2e`（TEST-3）

**エラーメッセージ**:
```
panicked at mylib/src/stark.rs:632: STARK e2e: verify が true を返すべき
# verify 内部で以下が出力される:
Colinearity test failed for round 0
```

**構成**: 移行制約なし・境界制約のみの最小構成（trace 長 4、境界点 3 つ）

**根本原因**: `stark::verify` 内で再構成する線形結合多項式の値が、`stark::prove` でコミットした値と一致しない。結果として FRI の colinearity check が round 0 で失敗する。

**補足**:
- `test_bug3_verify_does_not_panic_with_unconstrained_registers` は `catch_unwind` で包んで `is_ok()` のみ検査しているためパスするが、verify 自体は同様に false を返している。
- 移行制約を使おうとすると別の overflow バグ（`max_degree - transition_quotient_degree_bounds` で usize アンダーフロー）が先に発生するため、今回の e2e テストでは移行制約を除外した。それでも verify が失敗するため、stark.rs verify の正確性バグは独立した問題。

**推定原因の詳細**:

| 候補 | 説明 |
|------|------|
| ① 線形結合係数の不一致 | `prove` と `verify` で Fiat-Shamir から取り出す `alpha` 等の順序・タイミングが異なる |
| ② 評価点の構成差異 | `prove` では `point = [current_poly, next_poly, m_h, m_p, m_s]`（index 0 = current）、`verify` では `[domain_index, current_trace[0], next_trace[0], ...]`（index 0 = domain point）という変数インデックスの非対称がある |
| ③ 境界商多項式の次数見積もり誤り | `boundary_quotient_degree_bounds` の計算が correct でない場合、FRI の次数境界が合わずコリニアリティ検査が通らない |

**対応方針**: 本体コードのデバッグが必要（本作業スコープ外）。`prove`/`verify` 間でのアルファ取り出し順を逐一ログ比較するか、小さなフィールド・小さなトレースで両者の中間値を照合する。

---

### 3-2. `test_agg_sig`（TEST-4）

**エラーメッセージ**:
```
panicked at mylib/src/polynomial.rs:427:
cannot perform polynomial division because remainder is not zero
```
発生箇所: `stark.prove()` 内部の境界商多項式計算

**根本原因**: `agg_sig.rs` の `verify_each_sign` が生成するトレースが `boundary_constraints()` の値条件を満たしていない。つまりトレース多項式 `trace_poly(x)` が境界条件 `trace_poly(omicron^step) = expected_value` を満たさないため、境界商多項式 `(trace_poly - boundary_interpolant) / boundary_zerofier` の除算で余りが発生する。

**補足**: BUG-3 修正前は同じテストが `boundary_zerofiers[16]` の OOB パニックで失敗していた。BUG-3 修正後はより深いところまで到達したが、今度は多項式除算で失敗する別のバグが露出した。

**推定原因**:
- `verify_each_sign` のトレース生成ロジックが実際の Rescue ハッシュ実行と一致していない可能性
- `boundary_constraints()` が期待する初期値・終端値と実トレースの対応レジスタがずれている可能性（BUG-1 と類似の範囲指定ミス）

**対応方針**: `agg_sig.rs` のトレース生成とその境界条件を照合するデバッグが必要（本作業スコープ外）。

---

## 4. 残タスク一覧（`improvements.md` より）

### 優先度高

| ID | カテゴリ | 概要 | 注意点 |
|----|---------|------|--------|
| ROB-1 | 堅牢性 | `ProofStream::pull` / `deserialize` を `Result` 返しに変更 | 公開 API 変更のため呼び出し箇所洗い出しが先 |
| ROB-2 | 堅牢性 | `stark::prove` 内 `fri.prove().unwrap()` を `?` 伝播に変更 | ROB-1 と連動して `prove` を `Result` 返しにする必要あり |
| ROB-3 | 堅牢性 | `Polynomial::leading_coefficient()` のゼロ多項式パニックを `Option` 返しに変更 | `divide` 内部で呼ばれており影響範囲が広い |
| SEC-1 | セキュリティ | 署名検証の最終比較を `subtle` クレートで定数時間化 | — |
| SEC-2 | セキュリティ | STARK セキュリティパラメータのアサーションを有効化 | 既存テストパラメータが条件を満たさない可能性あり → パラメータ修正方針を要確認 |
| MAINT-1 | 保守性 | `rand` バージョンを root (0.9.1) と mylib (0.8.3) で統一 | API 変更あり（`thread_rng()` 廃止など）→ 影響箇所の修正が必要 |

### 優先度中〜低

| ID | カテゴリ | 概要 |
|----|---------|------|
| ROB-4 | 堅牢性 | `fri::sample_indices` の `counter` を `i32` → `u64` に変更 |
| ROB-5 | 堅牢性 | `fri::sample_indices` の到達不能な 2 番目のエラー条件を削除 |
| SEC-3 | セキュリティ | `alphainv` の正しさを `debug_assert!` で検証 |
| TEST-5 | テスト | `rescue_prime::test_speed` に `#[test]` or `#[ignore]` を追加 |
| API-1 | API | `substract` のスペルミス → `subtract` に統一 |
| API-2 | API | 公開 API の `Vec<u8>` 値渡し → `&[u8]` に変更 |
| API-3 | API | `&Vec<T>` 引数 → `&[T]` に変更（Clippy ptr_arg 警告解消） |
| API-4 | API | `rescue_open_thereshold` のスペルミス修正 |
| API-5 | API | `generator()` が特定素数のみ有効な `3` を決め打ち → バリデーション追加 |
| API-6 | API | 異なる体の `FieldElement` 同士の演算を `debug_assert!` で検出 |
| MAINT-2 | 保守性 | ライブラリコードの `println!` を `log` / `tracing` に置き換え |
| MAINT-3 | 保守性 | 未使用 import による Rust コンパイル警告の解消 |

---

## 5. 既知の stark.rs 未解決バグ

BUG-1〜4 の修正スコープ外だが、`stark.rs` には以下の既知バグが残る。

### STARK-BUG-A: `max_degree` の usize アンダーフロー

**場所**: `stark::prove` の `transition_quotient_degree_bounds` 参照箇所

**問題**: `transition_quotient_degree_bounds()` は `original_trace_length`（常に 2 のべき乗）を返す。`max_degree = next_pow2(bound) - 1 = bound - 1 < bound` となるため、`max_deg - bound` が usize アンダーフローを起こす。

**影響**: 移行制約を 1 つでも含むと `stark::prove` がデバッグビルドでパニックする。

---

### STARK-BUG-B: prove/verify 間の変数インデックス非対称

**場所**: `stark::prove` と `stark::verify` の遷移制約評価部分

**問題**:
- `prove` では `point = [current_poly, next_poly, m_h, m_p, m_s]`（index 0 = current レジスタ）
- `verify` では `point = [domain_index, current_trace[0], next_trace[0], ...]`（index 0 = ドメイン点）

変数インデックスが 1 ずれており、同じ `MPolynomial` を評価しても異なる結果になる。

**影響**: STARK-BUG-A があるため移行制約はそもそも使えないが、修正後も verify が失敗する原因となる。

---

### STARK-BUG-C: 境界制約のみでも verify が失敗する

**場所**: `stark::verify` の線形結合再構成部分

**問題**: 移行制約なし・境界制約のみの最小構成でも `verify` が false を返す（TEST-3 がこれを実証）。prove と verify で Fiat-Shamir の alpha 取り出し順か線形結合の組み立て方が一致していないと考えられる。

**影響**: 現状 STARK 証明の健全性検証が実質的に機能していない。

---

## 6. モジュール別テスト通過状況

| モジュール | PASS | FAIL | 備考 |
|-----------|------|------|------|
| `modulus` | 8 | 0 | 全通過 |
| `polynomial` | 11 | 0 | 全通過 |
| `mpolynomial` | 8 | 1 | `test_mpolynomial_pow`（BUG-4：テスト本体のバグ） |
| `rescue_prime` | 5 | 0 | 全通過 |
| `merkle` | 3 | 0 | 全通過 |
| `proofstream` | 4 | 0 | 全通過 |
| `fri` | 5 | 0 | 全通過（TEST-2 有効化後） |
| `stark` | 3 | 1 | `test_stark_prove_verify_e2e`（STARK-BUG-C） |
| `lamport_plus` | 5 | 0 | 全通過（TEST-1 有効化後） |
| `agg_sig` | 0 | 1 | `test_agg_sig`（agg_sig トレース生成バグ） |
| **合計** | **57** | **3** | |

---

## 7. 次のアクション推奨順

1. **stark.rs の verify デバッグ**（STARK-BUG-C）: prove と verify の中間値を照合し、線形結合の不一致箇所を特定する。これを直さないと TEST-3 が通らず、agg_sig の検証も機能しない。

2. **agg_sig.rs のトレース生成デバッグ**（TEST-4）: `verify_each_sign` の出力トレースと `boundary_constraints()` が期待する値を照合する。stark.rs の verify が直った後でないと切り分けが難しい。

3. **ROB-1〜3**（公開 API の Result 化）: 破壊的変更のため、影響箇所の一覧を先に提示してから着手。

4. **SEC-2**（セキュリティアサーション有効化）: 既存テストパラメータが条件を満たすか確認し、満たさない場合はパラメータ変更方針を事前合意してから着手。

5. **MAINT-1**（rand バージョン統一）: rand 0.9 の API 変更に合わせた修正が必要。影響箇所確認後に着手。
