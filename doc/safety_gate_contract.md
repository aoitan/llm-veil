# Safety Gate Contract (仕様契約書)

このドキュメントは、`llm-veil` が安全ゲートとして満たすべき各サブコマンド（`cat`, `grep`, `run`, `report`）の出力および振る舞いに関する仕様契約（Contract）を定義します。
評価プロセス（Evaluation）では、本契約に記述された期待値と実測値の完全な一致をもって PASS と判定します。

## 1. 期待仕様マトリクス

| コマンド/ケース | blocked | reason | path_rule | stdout 形式 | stderr 形式 | exit_code | redactions | leakage allowed |
|---|---|---|---|---|---|---|---|---|
| **`cat` 通常ファイル** | `false` | (empty) | (empty) | ファイル内容 + 末尾に untrusted 宣言 | (empty) | `0` | `0` | `false` |
| **`cat` 危険パス** | `true` | `path_blocked` | マッチした規則名 (例: `*.pem`) | 構造化テキスト（※1） | エラーメッセージ | `1` | `0` | `false` |
| **`cat` シークレット検出** | `true` | `secret_detected` | (empty) | 構造化テキスト（※1） | エラーメッセージ | `1` | 検出した置換数 | `false` |
| **`cat` プロンプトインジェクション検出** | `true` | `prompt_injection_detected` | (empty) | 構造化テキスト（※1） | 統計レポート | `1` | 検出した置換数 | `false` |
| **`cat` 巨大ファイル** | `false` | (empty) | (empty) | 制限サイズまでの内容 + `[TRUNCATED: omitted ...]` + untrusted 宣言 | (empty) | `0` | `0` | `false` |
| **`grep` 通常ファイル** | `false` | (empty) | (empty) | パスマスクされた検索結果行 | (empty) | `0` (or `1` if no match) | `0` | `false` |
| **`grep` シークレット検出** | `false` | (empty) | (empty) | シークレットが `[REDACTED_SECRET]` に置換された検索結果行 | (empty) | `0` | `>0` (置換数) | `false` |
| **`run` シークレット出力** | `false` | (empty) | (empty) | シークレットが `[REDACTED_SECRET]` に置換されたコマンド標準出力 | コマンド標準エラー (シークレットは置換) | コマンドの終了コード | `>0` (置換数) | `false` |
| **`report`** | `false` | (empty) | (empty) | 統計レポート（※2） | (empty) | `0` | (N/A) | `false` |

---

## 2. 出力フォーマット仕様

### ※1: `cat` ブロック時の構造化テキスト形式
ブロックされた場合、以下のフォーマットの構造化テキストを出力し、さらに全体が `untrusted` 宣言でラップされます。
```text
blocked: true
reason: <reason>
path_rule: <path_rule_pattern_or_empty>
redactions: <count>
exit_code: 1
```

### ※2: `report` 出力形式
```text
command: <command>
exit_code: <exit_code>
raw_bytes: <raw_bytes>
returned_bytes: <returned_bytes>
reduction: <reduction_percentage>%
redactions: <redactions_count>
prompt_injection_warnings: <warnings_count>
truncated: <true_or_false>
timeout: <true_or_false>
```

---

## 3. 回避ルールおよび制約
- **例外**: パスブロック時はファイルの読み込み処理自体が拒否されるため、`redactions` は必ず `0` となります。
- **優先順位**: パスブロック判定はコンテンツスキャン（シークレット検出）よりも前に実行されます。したがって、危険パス上のファイル内にシークレットが含まれていても、`reason` は `path_blocked` となり、`path_rule` にマッチした規則が設定されなければなりません。プロンプトインジェクション検出は、シークレット検出後に redactor 済み本文へ適用されます。

---

## 4. Coverage Contract (網羅性契約)

本契約は、安全ゲートがカバーしている漏洩面の網羅性と、それぞれの検証状態を明示します。
「実装が存在する」ことと「実測検証（fixture等のテストがあること）」を区別し、実測されたもののみを `verified` とします。

### 4.1 検証ステータス定義
- **`verified`**: 実測可能なテスト（fixture等）が存在し、漏洩がないことが確認されている状態。
- **`untested`**: 契約上重要だが、まだ自動検証ケースとして固定されていない状態。
- **`limited`**: 検知パターンは存在するが、一部の条件（巨大ファイルやエスケープされた入力等）において未検証、または制限がある状態。
- **`out_of_scope`**: 設計上、本安全ゲートの検知・保護対象外とする状態。

### 4.2 Coverage Matrix
安全ゲートの網羅性マトリクスは `doc/contract_coverage_matrix.json` で管理します。
`scripts/verify_contract.py` は以下を検証します。

- 実測されたケースがすべて coverage matrix に存在すること。
- `verified` とされたケースが実測結果に存在すること。
- matrix 上の `expected_exit_code` と実測終了コードが一致すること。
- `required` かつ `untested` のケースを `Coverage completeness: PARTIAL` として出力に残すこと。

通常の契約検証は、既存の contract assertions が満たされれば成功します。
未検証ケースも失敗にしたい場合は `scripts/verify_contract.py --strict-coverage` を使用します。
