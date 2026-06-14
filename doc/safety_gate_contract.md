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
