---
title: veil init サブコマンド機能仕様書
date: 2026-07-23
target_revision: 1fff4a88bdaba28c94915ef6dbc9f2a8dfc0a883
short_hash: 1fff4a8
author: Antigravity AI Agent
status: Proposal
---

# `veil init` サブコマンド機能仕様書

## 1. 概要

本仕様書は、LLMエージェント（Antigravity, Claude Code, GitHub Copilot, Cursor 等）の実行環境に対して、`veil` による安全フィルタ（シークレット置換・プロンプトインジェクション検知・コンテキスト制限）を自動的にセットアップ・適用するための `veil init` サブコマンドの機能仕様を定義する。

---

## 2. 機能仕様一覧

| 仕様番号 | 機能名称 | 概要 |
|---|---|---|
| **SPEC-INIT-001** | CLIインターフェース＆引数仕様 | `veil init` のオプション・対話/非対話モード・ターゲット指定 |
| **SPEC-INIT-002** | SKILL.md 自動配備機能 | 各種エージェントのスキル検索ディレクトリへの `SKILL.md` コピー・配置 |
| **SPEC-INIT-003** | Agent 指示ファイル自動パッチ機能 | `CLAUDE.md`, `AGENT.md`, `GEMINI.md` 等へのマーカー付きルール挿入 |
| **SPEC-INIT-004** | Claude Code PostToolHook 自動設定機能 | `.claude/hooks/` へのツール出力マスクフックの生成・登録 |
| **SPEC-INIT-005** | 透明Shim (PATHオーバーライド) 構築機能 | `~/.llm-veil/shims/` に `cat`/`grep` ラッパーを生成しPATHを設定 |
| **SPEC-INIT-006** | 冪等性・安全制御・アンインストール | 重複防止、`--dry-run` サポート、`--uninstall` による一括復元 |

---

## 3. 仕様詳細

### SPEC-INIT-001: CLIインターフェース＆引数仕様

#### [概要]
`veil init` コマンドの構文、オプションフラグ、動作モードを定義する。

#### [構文]
```bash
veil init [OPTIONS]
```

#### [オプション一覧]
- `-g, --global`: ユーザーホーム環境（`~/.config/`, `~/.claude/` 等）へ適用。
- `-l, --local`: カレントプロジェクト環境（`.claude/`, `CLAUDE.md`, `.github/` 等）へ適用（デフォルト）。
- `-t, --target <TARGET>`: 適用対象を限定 (`all`, `skill`, `instructions`, `hooks`, `shims`)。デフォルトは `all`。
- `--dry-run`: ファイル変更を行わず、変更予定の内容と差分をプレビュー表示。
- `--force`: 既存の設定が存在する場合に強制的に再生成・上書き。
- `--uninstall`: `veil init` によって適用された変更・フック・Shimを元に戻す。

---

### SPEC-INIT-002: SKILL.md 自動配備機能

#### [概要]
各LLMエージェントが検索するスキル用ディレクトリへ `SKILL.md` を自動配置する。

#### [動作詳細]
1. 対象ディレクトリの検出と作成:
   - **Antigravity**: `~/.gemini/config/skills/llm-veil/SKILL.md` (グローバル) または `.agents/skills/llm-veil/SKILL.md` (ローカル)
   - **Claude Code**: `~/.claude/skills/llm-veil/SKILL.md` (グローバル) または `.claude/skills/llm-veil/SKILL.md` (ローカル)
   - **通用Agent**: `skills/llm-veil/SKILL.md`
2. 最新の `SKILL.md` コンテンツの書き込み。

---

### SPEC-INIT-003: Agent 指示ファイル自動パッチ機能

#### [概要]
各エージェントツールがコンテキスト起動時に自動ロードする指示ファイル (`CLAUDE.md`, `AGENT.md`, `GEMINI.md`, `.github/copilot-instructions.md`, `.cursorrules`) に対し、`veil` の使用原則ルールを安全にパッチ挿入する。

#### [マーカーブロック制御]
ファイル挿入時、以下のコメントマーカーを使用することで、手動編集部を壊さずに安全な追加・更新（冪等性）を実現する。

```markdown
<!-- BEGIN LLM-VEIL INSTRUCTIONS -->
## LLM-Veil Security Tool Guidelines
- **File Access**: Always use `veil cat <file>` instead of direct `cat`.
- **Text Search**: Always use `veil grep <pattern> [path]` instead of direct `grep`.
- **Command Execution**: Always use `veil run -- <command>` for non-interactive commands.
<!-- END LLM-VEIL INSTRUCTIONS -->
```

#### [対象ファイルと処理方針]
- `CLAUDE.md`: Claude Code 用指示ファイル。
- `AGENT.md`: 一般的なAgentic CLI/エージェント用指示ファイル。
- `GEMINI.md`: Antigravity / Gemini 関連エージェント用指示ファイル。
- `.github/copilot-instructions.md`: GitHub Copilot Workspace/CLI 用指示ファイル。
- `.cursorrules` / `.windsurfrules`: Cursor / Windsurf 用指示ファイル。

---

### SPEC-INIT-004: Claude Code PostToolHook 自動設定機能

#### [概要]
Claude Code の Hook システム（`PostToolExecution`）を利用し、ツール（Bash / View 等）の実行結果をモデルに渡す直前で `veil` のサニタイザーを通すフックスクリプトを自動生成・設定する。

#### [生成ファイルパス]
- `.claude/hooks/post_tool_execution.py`（または `.claude/hooks/post_tool_execution.sh`）

#### [スクリプト処理概要]
1. Claude Code の Tool レスポンス JSON を stdin から受信。
2. ツール名が `Bash` または `View` / `FileRead` の場合、出力テキストを `veil` 内蔵の置換・サニタイズロジックに透過パイプ。
3. `[REDACTED_SECRET]` 置換およびプロンプトインジェクション警告が付与されたレスポンス JSON を stdout に返却。
4. `.claude/settings.json` の `hooks` セクションに `post_tool_execution` のエントリを自動追加。

---

### SPEC-INIT-005: 透明Shim (PATHオーバーライド) 構築機能

#### [概要]
LLMエージェントが `SKILL.md` や指示に従わず愚直に `cat` や `grep` を実行した場合でも、OSの `PATH` 優先順位を利用して透過的に `veil` にルーティングする Shim スクリプト群を生成・設定する。

#### [ディレクトリ構造]
```
~/.llm-veil/shims/
├── cat
└── grep
```

#### [Shim スクリプト内容]
- `cat`:
  ```sh
  #!/bin/sh
  exec veil cat "$@"
  ```
- `grep`:
  ```sh
  #!/bin/sh
  exec veil grep "$@"
  ```

#### [環境変数PATH設定の提示・挿入]
- ユーザーのシェル設定ファイル (`~/.bashrc`, `~/.zshrc` 等) に対し、以下の行をパッチ挿入する（確認プロンプト付き）。
  ```sh
  export PATH="$HOME/.llm-veil/shims:$PATH"
  ```

---

### SPEC-INIT-006: 冪等性・安全制御・アンインストール

#### [冪等性 (Idempotency)]
`veil init` を何度連続で実行しても、設定ファイルや指示ファイル内に重複してルールが追記されたり、フックが多重登録されたりしない構造とする。

#### [アンインストール (`--uninstall`)]
`veil init --uninstall` が実行された場合:
1. 指示ファイル内の `<!-- BEGIN LLM-VEIL INSTRUCTIONS --> ...` マーカーブロックを削除。
2. 生成された SKILL.md および Shim ファイル (`~/.llm-veil/shims/`) を削除。
3. Claude Code フック設定を解除。
