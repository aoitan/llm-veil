---
title: セキュリティ情報マスク機能コードレビュー報告書
date: 2026-07-23
target_revision: 1fff4a88bdaba28c94915ef6dbc9f2a8dfc0a883
short_hash: 1fff4a8
reviewer: Antigravity AI Agent
status: Reviewed
---

# セキュリティ情報マスク機能 コードレビュー報告書

## 概要

`llm-veil` における「LLMからファイルを読み出す・コマンドを実行する際のセキュリティ情報のマスク機能」を中心にコードの全般レビューを行いました。

全体として、PathGuard・Redactor・Injector・Truncator・Untrusted Wrapper による多層防御アーキテクチャが美しく設計されており、一般的なシークレットや危険パスのブロック・マスクは非常に高いレベルで実装されています。

しかし、特定のAPIトークン単体での出現や、一部のパス置換正規表現、サブコマンド間の仕様差異において、いくつかの検知漏洩リスクやバイパス経路となり得る箇所が確認されました。

---

## 1. 高く評価できる実装

### 1.1 多層防御アーキテクチャ
- 単一のパターンマッチだけでなく、パスチェック・シークレット置換・プロンプトインジェクション検知・文字数制限・非信頼宣言ラッピングが順序立てて実行されています。

### 1.2 全最終出力に対する一括マスク適用 (`final_output_filter`)
- [src/main.rs](file:///Users/aoitan/workspace/token_filter/repo/src/main.rs#L36-L44)
- ファイル内容だけでなく、エラーメッセージ・`veil report` 出力・`eprintln` デバッグ出力に至るまで最終段で `final_output_filter` を適用しており、ログ出力経由での二次漏洩が防がれています。

### 1.3 Base64エンコード済みシークレットの検出とマスク
- [src/redactor.rs](file:///Users/aoitan/workspace/token_filter/repo/src/redactor.rs#L110-L133)
- デコード処理を行い、内部にシークレットパターンやキーワードが含まれる場合、Base64文字列自体を `[REDACTED_SECRET]` に置換する先進的な保護機能が組み込まれています。

### 1.4 PathGuardによる堅牢なパス検証
- [src/path_guard.rs](file:///Users/aoitan/workspace/token_filter/repo/src/path_guard.rs#L85-L95)
- パストラバーサル (`../`)、Windowsパス区切り (`\`)、標準化 (`canonicalize`) によるシンボリックリンク参照先の危険パス判定が網羅されています。

---

## 2. セキュリティリスク・検知漏れ項目 (指摘事項)

### 2.1 固有プレフィックス型 API キー / トークンの単体検知漏れ
- **対象ファイル**: [src/redactor.rs](file:///Users/aoitan/workspace/token_filter/repo/src/redactor.rs#L23-L89)
- **問題点**:
  現在の正規表現ルールは `password = ...` や `api_key: ...` など**変数名・キー名を伴うパターン**が中心となっています。そのため、以下のような有名サービスの固有プレフィックス型トークンが単体（例: ログ中や環境変数 `HEADER="ghp_xxx"` 内）で出現した場合に置換されません。
- **影響を受ける主なトークン**:
  - GitHub PAT / Token: `ghp_[A-Za-z0-9_]{36}`, `github_pat_[A-Za-z0-9_]{82}`
  - OpenAI API Key: `sk-[A-Za-z0-9]{32,}`, `sk-proj-[A-Za-z0-9_-]+`
  - Anthropic API Key: `sk-ant-[A-Za-z0-9_-]+`
  - Google API Key: `AIzaSy[A-Za-z0-9_-]{33}`（キー名が `api_key` でない場合漏れる）
  - Slack Token: `xox[baprs]-[A-Za-z0-9_-]+`
  - Stripe API Key: `sk_live_[A-Za-z0-9]+`
  - JWT Token: `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]+`
- **推奨対策**: `rules` および `detect_set` に固有プレフィックスの検出ルールを追加する。

### 2.2 Linux/macOS ユーザー名のドット (`.`) パス置換漏れ
- **対象ファイル**: [src/redactor.rs](file:///Users/aoitan/workspace/token_filter/repo/src/redactor.rs#L62)
- **問題点**:
  ```rust
  Regex::new(r"/(Users|home)/[a-zA-Z0-9_-]+").unwrap(),
  ```
  正規表現クラスにドット `.` が含まれていないため、`/Users/john.doe/project/main.rs` のようなドット入りユーザー名の場合、`/Users/john` のみがマッチし、`[REDACTED_PATH].doe/project/main.rs` のようにユーザー名の一部が残存します。
  (※ Windows側のルール [src/redactor.rs:L66](file:///Users/aoitan/workspace/token_filter/repo/src/redactor.rs#L66) には `.` が含まれています)
- **推奨対策**: `r"/(Users|home)/[a-zA-Z0-9_.-]+"` に変更する。

### 2.3 `veil grep` でのワークスペース境界チェック (`is_inside_workspace`) の欠落
- **対象ファイル**: [src/main.rs](file:///Users/aoitan/workspace/token_filter/repo/src/main.rs#L347-L380)
- **問題点**:
  `handle_cat` には [is_inside_workspace](file:///Users/aoitan/workspace/token_filter/repo/src/main.rs#L191) によるアクセス制限が実装されていますが、`handle_grep` には同等の境界チェックがありません。
  そのため、`veil grep "pattern" /etc/passwd` や `veil grep "key" ~/.ssh/config` などのコマンドでワークスペース外の任意の絶対パスを指定してファイルを探索・内容取得できてしまうバイパス経路が存在します。
- **推奨対策**: `handle_grep` の開始時点でも対象パスに対して `is_inside_workspace` または安全チェックを追加する。

### 2.4 Authorization ヘッダーでの Bearer 以外の検出
- **対象ファイル**: [src/redactor.rs](file:///Users/aoitan/workspace/token_filter/repo/src/redactor.rs#L41)
- **問題点**:
  `Authorization: Bearer <token>` のみが対象となっており、`Authorization: Basic <base64>` や `Authorization: Token <token>` などが対象外となっています。
- **推奨対策**: `(?i)(authorization\s*:\s*(?:bearer|basic|token)\s+)([^\s'"\r\n]+)` に拡張する。

---

## 3. 結論と推奨アクション

1. `src/redactor.rs` の正規表現ルール（ユーザー名ドット対応、各社APIキープレフィックス追加、Authorization拡大）の追加・修正。
2. `src/main.rs` の `handle_grep` への `is_inside_workspace` 境界チェック追加。
3. 修正に対するテストケースの追加 (TDDフローに準拠)。
