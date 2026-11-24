# Agents: Autonomous Development Workflow for Antigravity (Sitemap Auditor)

## 1. 基本行動原則

* すべての実装は `Specification.md` と `Skills.md` に厳密に従うこと。
* **推測で仕様を省略・創作しないこと。** 不明点がある場合は実装前にユーザーへ確認すること。
* 一度に全ファイルを生成せず、以下の **Step 1 〜 Step 6 の小ステップ** で1段階ずつ実装し、各ステップ終了時に必ず `.venv\Scripts\python.exe -m pytest` を実行して全テスト通過を確認してから次へ進むこと。
* 各ステップ完了時に、変更ファイル一覧・テスト実行結果（件数とPASS/FAIL）・次ステップの予定を簡潔に報告すること。
* Git操作について: 各ステップのテスト通過後にローカルで分かりやすいコミットを作成してよいが、**`git push` および `apify push` は必ずユーザーの明示的な確認を得てから行うこと**。

## 2. 段階的実装ロードマップ

### Step 1: プロジェクト骨格・モデル・SSRF防御 (`core/models.py`, `core/ssrf.py`)

* `pyproject.toml`, `requirements.txt`, `.gitignore`, `core/__init__.py`, `core/models.py`, `core/ssrf.py` を作成。
* 完了条件: `tests/test_ssrf.py`（URL正規化、private IP / 169.254.169.254 / 非httpスキーム遮断、DNS解決モック検証）とモデルバリデーションテストが `pytest` で全通過。

### Step 2: 非同期HTTPクライアント・robots.txt・Sitemapパーサー (`core/http_client.py`, `core/robots.py`, `core/sitemap_parser.py`)

* 手動リダイレクト追跡（全ホップSSRF検証）、OOMバイト上限、プロキシ昇格フック、`protego>=0.6.2` パーサー、XML/Index/`.xml.gz`/Text/壊れたXML回復パーサーを実装。
* 完了条件: `tests/test_sitemap_parser.py` と `tests/test_robots_and_ai.py`（robots部分）がフィクスチャを用いたオフラインテストで全通過。

### Step 3: ページIndexability監査・AIボット差分・スコアリング (`core/page_auditor.py`, `core/ai_probe.py`, `core/scoring.py`)

* Canonical 5分類（`index_file_equivalent` の誤検知回避含む）、`noindex`（header/meta）、基本SEO/JSON-LD構文検証、AIボット5種差分＆`/llms.txt` 診断、0-100総合スコア＆優先修正リストを実装。
* 完了条件: `tests/test_page_auditor.py`, `tests/test_robots_and_ai.py`, `tests/test_scoring.py` が境界値ケース含め全通過。

### Step 4: オーケストレーター統合 & ローカル実疎通 (`core/runner.py`, `scripts/smoke_local.py`)

* 3モード（`extract_only`, `indexability_audit`, `full_audit`）の実行統合を `core/runner.py` に実装。
* 完了条件:
  1. モックHTTPを用いた `core` レベルの統合テストが全通過。
  2. `scripts/smoke_local.py` で公開3サイト（例：`https://www.sitemaps.org`, `https://docs.python.org`, `https://docs.perplexity.ai`）を `maxAuditPagesPerDomain=10` で実疎通実行し、Canonical分類・`llms.txt`・スコア・処理秒数が仕様通り出力されることをコンソール確認。

### Step 5: Apify Actorラッパー構築 (`apify_actor/`)

* `.actor/actor.json`, `.actor/input_schema.json`, `.actor/output_schema.json`, `Dockerfile`, `requirements.txt`, `README.md`, `apify_actor/src/main.py` を実装。
* PPE課金（`sitemap-url-extracted` / `page-indexability-audited` / `domain-audit-summary`）、二重課金防止、`event_charge_limit_reached` 安全停止、KV Store `SUMMARY` 保存、`autoEscalateProxy` 接続を実装。
* 完了条件: `tests/test_e2e_mock.py`（Apify SDKモックによる3モード・課金イベント回数・上限停止・`SUMMARY` 保存検証）およびローカル `apify run` が正常終了すること。

### Step 6: Apifyクラウド早期疎通テスト（海外AWSリージョン・512 MB検証）

* ユーザー確認後に Private 状態で `apify push` を実施（まだStore公開しない）。
* Apify Console（海外AWSリージョン・`512 MB` / `180s`・`useApifyProxy: false`）上で公開テストサイト（`https://developers.cloudflare.com`, `https://docs.python.org`, `https://docs.perplexity.ai`）を実行し、以下を実測検証する：
  1. 海外AWS IPからプロキシなしでSitemap取得・ページ監査・AIボット差分が通るか（ブロック時は `autoEscalateProxy` が機能するか）。
  2. 実行時間・メモリ使用量（512 MB以内）・プラットフォームUsage（`$0.001` 未満目標）。
  3. Default Dataset（`summary` / `url`）と Key-Value Store `SUMMARY` の出力整合性。
* 検証通過後、Pay per event + usage 設定（`apify-default-dataset-item` 削除、`Minimum for max cost per run` 空欄）、`Hide source files from Actor detail` ON、`LIMITED_PERMISSIONS` 稼働、Published Tasks 5本公開、日次ヘルスチェックSchedule登録へ進む。

## 3. 禁止事項

* `core/` 内に `apify` 依存を混ぜること。
* APIトークン（`APIFY_TOKEN` 等）や `.env` をGitへコミットすること（`.gitignore` で必ず除外）。
* テスト未実行のまま次のStepへ進むこと。