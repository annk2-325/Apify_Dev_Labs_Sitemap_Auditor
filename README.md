# Sitemap Extractor & Indexability Auditor (Fast, No Proxy, Broken Links & AI Bots)

軽量 HTTP（プロキシ不要・512 MB 運用）で XML / 入れ子 Index / `.xml.gz` / プレーンテキスト / 壊れた XML Sitemap を高速抽出し、HTTP ステータス・リダイレクト連鎖・`robots.txt` 競合・`noindex`・`canonical` 5分類・基本 SEO/JSON-LD・主要 AI 検索ボット 5 種（`OAI-SearchBot`, `GPTBot`, `ClaudeBot`, `Claude-SearchBot`, `PerplexityBot`）差分到達性・`/llms.txt` 診断・0〜100 総合スコアを一括出力するプロジェクトです。

> **現在の開発状態:** **Step 6 / 6 完了（全ステップ完了）** — テスト **288 件全通過**・Apify クラウド（海外 AWS・512 MB・`LIMITED_PERMISSIONS`・Private）実測検証 `SUCCEEDED`（7.39s / 最大メモリ 67.19 MB / 0.00103 CU / Proxy 0 GB）

## 設計原則

- **Apify 非依存のコア設計:** コアロジックは `core/` パッケージとして純粋 Python（`httpx[http2]`, `lxml`, `protego>=0.6.2`, `pydantic>=2.0`）のみで実装し、`apify` SDK を一切 `import` しません。
- **薄いアダプター層:** `apify_actor/` は `core/` を呼び出して Dataset / Key-Value Store へ出力し、Pay-per-event 課金を行う薄いラッパーに徹します。
- **オフライン単体テスト徹底:** 各ステップごとに `.venv\Scripts\python.exe -m pytest` の全テスト通過を確認してから次ステップへ進みます。

---

## V1.0 開発進捗ロードマップ

**進捗: 6 / 6 ステップ完了（テスト 288 件全通過・Apify クラウド早期疎通 `SUCCEEDED`）**

| Step | 内容 | ステータス | 主な成果物 |
|---|---|---|---|
| **Step 1** | プロジェクト骨格・モデル・SSRF防御 | ✅ 完了 | `pyproject.toml`, `requirements.txt`, `.gitignore`, `core/__init__.py`, `core/models.py`, `core/ssrf.py`, `tests/test_ssrf.py`, `tests/test_models.py` |
| **Step 2** | 非同期HTTPクライアント・robots.txt・Sitemapパーサー | ✅ 完了 | `core/http_client.py`, `core/robots.py`, `core/sitemap_parser.py`, `tests/fixtures/*`, `tests/test_sitemap_parser.py`, `tests/test_robots_and_ai.py` |
| **Step 3** | ページIndexability監査・AIボット差分・スコアリング | ✅ 完了 | `core/page_auditor.py`, `core/ai_probe.py`, `core/scoring.py`, `tests/fixtures/*`, `tests/test_page_auditor.py`, `tests/test_robots_and_ai.py`, `tests/test_scoring.py` |
| **Step 4** | オーケストレーター統合 & ローカル実疎通 | ✅ 完了 | `core/runner.py`, `scripts/smoke_local.py`, `tests/test_runner_integration.py`, 公開 3 サイト実疎通（7.15s / Proxy なし） |
| **Step 5** | Apify Actor ラッパー構築 & モックE2E・ローカル `apify run` | ✅ 完了 | `.dockerignore`, `apify_actor/.actor/*`, `apify_actor/Dockerfile`, `apify_actor/requirements.txt`, `apify_actor/README.md`, `apify_actor/src/main.py`, `tests/test_e2e_mock.py` |
| **Step 6** | Apify クラウド早期疎通テスト（海外AWS・512 MB検証） | ✅ 完了 | Private `apify push`（Build `0.1.1`）・クラウド 3 サイト実測 `SUCCEEDED`（7.39s / 最大メモリ 67.19 MB / 0.00103 CU / Proxy 0 GB / Dataset 720件・KVS `SUMMARY` 整合） |

### マイルストーン詳細

- [x] **Step 1:** 仮想環境（Python 3.11.1 `.venv`）および依存設定（`pyproject.toml`, `requirements.txt`）を整備。RFC 3986 URL 正規化・非 `http/https` スキーム遮断・プライベート IP / ループバック / AWS メタデータ（`169.254.169.254`）/ 難読化数値 IP / 全 DNS 解決 IP グローバル検証（`core/ssrf.py`）、および Pydantic v2 入出力・監査結果・サマリーモデル（`core/models.py`）を実装し、オフライン単体テスト 161 件の全通過を確認。
- [x] **Step 2:** `httpx.AsyncClient(follow_redirects=False)` 手動リダイレクト追跡（最大10ホップ・ループ検知・全ホップ SSRF 検証）・OOM ストリーミング上限・段階的プロキシ昇格（`core/http_client.py`）、`protego>=0.6.2` による RFC 9309 準拠 `robots.txt` 解析（`core/robots.py`）、XXE 遮断・壊れた XML 回復・マジックバイト `.xml.gz`（30 MB 展開上限）・プレーンテキスト・入れ子 Index 再帰（最大深度 5 / 循環防止）・重複/他ホスト/5万件超過/lastmod 検証パーサー（`core/sitemap_parser.py`）を実装し、計 217 件の全通過を確認。
- [x] **Step 3:** Canonical 5分類（`index_file_equivalent` の誤検知回避含む）・`noindex`（`X-Robots-Tag` ヘッダー / `meta robots|googlebot`）・`full_audit` 基本 SEO（`title`, `meta description`, `h1`, 本文 200 文字未満 `SSR_THIN_CONTENT`）および JSON-LD 構文検証（`core/page_auditor.py`）、主要 AI 検索ボット 5 種差分到達性（`cdn_or_waf_diff_block`）＆ HTML 誤認防止付き `/llms.txt` 診断（`core/ai_probe.py`）、カテゴリ上限付き 0〜100 総合スコア（2軸/3軸配点）＆優先修正リスト上位 10 件（`core/scoring.py`）を実装し、境界値ケース含む計 275 件の全通過を確認。
- [x] **Step 4:** 3 モード（`extract_only`, `indexability_audit`, `full_audit`）のドメイン単位・複数ドメイン統合オーケストレーター（`core/runner.py`）とローカル実疎通 CLI（`scripts/smoke_local.py`）を実装。モック統合テスト含む 279 件の全通過および公開 3 サイト（`www.sitemaps.org`, `docs.python.org`, `docs.perplexity.ai`、合計 7.15s）の実疎通を確認。
- [x] **Step 5:** `apify_actor/` ラッパー一式（`.actor/actor.json`, `input_schema.json`, `output_schema.json`, `Dockerfile`, `requirements.txt`, 英語 `README.md`, `src/main.py`）と `.dockerignore` を実装。`apify validate-schema` 全通過、PPE 課金・二重課金防止・`event_charge_limit_reached` 安全停止・SDK v2/v3 両対応・`autoEscalateProxy` 接続・KV Store `SUMMARY` 保存を `tests/test_e2e_mock.py`（計 288 件全通過）とローカル `apify run` で検証完了。
- [x] **Step 6:** Private 状態で `apify push`（`Ajisai-Labs/sitemap-extractor-indexability-auditor`, Build `0.1.1`, `isPublic: false`）を実施し、Apify クラウド（海外 AWS・`512 MB` / `180s`・`useApifyProxy: false`・`LIMITED_PERMISSIONS`）にて公開 3 サイト（`developers.cloudflare.com`, `docs.python.org`, `docs.perplexity.ai`）を実行。**7.39s / ピークメモリ 67.19 MB / 0.00103 CU / Proxy 0 GB / 720 Dataset 出力（summary 3 + audited 27 + extracted 690）＆ KVS `SUMMARY` 完全整合** を確認。Store 公開前チェック（PPE イベント設定・`Hide source files`・Published Tasks 5 本・日次 Schedule）へ移行可能。

---

## Apify クラウド実測結果（Step 6・Run ID: `h3xvAvz9c9bpwD3jV`）

- **環境:** Apify Cloud AWS / `512 MB` / `180s` / `LIMITED_PERMISSIONS` / `useApifyProxy: false` / `mode: full_audit` / `maxAuditPagesPerDomain: 10`
- **ラン全体:** `SUCCEEDED` | 実行時間 **7.39s**（監査本体 4.94s） | ピークメモリ **67.19 MB**（平均 53.56 MB） | Compute **0.00103 CU**（計算原価 ~\$0.00031、720 Dataset 書込込み合計 Usage \$0.00393） | Proxy 消費 **0 GB**（`proxy_escalated: false`）

| Domain | Score | Discovery | Sitemap URLs | Audited (Idx/Non) | Canonical (`self`/`idx_eq`/`same`/`cross`/`miss`) | `/llms.txt` | AI Diff Block | Elapsed |
|---|---:|---|---:|---:|---|---|---|---|
| `developers.cloudflare.com` | **100** | `robots_txt` (`sitemap-index.xml`) | 9,209（出力上限 500） | 10 (10/0) | `10/0/0/0/0` | YES (16,609B, H:10, L:111) | NO | 0.86s |
| `docs.python.org` | **90** | `robots_txt` (`sitemap.xml`) | 7 | 7 (1/6) | `0/1/6/0/0` | NO (HTTP 404) | NO | 0.09s |
| `docs.perplexity.ai` | **100** | `robots_txt` (`sitemap.xml`) | 210 | 10 (10/0) | `10/0/0/0/0` | YES (48,435B, H:3, L:217) | NO | 2.67s |

---

## ディレクトリ構成

```text
Apify_Sitemap_Auditor/
├── README.md                        # プロジェクト概要・進捗管理（本ファイル）
├── Specification.md                 # 詳細仕様書
├── Agents.md                        # 段階的開発ワークフロー
├── Skills.md                        # Python / Apify エンジニアリングガイドライン
├── pyproject.toml                   # パッケージ・pytest設定
├── requirements.txt                 # core + dev 依存（Apify非依存）
├── .gitignore                       # .env / .venv / storage / キャッシュ除外
├── .dockerignore                    # Dockerビルドコンテキスト除外設定
├── core/                            # Apify非依存の純粋Pythonパッケージ
│   ├── __init__.py                  # ✅ Step 1-4
│   ├── models.py                    # ✅ Step 1: Pydantic v2 統一モデル
│   ├── ssrf.py                      # ✅ Step 1: URL正規化・SSRF防御
│   ├── http_client.py               # ✅ Step 2: 非同期HTTP/2・手動リダイレクト・OOM上限・プロキシ昇格
│   ├── robots.py                    # ✅ Step 2: RFC 9309 robots.txt パーサー (protego)
│   ├── sitemap_parser.py            # ✅ Step 2: XML/Index/.xml.gz/Text/回復 Sitemapパーサー
│   ├── page_auditor.py              # ✅ Step 3: Indexability / Canonical 5分類 / SEO / JSON-LD監査
│   ├── ai_probe.py                  # ✅ Step 3: AI検索ボット5種差分到達性 & /llms.txt 診断
│   ├── scoring.py                   # ✅ Step 3: 0-100総合スコア & 優先修正リスト生成
│   └── runner.py                    # ✅ Step 4: 3モードオーケストレーター統合
├── scripts/
│   └── smoke_local.py               # ✅ Step 4: ローカル実疎通CLI（Markdown/JSON出力）
├── apify_actor/                     # ✅ Step 5-6: Apifyデプロイ用ラッパー（Build 0.1.1 検証済）
│   ├── .actor/
│   │   ├── actor.json               # dockerContextDir: "../..", 512MB/180s, Overview view
│   │   ├── input_schema.json        # 基本6項目 + sectionCaption詳細設定
│   │   └── output_schema.json       # Overview Dataset & KVS SUMMARY定義
│   ├── Dockerfile                   # FROM apify/actor-python:3.11
│   ├── README.md                    # Apify Store & MCP向け英語ドキュメント
│   ├── requirements.txt             # apify SDK + core依存
│   └── src/
│       ├── __init__.py
│       ├── __main__.py              # ローカル apify run エントリポイント
│       └── main.py                  # PPE課金・二重課金防止・KV SUMMARY保存
└── tests/
    ├── fixtures/                    # ✅ Step 2-3: robots / XML / .xml.gz / HTML / llms.txt
    ├── test_models.py               # ✅ Step 1 (29 tests)
    ├── test_ssrf.py                 # ✅ Step 1 (132 tests)
    ├── test_sitemap_parser.py       # ✅ Step 2 (44 tests)
    ├── test_robots_and_ai.py        # ✅ Step 2-3 (25 tests)
    ├── test_page_auditor.py         # ✅ Step 3 (36 tests)
    ├── test_scoring.py              # ✅ Step 3 (9 tests)
    ├── test_runner_integration.py   # ✅ Step 4 (4 tests)
    └── test_e2e_mock.py             # ✅ Step 5 (9 tests)
```

---

## セットアップ & テスト実行

```powershell
# 依存パッケージのインストール（Python 3.11.1 / .venv）
.venv\Scripts\python.exe -m pip install -r requirements.txt

# 全単体・統合・モックE2Eテストの実行（オフライン・ネットワーク不要）
.venv\Scripts\python.exe -m pytest -v

# 公開 3 サイトに対するローカル実疎通テスト（プロキシ不要・Markdown出力）
.venv\Scripts\python.exe scripts/smoke_local.py --max-audit-pages 10
```
