
# Specification: Sitemap Extractor & Indexability Auditor (Fast, No Proxy, Broken Links & AI Bots)

## 1. プロダクト概要とゴール

* **想定スラッグ / ブランド:** `ajisai-labs/sitemap-extractor-indexability-auditor` (`Ajisai-Labs`)
* **公開タイトル:** `Sitemap Extractor & Indexability Auditor — Fast, No Proxy, Broken Links & AI Bots`
* **ポジション:** 公式 `apify/sitemap-extractor`（4096 MB・Proxy必須・評価3.24）の軽量・高速・高機能な完全上位互換。
* **提供価値:**
  1. **超高速Sitemap抽出（プロキシ不要・512 MB）：** `robots.txt` からの自動Sitemap発見、入れ子 `sitemap_index.xml` 再帰展開、`.xml.gz` 解凍、プレーンテキストSitemap、壊れたXMLの回復パースに標準対応。重複URL・他ホスト混入・サイズ/件数超過を自動検知する。
  2. **Indexability（インデックス適性）4点突合監査：** 抽出したURLに対し、HTTPステータス・リダイレクト連鎖（ホップ数/ループ）・`robots.txt` 競合・`noindex`（HTTPヘッダー/meta）・`canonical` 不一致（重大度別）を一括検証する。
  3. **AI検索クローラー差分検証＆SEO/JSON-LD診断：** ブラウザUAと主要AIボット5種（`OAI-SearchBot`, `GPTBot`, `ClaudeBot`, `Claude-SearchBot`, `PerplexityBot`）の到達性差分（CDN/WAF誤ブロック検知）、`/llms.txt` 診断、基本HTML SEOタグおよびJSON-LD構文エラーを構造化出力する。
* **設計原則（最重要）:**
  * コアロジックは `core/` パッケージとして **Apify SDKに一切依存しない純粋Python** で実装する。
  * `apify_actor/` は `core/` を呼び出してDataset / Key-Value Storeへ出力し、Pay-per-event課金を行う薄いアダプター層に徹する。

---

## 2. リポジトリ・ディレクトリ構成

```text
Apify_Sitemap_Auditor/
├── Specification.md
├── Skills.md
├── Agents.md
├── pyproject.toml
├── requirements.txt             # core + dev 依存
├── core/                        # Apify非依存の純粋Pythonパッケージ
│   ├── __init__.py
│   ├── models.py                # Pydantic v2 入出力・監査結果・サマリーモデル
│   ├── ssrf.py                  # URL正規化・スキーム検証・DNS解決後のグローバルIP厳格検証
│   ├── http_client.py           # 非同期HTTP/2クライアント・手動リダイレクト追跡・OOM上限・プロキシ昇格
│   ├── robots.py                # RFC 9309準拠 robots.txt パーサー (protego>=0.6.2)
│   ├── sitemap_parser.py        # XML/Index/.xml.gz/Text Sitemap安全パーサー・重複/他ホスト検知
│   ├── page_auditor.py          # HTML indexability (noindex/canonical/SEO/JSON-LD) 解析
│   ├── ai_probe.py              # ブラウザUA vs AI検索ボット5種 差分到達性 & /llms.txt 診断
│   ├── scoring.py               # ドメイン総合0-100スコア・重大度別集計・優先修正リスト生成
│   └── runner.py                # ドメイン単位オーケストレーション (extract / indexability / full)
├── apify_actor/                 # Apifyデプロイ用の薄いラッパー
│   ├── .actor/
│   │   ├── actor.json           # dockerContextDir: "../.."
│   │   ├── input_schema.json
│   │   └── output_schema.json
│   ├── Dockerfile               # FROM apify/actor-python:3.11
│   ├── README.md                # Apify Store & MCP向けドキュメント
│   ├── requirements.txt         # apify SDK + core依存
│   └── src/
│       ├── __init__.py
│       └── main.py              # Actorエントリポイント・PPE課金・KV SUMMARY保存
├── scripts/
│   └── smoke_local.py           # ローカル実疎通確認用CLI
└── tests/
    ├── fixtures/                # モックXML / .xml.gz / HTML / robots.txt / llms.txt
    ├── test_ssrf.py
    ├── test_sitemap_parser.py
    ├── test_robots_and_ai.py
    ├── test_page_auditor.py
    ├── test_scoring.py
    └── test_e2e_mock.py
```

## 3. コア機能・判定仕様

### 3.1 SSRF防御 & HTTP取得 (`core/ssrf.py`, `core/http_client.py`)

* SSRF防御（全ホップ必須）：
  * 許可スキームは `http` / `https` のみ。
  * 初回アクセスおよびリダイレクト追跡時の全ホップでDNS解決を行い、解決された全IPアドレスが `ipaddress.ip_address(ip).is_global == True` であることを検証する（プライベートIP・ループバック・クラウドメタデータ `169.254.169.254` 等は `SSRFBlockedError` で遮断）。

* リダイレクト追跡：
  * `httpx.AsyncClient(follow_redirects=False)` と `response.next_request` による手動ループ（最大10ホップ）。ループ検知時は `REDIRECT_LOOP`、超過時は `TOO_MANY_REDIRECTS` を記録。

* OOM防止（512 MB運用上限）：
  * ストリーミング受信上限：Sitemap `15 MB`、HTML `2 MB`、robots.txt `1 MB`、llms.txt `512 KB`。上限到達時は `truncated = True` で安全打ち切り。
  * `.xml.gz` 解凍時は段階読み込みで最大 `30 MB` を上限とし、gzipボムによるOOMを防止する。

### 3.2 Sitemap発見 & 解析 (`core/robots.py`, `core/sitemap_parser.py`)

* 発見順：
  1. ユーザーが明示的なSitemap URL（例：`.../sitemap.xml`）を渡した場合はそれを直接処理。
  2. ドメイン／トップURLが渡された場合、`robots.txt` を `protego>=0.6.2` で解析し `Sitemap:` 宣言をすべて抽出。
  3. `robots.txt` に宣言が無い場合のみ、`/sitemap.xml` → `/sitemap_index.xml` → `/sitemap.xml.gz` の順にフォールバック探索。

* 対応フォーマット（sitemaps.org準拠）：
  * XML `urlset`、入れ子 `sitemapindex`（最大再帰深度5・最大ファイル数 `maxSitemapFiles`）、`.xml.gz`（マジックバイト `1f 8b` 検知）、プレーンテキストSitemap（1行1URL）。
  * 厳格XMLパース失敗時のみ `lxml.etree.XMLParser(resolve_entities=False, no_network=True, recover=True)` で回復パースし、`recovered_xml = True`（warning）を記録。

* Sitemap構造品質チェック：
  * 重複URL（正規化後一致）件数、`cross_host` URL件数、1ファイル50,000URL超過、lastmod 付与率・不正日付形式、`sitemap_files` 単位のステータス/エラー記録。

### 3.3 URL Indexability & HTML監査 (`core/page_auditor.py`)

監査対象URL（最大 `maxAuditPages` 件）に対し、以下を判定し `issues: list[AuditIssue]`（`code`, `severity: critical|warning|info`, `detail`）を付与する。

* HTTP / リダイレクト：
  * `HTTP_4XX` / `HTTP_5XX` / `FETCH_ERROR` (`critical`)
  * `REDIRECT_CHAIN`（1ホップは `warning`、2ホップ以上またはループは `critical`）
  * `HTTP_NON_HTTPS`（Sitemap内に `http://` 記載：`warning`）

* インデックス阻害（Sitemapとの矛盾）：
  * `DISALLOWED_BY_ROBOTS`（`robots.txt` の `User-agent: *` で拒否：`critical`）
  * `NOINDEX_IN_SITEMAP`（`X-Robots-Tag: noindex` または `<meta name="robots|googlebot" content="...noindex...">：critical`）

* Canonical分類（PoC実測に基づく誤検知防止ルール）：
  * `self`：正規化URL完全一致（正常）
  * `index_file_equivalent`：末尾 `/` と `/index.html`（`/index.htm`, `/index.php`）の差分のみ（`info` — 重大減点しない）
  * `cross_path_same_host`：同一ホスト内の別パスを指す（`warning`：`CANONICAL_MISMATCH_SAME_HOST`）
  * `cross_host`：別ホストを指す（`critical`：`CANONICAL_MISMATCH_CROSS_HOST`）
  * `missing`：canonicalタグ未設置（`info`）

* `full_audit` モード追加項目：
  * `title`（有無・文字数：空なら `warning`）、`meta description`（有無・文字数）、h1 個数（0個または複数なら `info`/`warning`）、本文テキスト文字数（200文字未満の薄コンテンツ／CSR空ページ疑い：`SSR_THIN_CONTENT warning`）。
  * `application/ld+json` 個数・`@type` 一覧・JSON構文エラー件数（不正JSONがあれば `INVALID_JSONLD warning`）。

### 3.4 AI検索ボット差分検証 & /llms.txt (core/ai_probe.py)

`full_audit`（または `includeAiBotAudit: true`）時、ドメインのトップURLに対して実行する。

* 対象ボット（一次公式ドキュメント準拠）：
  * `OAI-SearchBot`, `GPTBot`, `ClaudeBot`, `Claude-SearchBot`, `PerplexityBot`

* 検証内容：
  * 各ボットの `robots.txt` 許可可否（`protego.can_fetch(url, bot_name)`）。
  * ブラウザUAで HTTP 200 を返すトップURLに対し、各ボットUAでアクセスした際のHTTPステータス比較。ブラウザ200かつボットが `401/403/429/503` の場合、`cdn_or_waf_diff_block = True`（`AI_BOT_CDN_BLOCK`）をフラグ立てする。

* `/llms.txt` 診断：
  * HTTP 200 かつ非HTML（`text/html` でない）かつ 20バイト以上を `llms_txt_present = True` と判定し、バイト数・Markdown見出し数・リンク数を出力。

### 3.5 ドメイン総合スコア & 優先修正リスト (`core/scoring.py`)

* `health_score`（0〜100の整数）：
  * 100点満点からの減点方式（各カテゴリの最大減点上限を設け、1項目だけで極端に0点崩壊しない設計）。
  * 配点目安：Indexability整合性（4xx/5xx・robots競合・noindex・cross-host canonical：最大 -50点）、Sitemap衛生（重複・壊れたXML・リダイレクト連鎖：最大 -25点）、SEO/JSON-LD・AI Bot/llms.txt（`full_audit` 時のみ最大 -25点、`indexability_audit` 時は上記2軸を100点換算）。

* `top_priority_fixes`：検出されたイシューを `severity`（`critical` > `warning` > `info`）と影響URL件数降順で集計し、上位10件を構造化リスト化（影響件数・サンプルURL最大3件・修正アクション文）。

## 4. Apify Actor インターフェース＆課金仕様 (`apify_actor/`)

### 4.1 入力スキーマ (`input_schema.json`)

* `startUrls` (array[string], required, prefill: ["https://www.sitemaps.org"]): 対象ドメインURLまたはSitemap URLの配列（文字列配列またはApify RequestList形式の両対応）。
* `mode` (string, enum: `["extract_only", "indexability_audit", "full_audit"]`, default: `"indexability_audit"`): 実行モード。
* `maxUrlsPerDomain` (integer, default: `500`, min: `1`, max: `50000`): Sitemapから抽出・出力する最大URL数。
* `maxAuditPagesPerDomain` (integer, default: `50`, min: `0`, max: `2000`): HTTP/HTML実監査を行う最大ページ数（`extract_only` 時は自動的に0扱い）。
* `maxSitemapFiles` (integer, default: `30`, min: `1`, max: `200`): 1ドメインあたり取得する最大Sitemapファイル数。
* `concurrency` (integer, default: `5`, min: `1`, max: `15`): 1ドメインあたりの並列HTTP接続数。
* `includeAiBotAudit` (boolean, default: `true`): `full_audit` 時のAIボット差分＆`llms.txt` 診断ON/OFF（`indexability_audit` でも明示ONで実行可）。
* `outputMode` (string, enum: `["both", "urls_only", "summary_only"]`, default: `"both"`): Dataset出力モード。
* `onlyIssuesInDataset` (boolean, default: `false`): `true` の場合、問題が検出されたURL行のみDataset出力する（ノイズ削減モード）。
* `autoEscalateProxy` (boolean, default: `true`): Direct HTTPで403/429/503ブロック検知時のみApify Proxyへ自動昇格するフラグ。
* `proxyConfiguration` (object, default: `{"useApifyProxy": false}`): デフォルトはプロキシなし。

### 4.2 出力設計

1. Default Dataset（フラット英語キー構造）：
   * `record_type == "summary"`：ドメイン単位の総合スコア・Sitemap統計・監査集計・AIボット判定・`llms_txt`・`top_priority_fixes`・`proxy_escalated`。
   * `record_type == "url"`：URL単位のクリーン明細（`domain`, `url`, `sitemap_source`, `lastmod`, `http_status`, `final_url`, `redirect_hops`, `robots_allowed`, `indexable`, `noindex`, `canonical_status`, `canonical_url`, `issues`, `issue_severities`, `elapsed_ms` 等）。

2. Key-Value Store (`SUMMARY` キー):
   * 全対象ドメインのサマリー配列、実行メタデータ（`mode`, `total_domains`, `total_urls_extracted`, `total_pages_audited`, `elapsed_sec, proxy_escalated`）を必ず保存。

### 4.3 Pay-per-event (PPE) 課金設計

* Apify Console側で `Pay per event + usage` を有効化、`apify-default-dataset-item` は削除、`Minimum for max cost per run` は空欄とする。

* 課金イベント定義（コード側イベント名と完全一致させること）：
  * `sitemap-url-extracted`（Primary event）：Free `$0.0004`（$0.40/1k） / Starter `$0.0003` / Scale・Business `$0.0002`
  * `page-indexability-audited`：Free `$0.0040`（$4.00/1k） / Starter `$0.0030` / Scale・Business `$0.0020`
  * `domain-audit-summary`（Infrequent）：`$0.015` / ドメイン
  * `apify-actor-start`（Infrequent）：`$0.00005`（512 MB推奨・最初の5秒免除）

* 二重課金防止＆上限遵守ルール：
  * URL行の出力・課金はモードに応じて `extract_only` は `sitemap-url-extracted`、実監査済みURL行は `page-indexability-audited` を `Actor.push_data(batch, event_name=...)` で計上する（未監査の追加抽出URL行があれば `sitemap-url-extracted` で計上し、1 URLに対して2重課金しない）。
  * ドメインサマリーは `Actor.charge(event_name="domain-audit-summary", count=1, idempotency_key=f"summary-{domain_hash}")` で計上し、`event_charge_limit_reached == True` なら安全停止して `SUMMARY` をKVS保存する。

### 4.4 Published Tasks 設計（公開フェーズ用・全5本、基本入力項目に絞り込み）

1. `Fast Sitemap URL Extractor (No Proxy, .xml.gz Supported)`（`mode: "extract_only"`, `maxUrlsPerDomain: 2000`）
2. `Sitemap Broken Links & Redirect Chain Checker`（`mode: "indexability_audit"`, `onlyIssuesInDataset: true`）
3. `Sitemap Indexability & Canonical Conflict Auditor`（`mode: "indexability_audit"`, `onlyIssuesInDataset: false`）
4. `AI Search Crawler (GPTBot / ClaudeBot) & llms.txt Audit`（`mode: "full_audit"`, `maxAuditPagesPerDomain: 10`, `includeAiBotAudit: true`）
5. `Technical SEO & Sitemap Health Monitor`（`mode: "full_audit"`, `maxAuditPagesPerDomain: 50`）
