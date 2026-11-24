# Skills: Python Backend & Apify SDK Engineering Guidelines (Sitemap Auditor)

## 1. 開発環境標準

* **Python:** 3.11.x (`.venv` + `pip`)
* **型安全性:** すべてのデータモデルと関数シグネチャに Python 3.11 型ヒント（`from __future__ import annotations`）と **Pydantic v2 (`BaseModel`)** を使用する。
* **非同期HTTP:** `httpx.AsyncClient`（`httpx[http2]` によるHTTP/2対応、未導入時は自動フォールバック）を標準とし、ヘッドレスブラウザ（Playwright等）は一切導入しない（メモリ 512 MB・高速・低原価を維持するため）。
* **外部依存の最小化:** コア依存は `httpx[http2]`, `lxml`, `protego>=0.6.2`, `pydantic>=2.0` に抑える。

## 2. 厳守すべきアーキテクチャ分離

* **`core/` 内から `apify` パッケージを絶対に `import` しないこと。**
* プロキシURL供給やログ出力は依存性注入（例：`proxy_url_factory: Callable[[bool], Awaitable[str | None]] | None`、標準 `logging.Logger`）経由で `apify_actor/` から `core/` へ渡す。
* これにより `core/` はローカルCLI、FastAPI、独立MCPサーバー、pytest単体テストのいずれからもそのまま再利用できる状態を保つ。

## 3. セキュリティ・堅牢性の必須作法

### 3.1 SSRF防御 (`core/ssrf.py`)

* 任意URLを受け取る公開Actorであるため、`follow_redirects=False` を徹底し、初回リクエストと全リダイレクト先ホップの直前で `socket.getaddrinfo` によりDNS解決を行い、**すべての解決IPで `ipaddress.ip_address(ip).is_global` が `True` であることを検証**する。
* `127.0.0.1`, `::1`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.169.254`（AWS/クラウドメタデータ）は例外なくブロックし、ユニットテストで必ず検証する。

### 3.2 安全なXML / Gzip / HTMLパース

* `lxml.etree.XMLParser` は必ず **`resolve_entities=False, no_network=True`** を指定し、XXE（XML External Entity）攻撃を防ぐ。
* まず `recover=False` で厳格パースし、`XMLSyntaxError` 時のみ `recover=True` で回復パースして `recovered_xml = True` を記録する。
* `.xml.gz` はURL拡張子だけでなくマジックバイト（`b"\x1f\x8b"`）で判定し、`gzip.GzipFile.read(max_out_bytes + 1)` により展開サイズ上限（30 MB）を厳守して解凍ボムによるOOMを防ぐ。

### 3.3 RFC 9309準拠 `robots.txt` (`protego>=0.6.2`)

* `protego>=0.6.2` を使用する（旧バージョンのReDoS脆弱性対策）。
* `robots.txt` が 4xx の場合は「全許可」、5xx またはタイムアウトの場合は「不明（監査継続・warning記録）」として安全にフォールバックし、実行全体をクラッシュさせない。

### 3.4 段階的プロキシ昇格（コスト最適化）

1. まずプロキシなし（Direct HTTP）でリクエストを実行する。
2. 403 / 429 / 503 または Cloudflareチャレンジ画面等のブロック検知時かつ `autoEscalateProxy == True` の場合のみ、`proxy_url_factory(True)` を呼んでプロキシ経由で最大1回リトライする。
3. 同一ドメイン内で一度プロキシへ昇格したら、そのドメインの残りリクエストはプロキシ経由を維持し、`proxy_escalated = True` をサマリーへ記録する。
4. 同時接続は `asyncio.Semaphore(concurrency)` で制御し、対象サーバーへの過度なバーストを避ける。

## 4. Apify SDK for Python (PPE) 実装作法

* エントリポイントは `async with Actor:` コンテキストマネージャを使用する。
* `startUrls` は `["https://example.com"]` の文字列配列と `[{"url": "https://example.com"}]` の両形式を受け付けられるように正規化する。
* 課金イベント付きデータ出力は **`await Actor.push_data(records, event_name=...)`** を使用する。
* ドメインサマリー課金は **`await Actor.charge(event_name="domain-audit-summary", count=1, idempotency_key=...)`** を使用し、返却の `event_charge_limit_reached` が `True` なら即座にループを安全停止する。
* 正常終了前に必ず `await Actor.set_value("SUMMARY", summary_payload)` を保存する。
* `.actor/actor.json` は `dockerfile: "../Dockerfile"`、`dockerContextDir: "../.."`、デフォルト実行設定 `memoryMbytes: 512`、`timeoutSecs: 180` を明記し、`output_schema.json` も同梱する。

## 5. テスト・品質基準

* ネットワークアクセスを伴わないオフライン単体テスト（`.venv\Scripts\python.exe -m pytest`）を必須とする。
* `tests/fixtures/` にモックデータを配置し、以下を必ず自動テストする：
  * SSRF防御（localhost / private IP / 169.254.169.254 / 非httpスキーム / リダイレクト先がprivate IPになるケース）
  * XML `urlset`・入れ子 `sitemapindex`・`.xml.gz`・壊れたXMLの回復・プレーンテキストSitemap・重複URL・他ホスト混入
  * Canonical 5分類（`self`, `index_file_equivalent`, `cross_path_same_host`, `cross_host`, `missing`）、`noindex`（header/meta）、JSON-LD正常/構文エラー
  * AIボット差分ブロック判定、`llms.txt` のHTML誤認防止
  * スコア算出の境界値（0件・全正常・全異常・下限0点ガード）
  * `apify_actor` モックE2E（`extract_only` / `indexability_audit` / `full_audit` の3モード、二重課金なし、`event_charge_limit_reached` 停止、`SUMMARY` 出力）

