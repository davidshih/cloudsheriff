## Status
PARTIAL — 計畫已完整實作，Python 67 tests 全過；但 Tofu provider 在 sandbox 內無法啟動，故驗證未全綠。

## Changes
`.env.example` — 新增 Arize project/model 設定並更新 SurrealDB 指令註解。  
`.gitignore` — 忽略本機 SurrealDB `data/`。  
`pyproject.toml` — 加入 pytest import path 與 test path。  
`cloudsheriff/__init__.py` — 建立套件。  
`cloudsheriff/engine.py` — 實作 OCSF normalization、SG evidence、三軸 diff 與 deterministic alert gate。  
`cloudsheriff/aws.py` — 實作 STS、SG rule snapshot 與 CloudTrail attribution。  
`cloudsheriff/scanroom.py` — 實作 Daytona snapshot、Prowler execution 與可靠 cleanup。  
`cloudsheriff/store.py` — 實作 SurrealDB state、scan/event atomic transaction。  
`cloudsheriff/explain.py` — 實作 Arize tracing、Claude explanation 與 deterministic fallback。  
`cloudsheriff/__main__.py` — 實作 `build-image`、`scan` CLI、enrichment 與文字報告。  
`tests/fixtures/prowler_demo.ocsf.json` — 新增五筆 OCSF fixture。  
`tests/conftest.py` — 新增 Finding/Transition fixtures。  
`tests/test_engine.py` — 覆蓋 normalization、12-row diff、gate 與 E2E engine scenario。  
`tests/test_aws.py` — 覆蓋 AWS adapters、Prowler command、Daytona cleanup paths。  
`tests/test_store.py` — 覆蓋 persistence、upsert、ordering 與 transaction atomicity。  
`tests/test_explain.py` — 覆蓋 prompt isolation、fallback 與 SDK failure paths。  
`tests/test_main.py` — 覆蓋 best-effort enrichment。  
`README.md` — 更新 scope、CIS 說明、部署與 pipeline runbook。  
`HACKSPRINT_BOUNDARY.md` — 改寫 pre-event/event boundary 與 demo contract。

## Verification
- `uv run pytest -q` — 未進入測試；uv 讀取 sandbox 外 cache 時被拒，exit 2。
- `uv run --no-sync pytest -q` — 同上，exit 2。
- `.venv/bin/pytest -q` — PASS，67 passed。
- `UV_CACHE_DIR=/tmp/cloudsheriff-uv-cache uv run --offline --no-sync pytest -q` — PASS，67 passed。
- `.venv/bin/python -m cloudsheriff --help` — PASS，exit 0。
- `.venv/bin/python -m cloudsheriff scan --help` — PASS，exit 0；顯示 `--baseline`、`--profile`。
- 隔離環境執行 `.venv/bin/python -m cloudsheriff scan` — PASS，exit 2；列出四個缺少的環境變數，無 traceback。
- 使用 writable uv cache 重跑兩個 CLI help 與 missing-env gate — 結果相同，符合預期。
- `.venv/bin/python -m compileall -q cloudsheriff tests` — PASS。
- `shellcheck --severity=warning scripts/*.sh` — PASS，exit 0。
- secret `rg` scan — PASS，無 matches（`rg` exit 1）。
- `git diff --check` — PASS。
- `tofu -chdir=terraform test` — FAIL：AWS provider plugin 無法在 sandbox 內完成 handshake；0 passed、1 failed、5 skipped，尚未執行 assertions。
- `git status --porcelain` — 僅出現計畫範圍內檔案、planner 預置檔案與 `plans/`。

## Deviations from plan
原始 `uv run` 無法存取 repo 外的 uv cache，因此改以 `/tmp/cloudsheriff-uv-cache` 搭配 `--offline --no-sync` 執行；同一既有環境下 67 tests 全過。

## Open issues
`tofu -chdir=terraform test` 受 sandbox provider-process 限制而未通過；需由 orchestrator 在可啟動 Terraform AWS provider 的環境重跑。