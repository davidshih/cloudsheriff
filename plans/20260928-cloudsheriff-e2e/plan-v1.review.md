## Verdict

REVISE — 核心方向可行，但狀態機、持久化失敗隔離與 Daytona lifecycle 尚有會讓 E2E 中斷或漏報的缺口。

## Findings

1. **high — `MANUAL` 狀態機未定義完整**
   - **Evidence:** `plans/20260928-cloudsheriff-e2e/plan-v1.html:147-158` 只定義新 finding 為 `PASS`/`FAIL`，row 9 又要求 `MANUAL` 必須已有 previous state；但 fixture 明定包含新的 `MANUAL` finding（`:265`），baseline 測試還要求「all NEW」（`:285-289`）。
   - **Why it matters:** 實作者無法依表格處理第一次出現的 `MANUAL`，也沒有 `MANUAL → PASS/FAIL` 規則；指定的 offline E2E test 無法在不自行發明語意的情況下完成。
   - **Suggested fix:** 明確補齊 `none/gone → MANUAL`、`MANUAL → PASS/FAIL/MANUAL`，以及是否寫入 state；更簡單的方案是將 `MANUAL` 排除於 state/diff，另列為 `NOT_EVALUATED`，並同步修正 fixture 期待。

2. **high — Alert persistence 會被非必要 enrichment 阻斷，且寫入不是 atomic**
   - **Evidence:** orchestration 先執行 CloudTrail 與 Claude，再呼叫 `store.save_scan`（plan `:230-238`）。`explain` 只捕捉 `anthropic.APIError`（`:205`），但 `ANTHROPIC_API_KEY` 不在 required env（`:212-213`）；installed SDK 缺少認證時可在 `.venv/lib/python3.12/site-packages/anthropic/_client.py:396-420` 丟出未被捕捉的 `TypeError`。另外 `save_scan` 依序 upsert state、create scan、create events，沒有 transaction（plan `:189-194`）。
   - **Why it matters:** CloudTrail、認證或 Claude 任一錯誤都可能讓已決定的 alert 完全沒被保存；若 state upsert 後才失敗，下一次同一 regression 會變成 `UNCHANGED`，造成永久漏報。這直接違反「explanation must never block an alert」。
   - **Suggested fix:** 將 scan、transition、alert decision 與 state update 放在同一 SurrealDB transaction；CloudTrail/LLM 改成 best-effort enrichment，失敗時寫入 `attribution=None` 和 deterministic fallback。補測 CloudTrail exception、缺少 Anthropic credential，以及每個 DB 寫入點失敗的情境。

3. **medium — Inactive snapshot 的判斷容易永遠不成立**
   - **Evidence:** plan `:180` 要以字串 `"inactive"` 判斷 snapshot state；實際型別是 `SnapshotState(str, Enum)`（`.venv/lib/python3.12/site-packages/daytona_api_client/models/snapshot_state.py:22-35`），而 `str(SnapshotState.INACTIVE)` 是 `SnapshotState.INACTIVE`，不是 `inactive`。
   - **Why it matters:** snapshot 進入 inactive 後可能不會被 activate，後續 sandbox 建立便會失敗。
   - **Suggested fix:** 明定比較 `snapshot.state.value == "inactive"` 或直接比較 `SnapshotState.INACTIVE`，並以 fake snapshot 加一個 activation test。

4. **medium — Stored state 缺少 row 10/11 所需欄位**
   - **Evidence:** `Transition` 必須含 `labels` 與 `compliance`（plan `:129-135`），row 10/11 又要求從 previous record 填 descriptive fields（`:156-160`）；但同段列出的 persisted state schema 沒有 `labels` 或 `compliance`（`:160`）。
   - **Why it matters:** finding 缺席時沒有 current finding 可補資料，實作者無法建出符合 dataclass 的 `NOT_EVALUATED`／`RESOURCE_GONE` transition。
   - **Suggested fix:** 將 `labels`、`compliance` 納入完整 state record 與 round-trip test，或明定 absent transition 使用空值並調整資料模型。

5. **medium — Sandbox cleanup 不保證驗收時已銷毀，也沒有測 failure paths**
   - **Evidence:** plan `:180` 呼叫 `d.delete(sandbox)` 並立刻印出 `destroyed`；Daytona SDK 預設 `wait=False`，只代表 deletion request 已接受（`.venv/lib/python3.12/site-packages/daytona/_sync/daytona.py:608-618`）。測試清單只驗證 `prowler_command`，沒有驗證 exec、download、JSON parse 失敗時仍 delete（plan `:296`）。
   - **Why it matters:** 這不足以支持 live criterion「no leftover sandbox」（`:356`）與 goal 的「always delete」。
   - **Suggested fix:** cleanup 使用 `d.delete(sandbox, wait=True)`，並用 fake Daytona 分別測成功、non-zero exit、download failure、invalid JSON；每案都斷言 delete 被呼叫且原始錯誤沒有被 cleanup error 遮蔽。

6. **medium — 多個 verification command 不能作為可直接執行的 gate**
   - **Evidence:** live steps 使用不存在的 `scan --baseline`、`scan` 與 `drift.sh open`（plan `:355-357`），但 plan 已明定不建立 console entry point（`:101`），腳本實際位於 `scripts/drift.sh`。從 repo root 執行 `tofu apply`（`:353`）也找不到 root module。另 `shellcheck scripts/*.sh` 會因 `scripts/drift.sh:63` 的 SC2016 回傳 exit 1；`git grep`（`:348`）只掃 tracked files，但驗收同時預期新檔仍可能是 untracked（`:349`）。
   - **Why it matters:** 指令可能失敗，或 secret scan 漏掉本次新增的 Python/test files。
   - **Suggested fix:** 改成完整命令，例如 `tofu -chdir=terraform apply`、`uv run python -m cloudsheriff scan --baseline`、`./scripts/drift.sh open`；ShellCheck 使用 `shellcheck --severity=warning scripts/*.sh`，secret scan 改用涵蓋 untracked files 的 `rg`，或先 stage 後再跑 `git grep --cached`。

7. **low — README 預定加入的 EBS 說明過度且不正確**
   - **Evidence:** plan `:319` 要寫「EBS volume encryption is not a CIS 7.0 check in Prowler 5.43」，但本機 Prowler 5.43 的 `cis_7.0_aws.json:1407-1409` 明列 `ec2_ebs_default_encryption`。真正差異是它檢查 regional encryption-by-default，而非這顆既有 root volume。
   - **Why it matters:** 文件會錯誤描述實際 compliance coverage。
   - **Suggested fix:** 改寫為「CIS 7.0 checks regional EBS encryption-by-default, not encryption of this specific existing root volume；此 instance row 只保證 IMDSv2 finding。」

## Questions for the plan author

`MANUAL` findings 是要持久化並參與 lifecycle/diff，還是只列為當次 `NOT_EVALUATED`、完全不進 state？