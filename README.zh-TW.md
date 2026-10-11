# OpenDLP v0.11.0

開源 **端點稽核／偵測 MVP**（Windows Agent + Watchdog + FastAPI 中央伺服器）。目前定位是 **audit-first prototype**，不是已完成的商用 DLP。

> **⚠️ Windows Agent 尚未驗證：** 維護者尚未在乾淨的 Windows 10/11 + .NET 8 環境完成 C# 編譯與端點實機測試。歡迎協助測試並回報結果；請先在可拋棄的測試環境驗證，不要直接部署到重要電腦或企業環境。
>
> **功能限制：** 目前功能以稽核、內容偵測與事件回報為主。USB、剪貼簿、列印與瀏覽器政策欄位不代表所有情境都已具備可靠的系統層級阻擋能力；瀏覽器擴充功能尚未包含在此版本中。請勿把它當成防止資料外洩的唯一防線。

## 專案結構

```text
OpenDLP/
├── agent/                  .NET 8 Windows endpoint agent
├── watchdog/               Agent watchdog prototype
├── server/                 FastAPI API + dashboard
├── policies/default-policy.json
├── docs/RELEASE_AUDIT.md
├── SECURITY.md
└── LICENSE                 GPL-3.0-only
```

## 需求

- Windows Agent：Windows 10/11、.NET 8 SDK；部分監控功能需要適當權限。
- Server：Python 3.10+。
- 本版本尚未在此執行環境完成 Windows/.NET build，因此請先依下方測試步驟驗證。

## 啟動中央伺服器（開發環境）

Linux/macOS：

```bash
cd server
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
export OPENDLP_TOKEN="請換成至少 32 bytes 的隨機秘密"            # Agent 用
export OPENDLP_ADMIN_TOKEN="另一組至少 32 bytes 的隨機秘密"      # 讀取事件／Agent 清單用
export OPENDLP_DASHBOARD_PASSWORD="儀表板密碼"                   # 未設定則儀表板停用
uvicorn main:app --host 127.0.0.1 --port 8000
```

Windows PowerShell：

```powershell
cd server
py -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:OPENDLP_TOKEN = "請換成至少 32 bytes 的隨機秘密"
$env:OPENDLP_ADMIN_TOKEN = "另一組至少 32 bytes 的隨機秘密"
$env:OPENDLP_DASHBOARD_PASSWORD = "儀表板密碼"
uvicorn main:app --host 127.0.0.1 --port 8000
```

Dashboard：<http://127.0.0.1:8000/>（HTTP Basic，帳號預設 `admin`）。仍請搭配 TLS 反向代理，不要以明文暴露到網際網路。完整環境變數見 `server/env.example`，變更紀錄見 `CHANGELOG.md`。API 若未設定 `OPENDLP_TOKEN`，或 Token 少於 32 bytes，會拒絕請求。

政策檔預設為 `policies/default-policy.json`；可用 `OPENDLP_POLICY` 指定其他 JSON 檔案。`GET /api/v1/policy` 會回傳以共享 token 衍生金鑰簽署的 HMAC envelope。這是原型設計，不是公鑰簽章；請使用 TLS 並妥善保護 token。

## 設定與執行 Agent

1. 在 Windows 上進入 `agent` 資料夾。
2. 執行 `Copy-Item agent.config.example.json agent.config.json` 複製範例設定。
3. 設定 `ServerUrl`、`AgentId` 與敏感路徑。建議把 token 放在環境變數 `OPENDLP_TOKEN`，不要把真實 token 提交到 Git。
4. 確認中央伺服器與 Agent 的 token 完全一致。
5. 執行：

```powershell
dotnet build
dotnet run -- --mode console
```

模式：`--mode console` 用於開發測試；`--mode service` 供 Windows Service 整合測試；`--mode helper` 是使用者工作階段 helper。服務安裝、helper 啟動與 IPC 權限仍需在乾淨的 Windows 測試機驗證。

本地日誌可能包含檔案路徑等敏感資訊。只在授權設備上測試，並先確認組織政策與適用法規。

## 測試

```bash
cd server
pip install -r requirements-dev.txt
python -m pytest -q
python -m compileall -q main.py tests
```

Windows/.NET 測試：在 Windows 10/11 + .NET 8 SDK 上執行 `dotnet build agent/OpenDLP.Agent.csproj`，並測試正常／錯誤 token、政策簽章錯誤、離線重試、日誌保留、helper IPC 權限與服務啟停。

## License

GNU GPL v3 only. See [LICENSE](LICENSE).
