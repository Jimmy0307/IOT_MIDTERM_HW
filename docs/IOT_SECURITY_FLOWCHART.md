# IoT 資安作業整體流程圖

> 對應 Assignment #3 V2.2 的 E1 / E2 / E3。完整版高解析 PNG 已備份於 Google Drive，DOCX/PDF v3 亦已內嵌同一張流程圖。

[Google Drive｜高解析流程圖 PNG](https://drive.google.com/file/d/1gVQdnZZ0gIKsZ9PcQPG7nkuslEwu5yp7/view?usp=drivesdk)

```mermaid
flowchart TB
    A["Device / Client"] --> B["Network"] --> C["Transport / TLS"] --> D["Application / API"] --> E["Database"]

    B --> E1A["E1｜ARP Spoofing / MITM"]
    E1A --> E1B{"Attacker 是否 forwarding？"}
    E1B -->|否| E1C["DoS / Availability 受影響"]
    E1B -->|是| E1D["MITM Path 成立"]
    E1D --> E1E["HTTP：Token 可被觀察"]
    E1D --> E1F["HTTPS/TLS：Token 不出現在 Capture"]
    E1F --> E1G["TLS + Certificate Validation"]

    D --> E2A["E2｜Replay Attack"]
    E2A --> E2B["第一次合法 Request → action_count = 1"]
    E2B --> E2C["重送相同 Request"]
    E2C -->|未防護| E2D["再次接受 → action_count = 2"]
    E2C -->|HMAC + Timestamp + Nonce| E2E["Replay / Modified Request 被拒絕"]
    E2E --> E2F["action_count 維持 1"]

    D --> E3A["E3｜SQL Injection"]
    E3A --> E3B["Raw SQL：正常輸入 → 1 row"]
    E3A --> E3C["Raw SQL：惡意輸入 → 4 rows"]
    E3C --> E3D["Parameterized Query → 0 malicious rows"]
    E3D --> E3E["Least Privilege：Sensitive SELECT / UPDATE / DROP → DENIED"]
    E3E --> E3F["DB State：4 → 4"]

    E1G --> Z["Defense-in-Depth"]
    E2F --> Z
    E3F --> Z
```

## 一句話記憶

- **E1：路被劫持** → TLS + 憑證驗證保護 payload，但 TLS 不會阻止 ARP Spoofing。
- **E2：合法訊息被重播** → HMAC + Timestamp + Nonce 驗證 authenticity 與 freshness。
- **E3：資料被當成程式碼** → Parameterized Query 預防 root cause，Least Privilege 限制 blast radius。

**結論：不同 Trust Boundary 對應不同攻擊與控制，因此需要 Defense-in-Depth。**
