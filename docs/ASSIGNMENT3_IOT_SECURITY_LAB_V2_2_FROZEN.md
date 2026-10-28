# Assignment #3｜IoT Security Lab 實驗規格與驗收標準 V2.2

## 0. Final Freeze Summary

V2.2 為正式凍結版本。

本版不再增加攻擊種類、系統元件或新的研究問題，只修正實作時可能造成錯誤結論的細節：

```text
E1
→ 提前 Network Feasibility Gate
→ SQL Injection 成為第一 Fallback
→ Replay 成為第二 Fallback

E2
→ HMAC 必須簽 raw request body bytes
→ nonce / timestamp 必須受 HMAC 保護
→ constant-time comparison
→ per-device secret
→ nonce cache restart residual risk
→ Replay Protection 與 Idempotency 分離

E3
→ 真正 raw SQL interpolation baseline
→ table-level SELECT privilege containment
→ WRITE privilege containment

Defense-in-Depth
→ 明確標註 IMPLEMENTED / CONCEPTUAL
```

正式 Scope：

```text
PRIMARY_ATTACK =
ARP Spoofing / MITM

EXTENSION_E2 =
Replay Attack

EXTENSION_E3 =
SQL Injection
```

---

# 1. Assignment Scope

老師原始要求為：

```text
選擇其中一種攻擊進行實作
→ 說明攻擊原理
→ 探討防禦方法
→ 書面報告
```

因此正式報告定義：

## Primary Experiment

```text
E1 = ARP Spoofing / MITM
```

完整包含：

```text
Attack
→ Evidence
→ Root Cause
→ CIA
→ Defense
→ Re-test
→ Regression
→ Residual Risk
```

## Cross-Layer Extensions

```text
E2 = Replay Attack
E3 = SQL Injection
```

兩者用途為說明：

> 即使 Network Layer 已有安全控制，Message Layer 與 Application Layer 仍各自存在獨立的 Trust Boundary。

---

# 2. E1 Network Feasibility Gate

由於 E1 是 Primary Experiment，必須最先 De-risk。

環境優先順序：

```text
1. Isolated VM Network
2. Linux Network Namespace / Controlled Bridge
3. macvlan / dedicated Docker network
4. Docker default bridge only if experimentally verified
```

不得假設 Docker default bridge 一定能正確呈現 ARP Spoofing。

---

## 2.1 Minimum Gate

建立：

```text
Victim
Gateway
Attacker
```

必須證明：

```text
SAME_L2_DOMAIN = YES

ARP_TABLE_VISIBLE = YES

ARP_MAPPING_CAN_CHANGE = YES

ATTACKER_IP_FORWARDING = YES

TRAFFIC_CONTINUES_THROUGH_ATTACKER = YES

PCAP_EVIDENCE_AVAILABLE = YES
```

全部成立：

```text
E1_NETWORK_FEASIBILITY = PASS
```

---

# 3. Primary Experiment Fallback Policy

若：

```text
E1_NETWORK_FEASIBILITY = FAIL
```

不得無限投入時間處理環境問題。

Fallback 順序正式鎖定：

```text
Fallback 1
→ SQL Injection

Fallback 2
→ Replay Attack
```

理由：

### SQL Injection

老師原始作業清單中明確列為 DVWA 可選攻擊。

環境需求最低：

```text
Application
+
Database
```

不依賴：

```text
L2 topology
VM networking
ARP behavior
packet forwarding
```

因此為最穩定 Primary Fallback。

### Replay Attack

IoT 代表性較高，但屬老師「其他有興趣攻擊」範圍，且需要額外建立 Request Authentication / Freshness Model。

因此列第二順位。

Fallback 只能在：

```text
E1_NETWORK_FEASIBILITY = FAIL
```

且失敗 Evidence 已保存後啟動。

---

# 4. System Architecture

```text
                    External Client
                           │
                           ▼
                       Frontend
                           │
                         HTTPS
                           │
                           ▼
                         Nginx
                   TLS Termination
                           │
                           ▼
                    FastAPI Backend
                     │           │
            Data Path│           │Command Path
                     │           │
                     ▼           ▼
                PostgreSQL    IoT Service
                                  │
                                  ▼
                              MQTT / API
                                  │
                                  ▼
                           Device Simulator
```

Database 不位於所有 IoT Command 的必經路徑。

因此：

```text
FastAPI
├── Data Path → PostgreSQL
└── Command Path → IoT Service → Device
```

---

# 5. Trust Boundaries

```text
TB-A
External / Local Network
→ Reverse Proxy / TLS

TB-B
Reverse Proxy
→ Application Backend

TB-C
Application Backend
→ Database

TB-D
Application / IoT Service
→ Device
```

實驗映射：

```text
E1
→ TB-A
→ Network Trust

E2
→ TB-B / TB-D
→ Message Trust / Freshness

E3
→ TB-C
→ Code/Data Boundary
→ Database Authorization
```

---

# 6. Unified Threat Model

| Experiment | Attacker Position | Capability | Explicit Assumption |
|---|---|---|---|
| E1 | 同一 L2 Network | ARP manipulation、traffic interception | HTTP plaintext 可觀察；正確 TLS 驗證時 payload 受保護 |
| E2 | 已取得一份合法 request | Replay / modify captured request | Request 來自 log leakage、client compromise 或 TLS termination 後，不假設破解 TLS |
| E3 | 可存取 Backend API | 提供惡意輸入 | Request 已成功到達 Application Layer |

因此三個攻擊者不是同一個萬能角色。

---

# 7. E1｜ARP Spoofing / MITM

## 7.1 Root Cause

ARP 本身缺乏強式身分驗證。

正常：

```text
Gateway IP
→ Gateway MAC
```

攻擊後：

```text
Gateway IP
→ Attacker MAC
```

使：

```text
Victim
↓
Attacker
↓
Gateway
```

---

## 7.2 IP Forwarding Requirement

真正 MITM 必須：

```text
receive packet
↓
forward packet
↓
destination receives packet
```

若：

```text
ARP poisoned
BUT
forwarding disabled
```

結果：

```text
traffic disruption
→ DoS
```

不得宣稱成功 MITM。

---

## 7.3 TLS Requirement

HTTPS Scenario 必須：

```text
CERTIFICATE_VALIDATION = ENABLED
```

不得：

```text
verify = false
```

否則無法證明 TLS Control Effectiveness。

---

## 7.4 Evidence

```text
E1-01 Baseline ARP Table
E1-02 Poisoned ARP Table
E1-03 Baseline PCAP
E1-04 MITM PCAP
E1-05 HTTP Payload Observation
E1-06 HTTPS Payload Observation
E1-07 Certificate Validation Result
E1-08 Regression Result
```

---

## 7.5 CIA

```text
Integrity
→ ARP mapping modified

Confidentiality
→ plaintext traffic potentially exposed

Availability
→ forwarding failure may degrade service
```

---

## 7.6 Defense

實作：

```text
TLS
Certificate Validation
```

分析：

```text
Dynamic ARP Inspection
Network Segmentation
Static ARP in limited environments
Monitoring
```

---

## 7.7 Regression

防禦完成後：

```text
VALID_DEVICE_TLS_CONNECTION = PASS

VALID_CERTIFICATE = PASS

NORMAL_DEVICE_TRAFFIC = PASS
```

Security Control 不可藉由「所有流量都壞掉」取得 PASS。

---

## 7.8 Residual Risk

TLS：

```text
protects payload confidentiality/integrity
```

但不保證：

```text
network availability
endpoint security
```

若 Endpoint 本身被攻破：

```text
plaintext may be exposed
before encryption
or
after decryption
```

---

# 8. MQTT Decision

若 E1 採 MQTT：

```text
MQTT / TCP 1883
vs
MQTTS
```

可作為額外 IoT Evidence。

若未實際使用：

```text
MQTT = OPTIONAL
```

不得為了「架構看起來完整」增加無效建置成本。

---

# 9. E2｜Replay Attack

## 9.1 Threat Scenario

E2 不假設：

```text
Attacker breaks TLS
```

合法 request 取得來源限定：

```text
Debug log leakage
Client compromise
Internal attacker
Application log exposure
TLS termination 後的 internal traffic
```

---

# 10. Request Authentication

Request Security Fields：

```text
method
path
body
timestamp
nonce
```

建立：

```text
canonical_request
```

---

# 11. Canonicalization Rule｜FROZEN

HMAC 最容易出現的實作錯誤不是演算法，而是 Client / Server 對同一 Request 產生不同 byte sequence。

因此：

```text
canonical_body
=
RAW HTTP REQUEST BODY BYTES AS TRANSMITTED
```

不得：

```text
JSON parse
↓
re-serialize
↓
calculate HMAC
```

原因：

即使 JSON 語意完全相同：

```json
{"a":1,"b":2}
```

與：

```json
{
  "b": 2,
  "a": 1
}
```

byte representation 不同。

因此 HMAC 必然不同。

正式規格：

```text
Client signs
→ exact body bytes it transmits

Server verifies
→ exact raw body bytes it received
```

---

## 11.1 Canonical Request

概念：

```text
canonical_request =
method
+
normalized path
+
raw body bytes
+
timestamp
+
nonce
```

其中：

```text
raw body bytes
```

不得由 Parsed JSON 重新產生。

Header 中的：

```text
timestamp
nonce
signature
```

亦需使用明確固定 encoding。

---

# 12. HMAC

Client：

```text
signature =
HMAC(
    device_secret,
    canonical_request
)
```

Server：

```text
expected_signature =
HMAC(
    device_secret,
    received_canonical_request
)
```

---

# 13. Constant-Time Comparison

不得：

```text
received_signature == expected_signature
```

必須使用 constant-time comparison，例如：

```text
hmac.compare_digest()
```

降低 timing side-channel。

---

# 14. Replay Protection

Server：

```text
1. Validate timestamp
2. Validate nonce unused
3. Rebuild canonical request from received bytes
4. Verify HMAC
5. Execute command
6. Mark nonce used
```

如果攻擊者修改：

```text
body
nonce
timestamp
path
method
```

但無法重新產生合法 HMAC：

```text
SIGNATURE_VALIDATION = FAIL
```

---

# 15. Nonce Cache × Time Window

Replay 防禦必須同時包含：

```text
timestamp window
AND
nonce cache
```

不得二選一。

例如：

```text
accepted_time_window = 5 min
nonce_cache_ttl = 5–10 min
```

Cache 只保存仍可能被 Replay 的 nonce。

---

# 16. Replay Demo Semantics

不得使用模糊的：

```text
OPEN
```

因為：

```text
already open
+
OPEN again
```

狀態可能看不出差異。

使用：

```text
UNLOCK
→ action_count +1
→ auto-lock
```

或：

```text
DISPENSE
→ action_count +1
```

第一次：

```text
action_count = 1
```

Replay 成功：

```text
action_count = 2
```

Replay 被阻擋：

```text
action_count remains 1
```

---

# 17. Replay vs Idempotency

Replay Protection 解決：

> 舊的合法 Request 是否再次被未授權執行？

Idempotency 解決：

> Legitimate Client timeout 後安全重試時，如何避免 Business Action 被重複執行？

兩者不同。

```text
nonce
→ security freshness

idempotency_key
→ application retry semantics
```

本 Lab：

```text
Replay Protection = IMPLEMENTED

Idempotency Semantics = CONCEPTUAL / FUTURE WORK
```

---

# 18. E2 Key Management Residual Risk

HMAC 假設：

```text
device_secret remains secret
```

如果攻擊者取得 Secret：

```text
new nonce
+
new timestamp
+
new body
+
valid HMAC
```

都可以自行產生。

因此：

```text
HMAC Replay Protection
≠
Protection against compromised device secret
```

---

## 18.1 Per-Device Keys

不得推薦：

```text
GLOBAL_SHARED_SECRET
```

因為：

```text
Device A compromised
→ Global secret leaked
→ Entire fleet compromised
```

實務上應：

```text
Device A → Key A
Device B → Key B
Device C → Key C
```

---

## 18.2 Secure Storage

實務環境可進一步採：

```text
Secure Element
TPM
TEE
Hardware-backed Keystore
```

本 Lab 不實作完整 Hardware Key Protection。

---

# 19. Nonce Cache Restart Residual Risk

本 Lab 若使用：

```text
in-memory nonce cache
```

Server Restart 後：

```text
nonce cache lost
```

則：

```text
previously used nonce
within accepted timestamp window
```

可能重新被視為未使用。

因此正式列為：

```text
E2_RESIDUAL_RISK
```

Production-grade 解法可使用：

```text
persistent replay store
distributed cache
shorter replay window
server-issued challenge
```

本作業不要求實作。

---

# 20. E2 PASS Gate

Vulnerable：

```text
FIRST_REQUEST = ACCEPT

EXACT_REPLAY = ACCEPT

ACTION_COUNT = 2
```

Protected：

```text
FIRST_REQUEST = ACCEPT

EXACT_REPLAY = REJECT

MODIFIED_NONCE_OLD_SIGNATURE = REJECT

MODIFIED_TIMESTAMP_OLD_SIGNATURE = REJECT

MODIFIED_BODY_OLD_SIGNATURE = REJECT

ACTION_COUNT_ON_REPLAY = UNCHANGED

AUDIT_LOG_CREATED = YES
```

---

# 21. E3｜SQL Injection

## 21.1 Vulnerable Baseline

必須使用隔離 Lab 中真正的：

```text
raw SQL
+
direct user-controlled string interpolation
```

不得使用：

```text
parameter binding
safe ORM query
```

卻宣稱為 Vulnerable。

---

# 22. Safe Injection Objective

只證明：

```text
user input changes SQL semantics
```

不進行破壞性測試。

證據可採：

```text
normal query
→ expected rows

injected condition
→ unexpected additional rows
```

---

# 23. E3 Evidence

```text
E3-01 User Input
E3-02 Generated SQL / DB Query Log
E3-03 HTTP Response
E3-04 Returned Row Count
E3-05 Parameterized Query Result
E3-06 DB State
E3-07 Normal Regression
E3-08 Allowed-table SELECT
E3-09 Sensitive-table SELECT Denied
E3-10 Unauthorized UPDATE Denied
E3-11 Unauthorized DROP Denied
```

---

# 24. Primary SQLi Defense

## Parameterized Query

修正 Root Cause：

```text
SQL code
≠
user-controlled data
```

因此：

```text
Parameterized Query
= PREVENT
```

---

# 25. Least-Privilege Database Account

建立：

```text
iot_search_reader
```

只允許：

```text
SELECT devices
SELECT telemetry
```

不得：

```text
SELECT users
SELECT secrets
SELECT audit_internal

UPDATE
DELETE
DROP
ALTER
```

---

# 26. Confidentiality Containment

只有限制 UPDATE / DROP 不夠。

SQL Injection 的主要危害之一是：

```text
unauthorized read
```

因此必須測：

```text
Injection attempts reading authorized IoT table
→ permitted according to role

Injection attempts reading unrelated sensitive table
→ permission denied
```

這樣才能合理宣稱：

```text
Confidentiality blast radius reduced
```

---

# 27. E3 Defense Interpretation

```text
Parameterized Query
→ PREVENT
→ fixes SQL Injection root cause
```

```text
Least Privilege
→ CONTAIN
→ limits read/write blast radius
```

但：

```text
Least Privilege
≠
SQL Injection Fix
```

即使 role 只有：

```text
SELECT devices
SELECT telemetry
```

如果 Injection 仍存在：

```text
all accessible telemetry
```

仍可能遭大量讀取。

---

# 28. E3 PASS Gate

Vulnerable：

```text
INPUT_CHANGES_QUERY_SEMANTICS = YES
```

Fixed：

```text
SAME_INPUT_CHANGES_QUERY = NO
```

Containment：

```text
SENSITIVE_TABLE_READ = DENIED

UNAUTHORIZED_UPDATE = DENIED

UNAUTHORIZED_DROP = DENIED
```

Regression：

```text
NORMAL_DEVICE_SEARCH = PASS
```

---

# 29. Defense-in-Depth Matrix

本表明確區分：

```text
[I] = Lab 中實際實作並驗證

[C] = Conceptual discussion only
```

| Experiment | Prevent | Detect | Contain | Recover |
|---|---|---|---|---|
| E1 ARP/MITM | **[I] TLS + Certificate Validation** / [C] DAI | [C] ARP anomaly monitoring | [C] Network Segmentation | [C] Restore trusted network state |
| E2 Replay | **[I] HMAC + Nonce + Timestamp** | **[I] Invalid signature / duplicate nonce audit** | **[I] Reject request** / [C] revoke device key | [C] Key rotation / session recovery |
| E3 SQLi | **[I] Parameterized Query** | [C] DB/API anomaly monitoring | **[I] Table-level Least Privilege** | [C] DB restore / credential rotation |

因此正式報告不得寫成：

> 本研究已完整建置 Detect / Recover Pipeline。

真正實作範圍主要是：

```text
Prevent
+
部分 Detect Evidence
+
Contain
```

Recover 主要作為架構與 Residual Risk 討論。

---

# 30. Reproducibility

每個實驗必須有固定 Runner：

```text
run_e1
run_e2
run_e3
```

以及：

```text
docker-compose.yml
.env.example
dependency lock
database seed
sample data
```

Runner 流程：

```text
prepare
↓
baseline
↓
controlled test
↓
collect evidence
↓
re-test
↓
print verdict
```

---

# 31. Unified Result Schema

```text
experiment_id
scenario_id
timestamp
attacker_model
trust_boundary
expected_result
actual_result
security_control
evidence_location
verdict
```

Verdict：

```text
PASS
FAIL
PARTIAL
```

---

# 32. Formal Report Structure

## 1. Introduction

說明：

```text
IoT Security
≠
Device-only Security
```

而是跨：

```text
Device
Network
Transport
Application
Data
```

的 Trust Chain。

---

## 2. Assignment Requirement

明確宣告：

```text
Primary Attack
= ARP Spoofing / MITM

Cross-Layer Extensions
= Replay + SQL Injection
```

---

## 3. Architecture

Full-stack IoT Architecture。

---

## 4. Threat Model

包含：

```text
Attacker Position
Capability
Trust Boundary
Assumption
```

---

## 5. Primary Experiment

ARP Spoofing / MITM。

---

## 6. Replay Extension

Message Authentication + Freshness。

---

## 7. SQL Injection Extension

Code/Data Boundary + DB Authorization。

---

## 8. Cross-Layer Analysis

```text
Network Trust
↓
Message Trust
↓
Application/Data Trust
```

---

## 9. Defense-in-Depth

明確區分：

```text
Implemented
vs
Conceptual
```

---

## 10. Residual Risk

包含：

```text
Endpoint Compromise
HMAC Key Leakage
Nonce Cache Restart
Clock Drift
Idempotency
Application-accessible SQL Data
```

---

## 11. Limitations

```text
Controlled Lab
Simulated IoT Device
No public target
No destructive malware
No Internet DDoS
No production credential
```

---

## 12. Conclusion

核心論點：

> IoT Security 是跨層 Trust Management 問題；單一控制只能保護單一 Failure Domain，因此需要 Defense-in-Depth。

---

## 13. References

至少包含：

```text
Course Slides
Assignment #3 Slides
Relevant Protocol / Security References
Real-world IoT Cases actually cited in the report
```

---

# 33. Final Execution Order

```text
P0
E1 Network Feasibility

↓ PASS

P1
Common Baseline

↓

P2
E2 Replay

↓

P3
E3 SQL Injection

↓

P4
E1 Full Primary Experiment

↓

P5
Regression

↓

P6
Evidence Freeze

↓

P7
Report
```

若 P0：

```text
E1_NETWORK_FEASIBILITY = FAIL
```

則：

```text
PRIMARY = E3 SQL Injection
```

若 E3 亦出現不可接受 blocker：

```text
PRIMARY = E2 Replay
```

---

# 34. Freeze Rules

V2.2 後不再新增：

```text
Fourth Attack
New Framework
New Database
New Frontend Requirement
New Protocol
New Real-world Case as formal experiment
```

新想法一律進：

```text
Residual Risk
Future Work
Appendix
```

除非它會推翻：

```text
Experiment Validity
Threat Model
Security Conclusion
```

才允許重新開 Freeze。

---

# 35. Final Acceptance Gates

## E1

```text
E1_NETWORK_FEASIBILITY = PASS

MITM_PATH = VERIFIED

IP_FORWARDING = VERIFIED

TLS_CERT_VALIDATION = VERIFIED

NORMAL_TLS_REGRESSION = PASS
```

---

## E2

```text
RAW_BODY_HMAC = ENABLED

CONSTANT_TIME_COMPARE = ENABLED

EXACT_REPLAY = BLOCKED

MODIFIED_NONCE_WITH_OLD_SIGNATURE = BLOCKED

MODIFIED_TIMESTAMP_WITH_OLD_SIGNATURE = BLOCKED

MODIFIED_BODY_WITH_OLD_SIGNATURE = BLOCKED

ACTION_STATE = UNCHANGED
```

---

## E3

```text
TRUE_RAW_SQL_BASELINE = VERIFIED

QUERY_SEMANTICS_MANIPULATION = VERIFIED

PARAMETERIZED_QUERY = PASS

SENSITIVE_TABLE_READ = DENIED

UNAUTHORIZED_WRITE = DENIED

NORMAL_QUERY_REGRESSION = PASS
```

---

## Documentation

```text
THREAT_MODEL = CONSISTENT

TRUST_BOUNDARIES = EXPLICIT

IMPLEMENTED_VS_CONCEPTUAL = LABELED

RESIDUAL_RISKS = DOCUMENTED

REFERENCES = COMPLETE

EVIDENCE = REPRODUCIBLE
```

---

# 36. Final Freeze Verdict

```text
ARCHITECTURE = FROZEN

PRIMARY_ATTACK = FROZEN

FALLBACK_ORDER = FROZEN

THREAT_MODEL = FROZEN

E1_SECURITY_MODEL = FROZEN

E2_SECURITY_MODEL = FROZEN

E3_SECURITY_MODEL = FROZEN

DEFENSE_IN_DEPTH_SCOPE = FROZEN

EXPERIMENT_COUNT = FROZEN

REPORT_STRUCTURE = FROZEN
```

# FINAL STATUS

```text
IOT_SECURITY_ASSIGNMENT_V2_2
=
FROZEN

IMPLEMENTATION_READINESS
=
YES
```