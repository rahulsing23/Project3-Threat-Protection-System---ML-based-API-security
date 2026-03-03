# 🛡️ Threat Protection System

<div align="center">

![Java](https://img.shields.io/badge/Java-17-orange?style=for-the-badge&logo=java)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.3-brightgreen?style=for-the-badge&logo=springboot)
![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-teal?style=for-the-badge&logo=fastapi)
![Redis](https://img.shields.io/badge/Redis-7.0-red?style=for-the-badge&logo=redis)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-15-blue?style=for-the-badge&logo=postgresql)
![scikit-learn](https://img.shields.io/badge/scikit--learn-1.4.2-orange?style=for-the-badge&logo=scikitlearn)

**A production-style microservices security system that uses Machine Learning to detect and block malicious API requests in real time.**

</div>

---

## 📋 Table of Contents

- [Overview](#-overview)
- [Architecture](#-architecture)
- [Tech Stack](#-tech-stack)
- [Services](#-services)
- [How It Works](#-how-it-works)
- [20 ML Features](#-20-ml-features)
- [Threat Actions](#-threat-actions)
- [Key Features](#-key-features)
- [Project Structure](#-project-structure)
- [Prerequisites](#-prerequisites)
- [Running Locally](#-running-locally)
- [API Reference](#-api-reference)
- [Testing with Postman](#-testing-with-postman)
- [Monitoring](#-monitoring)

---

## 🔍 Overview

The Threat Protection System sits between the internet and your application. Every HTTP request is analyzed by a Machine Learning model before reaching the business logic. The system can:

- ✅ **Allow** safe requests through instantly
- 👀 **Monitor** suspicious requests silently
- 🧩 **Challenge** medium-risk users with CAPTCHA
- ❌ **Block** malicious requests with 403 response
- 🚫 **Auto-ban** IPs that score above 95% threat probability

---

## 🏗️ Architecture

```
                         ┌─────────────────────────────────────┐
                         │           INTERNET                   │
                         └──────────────┬──────────────────────┘
                                        │ Every HTTP Request
                                        ▼
                         ┌─────────────────────────────────────┐
                         │       API GATEWAY  :8080             │
                         │   Spring Cloud Gateway               │
                         │                                      │
                         │  1. Check Redis Blacklist            │
                         │  2. Extract 20 ML Features           │
                         │  3. Call Threat Service              │
                         │  4. ALLOW / MONITOR / CAPTCHA /BLOCK │
                         └──────────────┬──────────────────────┘
                                        │
                    ┌───────────────────┼────────────────────┐
                    │                   │                     │
                    ▼                   ▼                     ▼
          ┌──────────────┐   ┌──────────────────┐   ┌──────────────┐
          │    REDIS      │   │  THREAT SERVICE   │   │  AUTH SERVICE│
          │    :6379      │   │     :8081         │   │    :8082     │
          │               │   │  Spring Boot      │   │ Spring Boot  │
          │ • Blacklist   │   │                   │   │ + Security   │
          │ • Counters    │   │ 1. Call ML Service│   │              │
          │ • Sessions    │   │ 2. Business Rules │   │ • Login      │
          │ • Bypass Tkns │   │ 3. Persist logs   │   │ • Data API   │
          └──────────────┘   │ 4. Auto-blacklist  │   │ • CAPTCHA    │
                              └────────┬─────────┘   └──────────────┘
                                       │
                                       ▼
                         ┌─────────────────────────────────────┐
                         │         ML SERVICE  :8090            │
                         │         Python FastAPI               │
                         │                                      │
                         │  Random Forest Model                 │
                         │  → Returns probability 0.0 - 1.0    │
                         │  Fallback: weighted scoring          │
                         └──────────────┬──────────────────────┘
                                        │
                                        ▼
                         ┌─────────────────────────────────────┐
                         │        POSTGRESQL  :5432             │
                         │  • threat_logs (all requests)        │
                         │  • ip_blacklist                      │
                         └─────────────────────────────────────┘
```

---

## 🛠️ Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| **API Gateway** | Java 17, Spring Cloud Gateway, WebFlux | Reactive entry point, filter all traffic |
| **Threat Service** | Java 17, Spring Boot 3.2, JPA, Resilience4j | ML orchestration, business rules, persistence |
| **ML Service** | Python 3.11, FastAPI, scikit-learn, NumPy | Random Forest threat prediction |
| **Auth Service** | Java 17, Spring Boot 3.2, Spring Security | Business application, login, CAPTCHA |
| **Cache** | Redis 7.0 | Fast counters, blacklist, session tracking, bypass tokens |
| **Database** | PostgreSQL 15 | Permanent threat logs, IP blacklist, ML training data |
| **Monitoring** | Prometheus, Micrometer | Metrics from all services |
| **Build** | Maven 3.9, pip | Dependency management |

---

## 🔧 Services

### 1. API Gateway `:8080`
> The single entry point. No request reaches the application without passing through here.

- Checks Redis blacklist on every request (~1ms)
- Extracts 20 ML features in parallel using reactive `Mono.zip()`
- Injects `X-Threat-Level`, `X-Threat-Action`, `X-Threat-Probability`, `X-Request-ID` headers
- Routes: `ALLOW` → forward | `MONITOR` → forward with headers | `CAPTCHA` → 307 redirect | `BLOCK` → 403

### 2. Threat Service `:8081`
> The decision-making center. Orchestrates ML call and applies business rules.

- Calls ML Service and receives threat probability
- Applies 5 business rule overrides on top of ML result
- Persists all 20 features + result to PostgreSQL for every request
- Auto-blacklists IPs scoring ≥ 0.95 probability for 24 hours
- Syncs blacklist from PostgreSQL → Redis every 5 minutes

### 3. ML Service `:8090`
> The AI brain. Returns a threat probability score for 20 input features.

- Random Forest Classifier (200 estimators, depth 12, balanced class weights)
- Falls back to deterministic weighted scoring if model file not found
- Supports live retraining via `POST /train` with labeled data
- Hot-reloads retrained model without service restart

### 4. Auth Service `:8082`
> The actual business application sitting behind all security layers.

- Handles login (`POST /api/auth/login`)
- Serves protected data (`GET /api/data`)
- Reads threat headers and logs extra detail for monitored requests
- Issues CAPTCHA bypass tokens after successful CAPTCHA verification

---

## ⚙️ How It Works

### Normal Request Flow
```
GET /api/data (normal browser)
  │
  ├─ Redis blacklist check        → not banned (1ms)
  ├─ Extract 20 features          → low scores
  ├─ ML prediction                → probability = 0.08
  ├─ Business rules               → no override
  ├─ Action = ALLOW
  └─ Forward to Auth Service → 200 OK
     Headers: X-Threat-Level: LOW THREAT
              X-Threat-Probability: 0.08
              X-Threat-Action: ALLOW
```

### SQL Injection Attack
```
GET /api/data?id=1' OR 1=1--
  │
  ├─ Redis blacklist check        → not banned
  ├─ request_pattern_score = 1.0  → SQL injection detected
  ├─ ML prediction                → probability = 0.94
  ├─ Business rules               → no override needed
  ├─ Action = BLOCK
  └─ Return 403 Forbidden
     Body: { "action": "BLOCK", "message": "Request blocked" }
```

### DDoS / Burst Attack
```
1001 requests in 10 seconds from same IP
  │
  ├─ burst_request_count = 1001
  ├─ Business Rule 1 fires        → extreme burst threshold exceeded
  ├─ Force BLOCK (skip ML)        → probability = 0.90
  └─ Return 403 Forbidden
     (No ML call made — pure Redis counter check)
```

### Auto Blacklist
```
Any request scoring probability ≥ 0.95
  │
  ├─ ML returns 0.96
  ├─ ThreatEvaluationService.autoBlacklist() fires
  ├─ PostgreSQL: INSERT ip_blacklist (expires +24h)
  ├─ Redis: SADD gateway:blacklist {ip}
  └─ All future requests from this IP
     → blocked in 1ms (Redis SET check)
     → no ML evaluation needed
```

---

## 📊 20 ML Features

| # | Feature | How Computed | Detects |
|---|---|---|---|
| 1 | `request_count` | Redis INCR (TTL 1hr) | High volume attackers |
| 2 | `burst_request_count` | Redis INCR (TTL 10s) | DDoS, flooding |
| 3 | `error_rate` | Error counter ÷ total | Scanning, fuzzing |
| 4 | `failed_login_attempts` | Redis counter (TTL 30min) | Brute force |
| 5 | `unique_ips` | HyperLogLog estimate | Distributed attacks |
| 6 | `unusual_hour_access` | 1 if hour is 1AM-5AM | Off-hours attacks |
| 7 | `payload_size` | Content-Length header | Oversized payloads |
| 8 | `avg_response_time` | Measured per request | Slowloris attacks |
| 9 | `session_duration` | Current time - session start | Session hijacking |
| 10 | `token_age` | JWT `iat` claim parsed | Expired/stolen tokens |
| 11 | `api_endpoint_risk_score` | Lookup table by path | High-risk endpoint targeting |
| 12 | `request_entropy` | Shannon entropy on query params | Randomized bot params |
| 13 | `request_pattern_score` | Regex: SQLi, XSS, path traversal | Injection attacks |
| 14 | `device_risk_score` | User-Agent classification | Bots, scripts, crawlers |
| 15 | `bot_probability_score` | device_risk × burst rate | Automated traffic |
| 16 | `ip_reputation_score` | Placeholder (AbuseIPDB ready) | Known bad IPs |
| 17 | `user_behavior_deviation` | Placeholder (baseline model ready) | Anomalous behavior |
| 18 | `proxy_usage_flag` | X-Forwarded-For / Via header | Hidden origin |
| 19 | `vpn_usage_flag` | Datacenter IP range check | VPN / datacenter traffic |
| 20 | `geo_distance` | Placeholder (MaxMind GeoIP ready) | Impossible travel |

---

## 🎯 Threat Actions

| ML Probability | Threat Level | Action | What Happens |
|---|---|---|---|
| `0.00 – 0.39` | 🟢 LOW THREAT | **ALLOW** | Request forwarded normally |
| `0.40 – 0.59` | 🟡 MEDIUM THREAT | **MONITOR** | Forwarded + extra logging |
| `0.60 – 0.79` | 🟠 HIGH THREAT | **CAPTCHA** | 307 redirect to CAPTCHA page |
| `0.80 – 1.00` | 🔴 CRITICAL THREAT | **BLOCK** | 403 Forbidden returned |
| `≥ 0.95` | 🔴 CRITICAL THREAT | **BLOCK + BAN** | Blocked + IP banned 24 hours |

---

## ✨ Key Features

### 🔄 Circuit Breaker (Resilience4j)
If the ML service goes down, the Threat Service automatically switches to rule-based scoring. No service crashes, no requests fail.
```
ML Service down → Circuit opens → ruleBasedFallback() → system keeps running
```

### ⚡ Parallel Feature Extraction
All 7 Redis calls in the gateway run simultaneously using reactive `Mono.zip()`. Total Redis time = slowest single call (~1ms), not sum of all calls.

### 🔁 Dual-Layer Blacklist
```
Redis SET  → O(1) lookup, ~1ms, checked on every request
PostgreSQL → source of truth, survives Redis restart
Sync       → every 5 minutes via @Scheduled
Immediate  → SADD to Redis on every manual ban (no wait)
```

### 🧠 Self-Improving ML Model
1. Every request saved to PostgreSQL with all 20 features
2. Security analysts label records as threat/safe
3. Call `POST /train` with labeled data
4. New Random Forest model trained + saved + hot-reloaded
5. No restart needed — better predictions from next request

### ⏰ Automatic TTL Expiry
Redis counters expire automatically — no cleanup code needed:
```
gateway:burst:{ip}        → expires in 10 seconds
gateway:login_fail:{ip}   → expires in 30 minutes
gateway:req:{ip}          → expires in 1 hour
gateway:bypass:{token}    → expires in 5 minutes
```

---

## 📁 Project Structure

```
threat-protection-system/
│
├── README.md
├── .gitignore
│
├── api-gateway/                          # Spring Cloud Gateway :8080
│   ├── Dockerfile
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/threatprotection/gateway/
│       │   ├── ApiGatewayApplication.java
│       │   ├── filter/
│       │   │   ├── ThreatProtectionFilter.java   # runs on every request
│       │   │   └── RequestFeatureExtractor.java  # builds 20 features
│       │   ├── service/
│       │   │   └── RedisCounterService.java      # all Redis operations
│       │   ├── client/
│       │   │   └── ThreatServiceClient.java      # calls threat-service
│       │   ├── config/
│       │   │   ├── RedisConfig.java
│       │   │   └── GatewayConfig.java
│       │   ├── model/
│       │   │   ├── ThreatRequest.java
│       │   │   └── ThreatResponse.java
│       │   └── exception/
│       │       └── FallbackController.java
│       └── resources/
│           ├── application.yml
│           ├── application-dev.yml
│           └── application-prod.yml
│
├── threat-service/                       # Spring Boot :8081
│   ├── Dockerfile
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/threatprotection/threat/
│       │   ├── ThreatServiceApplication.java
│       │   ├── controller/
│       │   │   └── ThreatController.java         # REST endpoints
│       │   ├── service/
│       │   │   ├── ThreatEvaluationService.java  # core orchestrator
│       │   │   └── IpBlacklistService.java       # blacklist management
│       │   ├── client/
│       │   │   └── MlServiceClient.java          # calls ML service (CB+Retry)
│       │   ├── entity/
│       │   │   ├── ThreatLog.java                # all 20 features per request
│       │   │   └── IpBlacklist.java              # banned IPs
│       │   ├── repository/
│       │   │   ├── ThreatLogRepository.java
│       │   │   └── IpBlacklistRepository.java
│       │   ├── model/
│       │   │   ├── ThreatFeatureRequest.java
│       │   │   ├── MlServiceResponse.java
│       │   │   └── ThreatEvaluationResponse.java
│       │   ├── config/
│       │   │   ├── RedisConfig.java
│       │   │   └── ThreatServiceConfig.java
│       │   └── exception/
│       │       └── GlobalExceptionHandler.java
│       └── resources/
│           ├── application.yml
│           ├── application-dev.yml               # H2 in-memory DB
│           └── application-prod.yml
│
├── auth-service/                         # Spring Boot :8082
│   ├── Dockerfile
│   ├── pom.xml
│   └── src/main/
│       ├── java/com/threatprotection/auth/
│       │   ├── AuthServiceApplication.java
│       │   ├── controller/
│       │   │   └── AuthController.java           # login, data, captcha
│       │   ├── service/
│       │   │   └── CaptchaService.java           # reCAPTCHA + bypass tokens
│       │   ├── filter/
│       │   │   └── ThreatHeaderLoggingFilter.java # reads threat headers
│       │   ├── model/
│       │   │   ├── LoginRequest.java
│       │   │   └── ThreatContext.java            # parses X-Threat-* headers
│       │   └── config/
│       │       ├── AuthServiceConfig.java
│       │       └── SecurityConfig.java
│       └── resources/
│           ├── application.yml
│           ├── application-dev.yml
│           └── application-prod.yml
│
├── ml-service/                           # Python FastAPI :8090
│   ├── Dockerfile
│   ├── requirements.txt
│   ├── .env.example
│   ├── main.py                           # FastAPI entry point
│   ├── models/                           # trained model stored here
│   └── app/
│       ├── api/
│       │   └── routes.py                 # /predict /train /health
│       ├── core/
│       │   ├── config.py                 # settings from env vars
│       │   ├── classifier.py             # probability → action mapping
│       │   └── lifespan.py              # startup model loader
│       ├── schemas/
│       │   └── threat_schema.py          # Pydantic request/response models
│       └── services/
│           └── model_service.py          # RandomForest + fallback + retraining
│
└── monitoring/
    └── prometheus.yml                    # scrape configs for all services
```

---

## ✅ Prerequisites

- **Java 17** — [Download](https://adoptium.net/temurin/releases/?version=17)
- **Maven 3.9** — [Download](https://maven.apache.org/download.cgi)
- **Python 3.11** — [Download](https://www.python.org/downloads/)
- **Redis** — [Download for Windows](https://github.com/microsoftarchive/redis/releases)
- **PostgreSQL 15** (optional — dev mode uses H2 in-memory) — [Download](https://www.postgresql.org/download/)

---

## 🚀 Running Locally

Start services in this order — each needs the previous one running first.

### Terminal 1 — ML Service
```powershell
cd ml-service
python -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
mkdir models
uvicorn main:app --host 0.0.0.0 --port 8090 --reload
```
✅ Verify: `GET http://localhost:8090/health`

---

### Terminal 2 — Threat Service
```powershell
cd threat-service
mvn spring-boot:run "-Dspring-boot.run.profiles=dev"
```
✅ Verify: `GET http://localhost:8081/threat/health`

> Dev profile uses **H2 in-memory database** — no PostgreSQL needed.

---

### Terminal 3 — Auth Service
```powershell
cd auth-service
mvn spring-boot:run "-Dspring-boot.run.profiles=dev"
```
✅ Verify: `GET http://localhost:8082/actuator/health`

---

### Terminal 4 — API Gateway
```powershell
cd api-gateway
mvn spring-boot:run "-Dspring-boot.run.profiles=dev"
```
✅ Verify: `GET http://localhost:8080/actuator/health`

---

### All Services Running

| Service | URL | Health Check |
|---|---|---|
| API Gateway | http://localhost:8080 | /actuator/health |
| Threat Service | http://localhost:8081 | /threat/health |
| Auth Service | http://localhost:8082 | /actuator/health |
| ML Service | http://localhost:8090 | /health |

```powershell
# Verify all ports are listening
netstat -ano | findstr "8080 8081 8082 8090"
```

---

## 📡 API Reference

### API Gateway `:8080`

| Method | Endpoint | Description | Headers |
|---|---|---|---|
| `GET` | `/api/data` | Protected business data | Threat headers injected |
| `POST` | `/api/auth/login` | User login | Body: `{username, password}` |
| `GET` | `/actuator/health` | Gateway health | — |

---

### Threat Service `:8081`

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/threat/evaluate` | Evaluate 20 features → return action |
| `GET` | `/threat/analytics?hours=24` | Threat statistics for last N hours |
| `POST` | `/threat/blacklist/{ip}` | Ban an IP address |
| `DELETE` | `/threat/blacklist/{ip}` | Unban an IP address |
| `GET` | `/threat/health` | Service health |

**Analytics Response Example:**
```json
{
  "period_hours": 24,
  "by_threat_level": {
    "LOW THREAT": 150,
    "MEDIUM THREAT": 23,
    "HIGH THREAT": 8,
    "CRITICAL THREAT": 3
  },
  "by_action": { "ALLOW": 150, "MONITOR": 23, "CAPTCHA": 5, "BLOCK": 6 },
  "total_blocked": 6,
  "total_captcha": 5,
  "top_threat_ips": [
    { "ip": "1.2.3.4", "count": 5 }
  ]
}
```

---

### ML Service `:8090`

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/predict` | Get threat probability for 20 features |
| `POST` | `/train` | Retrain model with labeled samples |
| `GET` | `/health` | Service health + model status |
| `GET` | `/model/info` | Model version, thresholds, feature list |

**Predict Request Example:**
```json
{
  "request_count": 5,
  "error_rate": 0.0,
  "avg_response_time": 120,
  "payload_size": 512,
  "unique_ips": 10,
  "failed_login_attempts": 0,
  "unusual_hour_access": 0,
  "geo_distance": 0,
  "session_duration": 30.0,
  "api_endpoint_risk_score": 0.3,
  "token_age": 1.0,
  "request_entropy": 0.1,
  "burst_request_count": 3,
  "device_risk_score": 0.05,
  "ip_reputation_score": 0.1,
  "user_behavior_deviation": 0.0,
  "request_pattern_score": 0.0,
  "proxy_usage_flag": 0,
  "vpn_usage_flag": 0,
  "bot_probability_score": 0.02
}
```

**Predict Response Example:**
```json
{
  "threatProbability": 0.082,
  "threatLevel": "LOW THREAT",
  "action": "ALLOW",
  "modelVersion": "fallback-v1",
  "usedFallback": true
}
```

---

### Auth Service `:8082`

| Method | Endpoint | Description |
|---|---|---|
| `POST` | `/api/auth/login` | Login with username/password |
| `GET` | `/api/data` | Protected business endpoint |
| `GET` | `/captcha/challenge` | CAPTCHA challenge page |
| `POST` | `/captcha/verify` | Verify CAPTCHA + issue bypass token |

---

## 🧪 Testing with Postman

### Setup Environment

Create a new Postman environment called `ThreatProtection`:

| Variable | Value |
|---|---|
| `gateway_url` | `http://localhost:8080` |
| `threat_url` | `http://localhost:8081` |
| `auth_url` | `http://localhost:8082` |
| `ml_url` | `http://localhost:8090` |
| `bypass_token` | *(auto-filled by test script)* |

---

### Key Test Cases

#### ✅ Normal Request
```
GET {{gateway_url}}/api/data
```
Expected response header: `X-Threat-Action: ALLOW`

#### 🤖 Bot Detection
```
GET {{gateway_url}}/api/data
Header → User-Agent: python-requests/2.28.0
```
Expected response header: `X-Threat-Action: MONITOR`

#### 💉 SQL Injection
```
GET {{gateway_url}}/api/data?id=1' OR 1=1--
```
Expected: `403 Forbidden` — `{"action":"BLOCK"}`

#### 🔒 IP Blacklist
```
POST {{threat_url}}/threat/blacklist/10.99.99.99?reason=Test&expireHours=1
GET  {{gateway_url}}/api/data  [Header: X-Forwarded-For: 10.99.99.99]
```
Expected: `403 Forbidden`

#### 🧠 Direct ML Prediction
```
POST {{ml_url}}/predict
Body: { high threat feature values }
```
Expected: `{"action":"BLOCK","threatProbability":0.95+}`

---

### Response Headers to Watch

Every request through port `8080` will have these headers:

| Header | Example Value | Meaning |
|---|---|---|
| `X-Request-ID` | `7f3a1b2c-...` | Unique ID — trace in PostgreSQL |
| `X-Threat-Level` | `LOW THREAT` | Classification result |
| `X-Threat-Probability` | `0.082` | ML confidence score |
| `X-Threat-Action` | `ALLOW` | Decision taken |

---

## 📈 Monitoring

### Start Prometheus

1. Download from https://prometheus.io/download/
2. Replace `prometheus.yml` with the config in `monitoring/prometheus.yml`
3. Run:
```powershell
cd C:\prometheus
.\prometheus.exe --config.file=prometheus.yml
```
4. Open: http://localhost:9090

### Metrics Endpoints

| Service | Metrics URL |
|---|---|
| API Gateway | http://localhost:8080/actuator/prometheus |
| Threat Service | http://localhost:8081/actuator/prometheus |
| Auth Service | http://localhost:8082/actuator/prometheus |
| ML Service | http://localhost:8090/metrics |

### Useful Prometheus Queries

```promql
# Request rate through gateway
rate(http_server_requests_seconds_count{job="api-gateway"}[1m])

# All services status (1=UP, 0=DOWN)
up

# JVM memory usage
jvm_memory_used_bytes{job="threat-service"}
```

---

## 🗃️ Redis Keys Reference

| Key Pattern | TTL | Purpose |
|---|---|---|
| `gateway:req:{ip}` | 1 hour | Total request count per IP |
| `gateway:burst:{ip}` | 10 seconds | Burst window counter |
| `gateway:login_fail:{ip}` | 30 minutes | Failed login attempts |
| `gateway:err:{ip}` | 5 minutes | Error rate counter |
| `gateway:session:{sid}` | 24 hours | Session start timestamp |
| `gateway:unique_ips` | No TTL | HyperLogLog of all IPs |
| `gateway:blacklist` | No TTL | SET of banned IP addresses |
| `gateway:whitelist` | No TTL | SET of trusted IP addresses |
| `gateway:bypass:{token}` | 5 minutes | CAPTCHA bypass tokens (single use) |

---

## 🗄️ Database Schema

### `threat_logs` table
Stores every request with all 20 ML features and the threat decision.
Used for analytics and ML model retraining.

### `ip_blacklist` table
Stores banned IP addresses with reason, expiry time, and who banned them.
Synced to Redis every 5 minutes as source of truth.

---

## 🤝 Contributing

This is an interview/learning project. Feel free to fork and extend with:

- [ ] Real JWT authentication
- [ ] MaxMind GeoIP integration (`geo_distance` feature)
- [ ] AbuseIPDB integration (`ip_reputation_score` feature)
- [ ] Grafana dashboard
- [ ] Kubernetes deployment manifests
- [ ] Rate limiting per API key
- [ ] Webhook alerts for critical threats

---

## 📄 License

MIT License — free to use for learning and interview purposes.

---

<div align="center">
Built with ☕ Java + 🐍 Python
</div>
