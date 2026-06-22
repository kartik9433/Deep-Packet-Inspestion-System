# DPI Engine - Deep Packet Inspection System (Spring Boot + React)

This document explains **everything** about this project — from basic networking concepts to the complete code architecture. After reading this, you should understand exactly how packets flow through the system without needing to read the code.

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [Networking Background](#2-networking-background)
3. [Project Overview](#3-project-overview)
4. [Tech Stack](#4-tech-stack)
5. [File Structure](#5-file-structure)
6. [The Journey of a Packet](#6-the-journey-of-a-packet)
7. [Deep Dive: Backend Components](#7-deep-dive-backend-components)
8. [Deep Dive: Frontend Pages](#8-deep-dive-frontend-pages)
9. [REST API Reference](#9-rest-api-reference)
10. [How SNI Extraction Works](#10-how-sni-extraction-works)
11. [How Blocking Works](#11-how-blocking-works)
12. [Authentication & Security](#12-authentication--security)
13. [Building and Running](#13-building-and-running)
14. [Environment Configuration](#14-environment-configuration)
15. [Understanding the Output](#15-understanding-the-output)

---

## 1. What is DPI?

**Deep Packet Inspection (DPI)** is a technology used to examine the contents of network packets as they pass through a checkpoint. Unlike simple firewalls that only look at packet headers (source/destination IP), DPI looks *inside* the packet payload.

### Real-World Uses:
- **ISPs**: Throttle or block certain applications (e.g., BitTorrent)
- **Enterprises**: Block social media on office networks
- **Parental Controls**: Block inappropriate websites
- **Security**: Detect malware or intrusion attempts

### What Our DPI Engine Does:
```
User Traffic (PCAP) → [Spring Boot DPI Engine] → Filtered Traffic (PCAP)
                                ↓
                       - Identifies apps (YouTube, Facebook, etc.)
                       - Blocks based on rules
                       - Tracks connections
                       - Exposes a REST API
                       - Shows results in a React dashboard
```

---

## 2. Networking Background

### The Network Stack (Layers)

When you visit a website, data travels through multiple "layers":

```
┌─────────────────────────────────────────────────────────┐
│ Layer 7: Application    │ HTTP, TLS, DNS               │
├─────────────────────────────────────────────────────────┤
│ Layer 4: Transport      │ TCP (reliable), UDP (fast)   │
├─────────────────────────────────────────────────────────┤
│ Layer 3: Network        │ IP addresses (routing)       │
├─────────────────────────────────────────────────────────┤
│ Layer 2: Data Link      │ MAC addresses (local network)│
└─────────────────────────────────────────────────────────┘
```

### A Packet's Structure

Every network packet is like a **Russian nesting doll** — headers wrapped inside headers:

```
┌──────────────────────────────────────────────────────────────────┐
│ Ethernet Header (14 bytes)                                       │
│ ┌──────────────────────────────────────────────────────────────┐ │
│ │ IP Header (20 bytes)                                         │ │
│ │ ┌──────────────────────────────────────────────────────────┐ │ │
│ │ │ TCP Header (20 bytes)                                    │ │ │
│ │ │ ┌──────────────────────────────────────────────────────┐ │ │ │
│ │ │ │ Payload (Application Data)                           │ │ │ │
│ │ │ │ e.g., TLS Client Hello with SNI                      │ │ │ │
│ │ │ └──────────────────────────────────────────────────────┘ │ │ │
│ │ └──────────────────────────────────────────────────────────┘ │ │
│ └──────────────────────────────────────────────────────────────┘ │
└──────────────────────────────────────────────────────────────────┘
```

### The Five-Tuple

A **connection** (or "flow") is uniquely identified by 5 values:

| Field | Example | Purpose |
|-------|---------|---------|
| Source IP | 192.168.1.100 | Who is sending |
| Destination IP | 172.217.14.206 | Where it's going |
| Source Port | 54321 | Sender's application identifier |
| Destination Port | 443 | Service being accessed (443 = HTTPS) |
| Protocol | TCP (6) | TCP or UDP |

**Why is this important?**
- All packets with the same 5-tuple belong to the same connection
- If we block one packet of a connection, we block all of them
- This is how we "track" conversations between computers

### What is SNI?

**Server Name Indication (SNI)** is part of the TLS/HTTPS handshake. When you visit `https://www.youtube.com`:

1. Your browser sends a "Client Hello" message
2. This message includes the domain name in **plaintext** (not encrypted yet!)
3. The server uses this to know which certificate to send

```
TLS Client Hello:
├── Version: TLS 1.2
├── Random: [32 bytes]
├── Cipher Suites: [list]
└── Extensions:
    └── SNI Extension:
        └── Server Name: "www.youtube.com"  ← We extract THIS!
```

**This is the key to DPI**: Even though HTTPS is encrypted, the domain name is visible in the first packet!

---

## 3. Project Overview

### What This Project Does

```
┌─────────────┐     ┌──────────────────────┐     ┌─────────────┐
│  PCAP File  │     │  Spring Boot Backend │     │ React       │
│  (upload    │ ──► │                      │ ──► │ Dashboard   │
│   via UI)   │     │  - Parse PCAP        │     │             │
└─────────────┘     │  - Classify traffic  │     │ - Stats     │
                    │  - Track connections │     │ - Rules     │
                    │  - Apply block rules │     │ - Packets   │
                    │  - Expose REST API   │     │ - Conns     │
                    └──────────────────────┘     └─────────────┘
```

### Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  React Frontend (Vite)                  │
│  Login │ Signup │ Dashboard │ Packets │ Connections │ Rules │
└───────────────────────┬─────────────────────────────────┘
                        │  HTTP / REST (axios)
                        ▼
┌─────────────────────────────────────────────────────────┐
│             Spring Boot Backend (port 9090)             │
│                                                         │
│  AuthController   PacketController   RuleController     │
│  ConnectionController                                   │
│           │               │                │            │
│     AuthService     DpiEngineService  RuleManagerService│
│                           │                             │
│               PacketParserService                       │
│               SniExtractorService                       │
│               ConnectionTrackerService                  │
│               DpiStats                                  │
└───────────────────────┬─────────────────────────────────┘
                        │  JPA / Hibernate
                        ▼
              ┌──────────────────┐
              │  MySQL Database  │
              │   (dpi_db)       │
              └──────────────────┘
```

---

## 4. Tech Stack

| Layer | Technology |
|-------|-----------|
| Backend Framework | Spring Boot 3.2 (Java 21) |
| REST API | Spring Web (MVC) |
| Database ORM | Spring Data JPA + Hibernate |
| Database | MySQL 8 |
| Authentication | Spring Security + JWT (jjwt 0.12.7) |
| Config Management | spring-dotenv (`.env` file) |
| Frontend | React 19 + Vite |
| Routing | React Router DOM v7 |
| HTTP Client | Axios |
| UI Components | Bootstrap 5 + Lucide React icons |
| Charts | Recharts |
| Build | Maven (backend), Vite (frontend) |

---

## 5. File Structure

```
springboot-dpi/
│
├── src/
│   ├── main/
│   │   ├── java/com/dpi/
│   │   │   │
│   │   │   ├── controller/                  # REST API endpoints
│   │   │   │   ├── AuthController.java      # /auth/login, /auth/signup
│   │   │   │   ├── PacketController.java    # /api/packets/*
│   │   │   │   ├── RuleController.java      # /api/rules/*
│   │   │   │   └── ConnectionController.java # /api/connections/*
│   │   │   │
│   │   │   ├── service/                     # Business logic
│   │   │   │   ├── DpiEngineService.java    # ★ CORE: PCAP reading + packet flow
│   │   │   │   ├── PacketParserService.java # Ethernet/IP/TCP/UDP parsing
│   │   │   │   ├── SniExtractorService.java # TLS SNI + HTTP Host extraction
│   │   │   │   ├── RuleManagerService.java  # Block/allow rules engine
│   │   │   │   └── ConnectionTrackerService.java # Flow state management
│   │   │   │
│   │   │   ├── model/                       # Domain objects
│   │   │   │   ├── ParsedPacket.java        # A fully decoded packet
│   │   │   │   ├── Connection.java          # A tracked network flow
│   │   │   │   ├── FiveTuple.java           # src_ip:port → dst_ip:port + proto
│   │   │   │   ├── AppType.java             # Enum: YOUTUBE, FACEBOOK, DNS, ...
│   │   │   │   ├── ConnectionState.java     # Enum: ACTIVE, CLASSIFIED, BLOCKED
│   │   │   │   ├── PacketAction.java        # Enum: FORWARD, DROP, LOG_ONLY
│   │   │   │   ├── BlockingRule.java        # JPA entity for persistent rules
│   │   │   │   └── DpiStats.java            # Thread-safe counters + snapshot
│   │   │   │
│   │   │   ├── dto/                         # API request/response shapes
│   │   │   │   ├── LoginRequestDto.java
│   │   │   │   ├── LoginResponseDto.java
│   │   │   │   ├── SignupRequestDto.java
│   │   │   │   └── SignupResponseDto.java
│   │   │   │
│   │   │   ├── security/                    # Auth & JWT
│   │   │   │   ├── WebSecurityConfig.java   # CORS, route protection
│   │   │   │   ├── JwtAuthFilter.java       # Validates Bearer tokens on each request
│   │   │   │   ├── AuthService.java         # Login / signup logic
│   │   │   │   ├── AuthUtil.java            # JWT creation & validation
│   │   │   │   └── CustomUserDetailService.java
│   │   │   │
│   │   │   ├── repository/                  # Spring Data JPA repos
│   │   │   │   ├── UserRepository.java
│   │   │   │   ├── ConnectionRepository.java
│   │   │   │   └── BlockingRuleRepository.java
│   │   │   │
│   │   │   ├── config/                      # Spring configuration beans
│   │   │   │   ├── AppConfig.java
│   │   │   │   └── DpiConfig.java           # DPI engine tuning (queue size, threads)
│   │   │   │
│   │   │   └── PacketAnalyzerApplication.java  # main()
│   │   │
│   │   └── resources/
│   │       └── application.properties       # All values read from .env
│   │
│   └── test/
│       └── java/com/dpi/DpiEngineTests.java
│
├── src/                                     # React Frontend (Vite)
│   ├── api/
│   │   ├── axiosConfig.js                   # Base URL + auth header injection
│   │   ├── Authapi.js                       # login(), signup()
│   │   ├── packetApi.js                     # analyzePcap(), getStatus(), getReport()
│   │   ├── ruleApi.js                       # blockIp(), blockApp(), blockDomain(), ...
│   │   └── connectionApi.js                 # getConnections(), getStats(), ...
│   │
│   ├── components/
│   │   ├── Navbar.jsx
│   │   ├── Sidebar.jsx
│   │   ├── StatsCard.jsx
│   │   └── ProtectedRoute.jsx               # Redirects to /login if no token
│   │
│   ├── pages/
│   │   ├── Login.jsx
│   │   ├── Signup.jsx
│   │   ├── Dashboard.jsx                    # Stats overview + charts
│   │   ├── PacketAnalysis.jsx               # Upload PCAP, view results
│   │   ├── Connections.jsx                  # Browse tracked flows
│   │   └── Rules.jsx                        # Manage block rules
│   │
│   ├── App.jsx                              # Router setup (protected routes)
│   ├── main.jsx
│   └── index.css
│
├── .env                                     # Environment variables (never commit)
├── vite.config.js
└── pom.xml
```

---

## 6. The Journey of a Packet

Let's trace a single packet from upload to decision inside `DpiEngineService.java`:

### Step 1: Upload PCAP via API

```
POST /api/packets/analyze
Content-Type: multipart/form-data
file: capture.pcap
```

`PacketController.analyzePcap()` saves the file to a temp path, then calls:

```java
dpiEngine.processFile(tempInput.toString(), tempOutput.toString());
```

---

### Step 2: Read PCAP Global Header

```java
byte[] globalHdr = fis.readNBytes(24);  // PCAP_GLOBAL_HDR_LEN
PcapGlobalHeader header = parsePcapGlobalHeader(globalHdr);
```

**PCAP File Format:**
```
┌────────────────────────────┐
│ Global Header (24 bytes)   │  ← magic, version, snapLen, linkType
├────────────────────────────┤
│ Packet Header (16 bytes)   │  ← timestamp, incl_len, orig_len
│ Packet Data (variable)     │  ← raw network bytes
├────────────────────────────┤
│ Packet Header (16 bytes)   │
│ Packet Data (variable)     │
└────────────────────────────┘
```

The magic number tells us byte order:
- `0xD4C3B2A1` → little-endian (most common, Wireshark default)
- `0xA1B2C3D4` → big-endian

---

### Step 3: Read Each Packet in a Loop

```java
byte[] pktHdr = new byte[16];
while (fis.read(pktHdr) == 16) {
    PcapPacketHeader ph = parsePcapPacketHeader(pktHdr, header.swapBytes());
    byte[] rawData = fis.readNBytes(ph.inclLen());
    // process rawData ...
}
```

---

### Step 4: Parse Protocol Layers (`PacketParserService`)

```java
ParsedPacket parsed = parserService.parse(rawData, ph.tsSec(), ph.tsUsec());
```

What gets extracted:

```
raw bytes:
[0-13]   Ethernet Header  → srcMac, dstMac, etherType
[14-33]  IP Header        → srcIp, dstIp, protocol, ttl
[34-53]  TCP/UDP Header   → srcPort, dstPort, tcpFlags
[54+]    Payload          → payloadPreview (first N bytes)

After parsing:
parsed.srcIp        = "192.168.1.100"
parsed.dstIp        = "172.217.14.206"
parsed.srcPort      = 54321
parsed.dstPort      = 443
parsed.protocol     = 6 (TCP)
parsed.hasTcp       = true
parsed.tcpFlags     = 0x02 (SYN)
parsed.payloadPreview = byte[]  // for SNI extraction
```

---

### Step 5: Look Up Connection (`ConnectionTrackerService`)

```java
FiveTuple tuple = parsed.toFiveTuple();
Connection conn = connTracker.getOrCreateConnection(tuple);
```

- If this 5-tuple was seen before → return existing `Connection`
- If new → create a fresh `Connection` in state `ACTIVE`
- All packets of the same TCP session share one `Connection` object

---

### Step 6: Fast-Path for Known Connections

```java
if (conn.getState() == ConnectionState.BLOCKED) {
    return PacketAction.DROP;  // no need to re-inspect
}
if (conn.getState() == ConnectionState.CLASSIFIED) {
    pkt.setAppType(conn.getAppType());  // reuse previous classification
}
```

---

### Step 7: Extract SNI — Deep Packet Inspection (`SniExtractorService`)

```java
if (pkt.isHasTcp() && pkt.getDstPort() == 443 && pkt.getPayloadPreview() != null) {
    String sni = sniExtractor.extract(pkt.getPayloadPreview());
    if (sni != null) {
        appType = AppType.fromSni(sni);  // "www.youtube.com" → YOUTUBE
    }
}
```

For plain HTTP (port 80), the `Host:` header is used instead of SNI.

**Port-based classification fallback:**

| Condition | AppType |
|-----------|---------|
| dstPort == 80 | HTTP |
| dstPort == 443 (no SNI) | HTTPS |
| dstPort == 53 | DNS |
| SNI contains "youtube" | YOUTUBE |
| SNI contains "facebook" | FACEBOOK |
| (else) | UNKNOWN |

---

### Step 8: Check Blocking Rules (`RuleManagerService`)

```java
Optional<BlockReason> blockReason = ruleManager.shouldBlock(
    pkt.getSrcIp(),
    pkt.getDstPort(),
    pkt.getAppType(),
    pkt.getSni()
);
```

Rule evaluation order:

```
1. Is source IP in blockedIps set?   → DROP
2. Is dstPort in blockedPorts set?   → DROP
3. Is appType in blockedApps set?    → DROP
4. Does SNI match any blockedDomain? → DROP
5. (none matched)                    → FORWARD
```

---

### Step 9: Forward or Drop

```java
if (blockReason.isPresent()) {
    connTracker.blockConnection(conn);   // mark whole flow as BLOCKED
    return PacketAction.DROP;
}
connTracker.updateConnection(conn, pkt.getPayloadLength(), true);
return PacketAction.FORWARD;
```

Forwarded packets are accumulated and written to the output PCAP file at the end.

---

### Step 10: Record Stats (`DpiStats`)

```java
stats.recordPacket(parsed, action);
```

`DpiStats` maintains thread-safe atomic counters for total, forwarded, dropped, TCP, UDP packets, and a per-app distribution map.

---

## 7. Deep Dive: Backend Components

### DpiEngineService.java

**Purpose:** Orchestrates the entire packet processing pipeline.

Key methods:

| Method | Description |
|--------|-------------|
| `processFile(inputPath, outputPath)` | Async PCAP processing, returns `ProcessingResult` |
| `processPacket(rawData, tsSec, tsUsec)` | Process a single raw packet (for `/api/packets/raw`) |
| `classifyAndDecide(parsed)` | Core DPI decision logic — returns `PacketAction` |
| `getStats()` | Returns a snapshot of current counters |
| `generateReport()` | Produces a text report of all stats |
| `isRunning()` | Prevents concurrent PCAP processing |

---

### PacketParserService.java

**Purpose:** Decode raw bytes into a structured `ParsedPacket`.

Parsing steps:

```
Ethernet (14 bytes) → IP (20+ bytes) → TCP or UDP (20+ or 8 bytes) → Payload
```

Important flag constants used for TCP inspection:

```java
TCP_SYN = 0x02
TCP_FIN = 0x01
TCP_RST = 0x04
TCP_ACK = 0x10
```

---

### SniExtractorService.java

**Purpose:** Extract the target domain from TLS or HTTP payloads.

For **TLS (HTTPS)** — inspects the `ClientHello` handshake:

```
Byte 0:     Content Type = 0x16 (Handshake)
Byte 5:     Handshake Type = 0x01 (Client Hello)
...navigate extensions...
Extension Type 0x0000 = SNI
  → SNI Value: "www.youtube.com"
```

For **HTTP** — scans for the `Host:` header:

```
GET /path HTTP/1.1
Host: www.example.com   ← extracted here
```

---

### RuleManagerService.java

**Purpose:** Evaluate block rules against each packet.

Four rule dimensions:

| Rule Type | Storage | Example |
|-----------|---------|---------|
| IP | `Set<String>` | `192.168.1.50` |
| Port | `Set<Integer>` | `6881` (BitTorrent) |
| App | `Set<AppType>` | `AppType.YOUTUBE` |
| Domain | `Set<String>` | `"tiktok"` (substring match) |

Returns a `BlockReason` record with `type` and `detail` for logging.

---

### ConnectionTrackerService.java

**Purpose:** Track the lifecycle of every TCP/UDP flow.

Connection states:

```
ACTIVE → (SNI/app identified) → CLASSIFIED → (rule matched) → BLOCKED
                                                             ↘ (FIN seen) → CLOSED
```

Key operations:

| Method | Description |
|--------|-------------|
| `getOrCreateConnection(tuple)` | Get existing or open new flow |
| `classifyConnection(conn, appType, sni)` | Move ACTIVE → CLASSIFIED |
| `blockConnection(conn)` | Move to BLOCKED state |
| `closeConnection(conn)` | Handle TCP FIN |
| `getRecentConnections()` | Used by the Connections API |
| `getAppDistribution()` | Used by the Dashboard |

---

### DpiStats.java

**Purpose:** Thread-safe statistics collection with a point-in-time `Snapshot`.

Uses `AtomicLong` for all counters and `ConcurrentHashMap` for per-app counts. The `snapshot()` method returns an immutable record used by the API.

---

## 8. Deep Dive: Frontend Pages

### App.jsx — Router Setup

```
/login    → Login.jsx          (public)
/signup   → Signup.jsx         (public)
/*        → ProtectedRoute     (requires JWT in localStorage)
   /                → Dashboard.jsx
   /packets         → PacketAnalysis.jsx
   /connections     → Connections.jsx
   /rules           → Rules.jsx
```

### Dashboard.jsx

Shows live stats via `GET /api/packets/status` — total packets, forwarded, dropped, TCP/UDP split, active connections, and an app distribution chart (Recharts).

### PacketAnalysis.jsx

File upload form that calls `POST /api/packets/analyze`. Displays `totalPackets`, `forwardedPackets`, `droppedPackets` from the response. Also includes a raw packet hex analyser hitting `POST /api/packets/raw`.

### Connections.jsx

Lists all tracked flows from `GET /api/connections`. Supports filtering by state (`/state/{state}`) and by app (`/app/{app}`).

### Rules.jsx

Full CRUD for all four rule types via the `/api/rules/*` endpoints. Users can add/remove IPs, ports, apps, and domains.

---

## 9. REST API Reference

### Auth

| Method | Endpoint | Body | Description |
|--------|----------|------|-------------|
| POST | `/auth/login` | `{username, password}` | Get JWT token |
| POST | `/auth/signup` | `{username, email, password}` | Register |

All other endpoints require `Authorization: Bearer <token>`.

### Packets

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/packets/analyze` | Upload + process a PCAP file (multipart) |
| POST | `/api/packets/raw` | Analyze a single hex-encoded packet |
| GET | `/api/packets/status` | Live engine stats snapshot |
| GET | `/api/packets/report` | Full text report |

### Rules

| Method | Endpoint | Body / Param | Description |
|--------|----------|-------------|-------------|
| GET | `/api/rules` | — | All active rules + stats |
| POST | `/api/rules/ip` | `{ip}` | Block source IP |
| DELETE | `/api/rules/ip/{ip}` | — | Unblock IP |
| GET | `/api/rules/ip/{ip}/check` | — | Is IP blocked? |
| POST | `/api/rules/app` | `{app}` | Block app type (e.g. `YOUTUBE`) |
| DELETE | `/api/rules/app/{app}` | — | Unblock app |
| POST | `/api/rules/domain` | `{domain}` | Block domain (substring) |
| DELETE | `/api/rules/domain` | `{domain}` | Unblock domain |
| GET | `/api/rules/domain/check?domain=X` | — | Is domain blocked? |
| POST | `/api/rules/port` | `{port}` | Block destination port |
| DELETE | `/api/rules/port/{port}` | — | Unblock port |

### Connections

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/connections` | All recent connections |
| GET | `/api/connections/state/{state}` | Filter by `ACTIVE`, `CLASSIFIED`, `BLOCKED` |
| GET | `/api/connections/app/{app}` | Filter by app type |
| GET | `/api/connections/stats` | Active count + app distribution |

---

## 10. How SNI Extraction Works

### The TLS Handshake

When you visit `https://www.youtube.com`:

```
┌──────────┐                              ┌──────────┐
│  Browser │                              │  Server  │
└────┬─────┘                              └────┬─────┘
     │                                         │
     │ ──── Client Hello ─────────────────────►│
     │      (includes SNI: www.youtube.com)    │
     │                                         │
     │ ◄─── Server Hello ───────────────────── │
     │      (includes certificate)             │
     │                                         │
     │ ──── Key Exchange ─────────────────────►│
     │                                         │
     │ ◄═══ Encrypted Data ══════════════════► │
     │      (from here on, nothing readable)   │
```

**We can only extract SNI from the Client Hello — the very first packet of a TLS session.**

### TLS Client Hello Byte Layout

```
Byte 0:     Content Type = 0x16 (Handshake)
Bytes 1-2:  TLS Version
Bytes 3-4:  Record Length

Byte 5:     Handshake Type = 0x01 (Client Hello)
Bytes 6-8:  Handshake Length

Bytes 9-10:  Client Version
Bytes 11-42: Random (32 bytes)
Byte 43:     Session ID Length
...Session ID...
...Cipher Suites...
...Compression Methods...

Extensions Block:
  Each extension:
    2 bytes: Extension Type
    2 bytes: Extension Data Length
    N bytes: Extension Data

SNI Extension (Type = 0x0000):
  2 bytes: SNI List Length
  1 byte:  SNI Type = 0x00 (hostname)
  2 bytes: SNI Hostname Length
  N bytes: Hostname → "www.youtube.com"  ← EXTRACTED!
```

### Mapping SNI to AppType

After extraction, `AppType.fromSni(sni)` does substring matching:

```java
if (sni.contains("youtube"))  → AppType.YOUTUBE
if (sni.contains("facebook")) → AppType.FACEBOOK
if (sni.contains("google"))   → AppType.GOOGLE
// ... more patterns
```

---

## 11. How Blocking Works

### Rule Types

| Rule Type | Example | What it Blocks |
|-----------|---------|----------------|
| IP | `192.168.1.50` | All traffic from this source IP |
| Port | `6881` | All traffic to this destination port |
| App | `YOUTUBE` | All connections classified as YouTube |
| Domain | `tiktok` | Any SNI containing "tiktok" |

### The Blocking Decision Flow

```
Packet arrives
      │
      ▼
┌─────────────────────────────────┐
│ Connection already BLOCKED?    │──Yes──► DROP (fast path)
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is source IP in blockedIps?    │──Yes──► DROP + mark BLOCKED
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is dstPort in blockedPorts?    │──Yes──► DROP + mark BLOCKED
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Is appType in blockedApps?     │──Yes──► DROP + mark BLOCKED
└───────────────┬─────────────────┘
                │No
                ▼
┌─────────────────────────────────┐
│ Does SNI match blockedDomain?  │──Yes──► DROP + mark BLOCKED
└───────────────┬─────────────────┘
                │No
                ▼
            FORWARD


### Text Report (`GET /api/packets/report`)

```
=== DPI Engine Report ===
Total Packets    : 77
Total Bytes      : 5738
Forwarded        : 69
Dropped          : 8
TCP Packets      : 73
UDP Packets      : 4
Active Conns     : 12

=== Application Distribution ===
  HTTPS           : 39
  UNKNOWN         : 16
  YOUTUBE         : 4
  DNS             : 4
  FACEBOOK        : 3
```

### What Each Field Means

| Field | Meaning |
|-------|---------|
| `totalPackets` | Packets read from the input PCAP |
| `forwardedPackets` | Packets written to output PCAP (allowed) |
| `droppedPackets` | Packets blocked by rules |
| `activeConnections` | Unique 5-tuples currently tracked |
| `appDistribution` | Per-app packet counts |

### Raw Packet Analysis Response

```json
{
  "action": "FORWARD",
  "srcIp": "192.168.1.100",
  "dstIp": "172.217.14.206",
  "srcPort": 54321,
  "dstPort": 443,
  "protocol": "TCP",
  "appType": "YOUTUBE",
  "sni": "www.youtube.com",
  "payloadBytes": 517,
  "tcpFlags": "SYN"
}
```

---

## Summary

This Spring Boot DPI engine demonstrates:

1. **Network Protocol Parsing** — Decoding Ethernet/IP/TCP/UDP in Java
2. **Deep Packet Inspection** — Extracting SNI from TLS handshakes
3. **Flow Tracking** — Stateful connection lifecycle management
4. **Rule Engine** — IP / port / app / domain blocking
5. **REST API Design** — Clean controller/service/repository layering
6. **JWT Authentication** — Stateless security with Spring Security
7. **React Dashboard** — Real-time stats, rules management, connection browser
8. **Configuration Management** — `.env`-driven properties

The key insight is that even HTTPS traffic leaks the destination domain in the TLS handshake (`ClientHello`), allowing network operators to identify and control application usage without breaking encryption.

---

## Questions?

The code follows the same flow described in this document. Start with `DpiEngineService.java` → `classifyAndDecide()` to understand the core logic, then explore the controllers to see how the REST API wraps it.

Happy learning! 🚀
