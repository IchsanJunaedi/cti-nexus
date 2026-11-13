# BUKU PANDUAN TEKNIS & MASTER STUDY GUIDE
## CTI NEXUS: AUTONOMOUS CYBER THREAT INTELLIGENCE & DEFENSIVE SHIELD PLATFORM
**Dokumen Pembekalan Tim & Acuan Presentasi Teknis Kartika Cyber Hackathon 2026**  
*Tim Pengembang: Aegis Nexus | Kategori: Penangkalan (Defensive Shield)*

---

## DAFTAR ISI
1. [BAB 1: Esensi & Landasan Teori CTI (Untuk Apa CTI Nexus Dibuat?)](#bab-1-esensi--landasan-teori-cti)
2. [BAB 2: Arsitektur Sistem & Spesifikasi Infrastruktur](#bab-2-arsitektur-sistem--spesifikasi-infrastruktur)
3. [BAB 3: Skema Basis Data & Model Data MongoDB](#bab-3-skema-basis-data--model-data-mongodb)
4. [BAB 4: Deep-Dive Fitur Unggulan (The Defensive Shield)](#bab-4-deep-dive-fitur-unggulan)
5. [BAB 5: Silabus Materi Pokok yang Wajib Dikuasai Anggota Tim](#bab-5-silabus-materi-pokok)
6. [BAB 6: Bank Pertanyaan & Strategi Menjawab Pertanyaan Juri](#bab-6-bank-pertanyaan--strategi-menjawab-juri)

---

## BAB 1: ESENSI & LANDASAN TEORI CTI

### 1.1 Masalah Fundamental Pertahanan Siber Saat Ini
Mayoritas Security Operations Center (SOC) dan tim pertahanan siber terjebak dalam paradigma **Reaktif**:
- Firewall dan SIEM hanya membunyikan alarm *setelah* malware menyentuh endpoint atau lalu lintas jaringan mencurigakan terdeteksi.
- Analis mengalami *alert fatigue* (kelelahan meninjau ribuan notifikasi per hari yang 95%-nya adalah false positive).
- Tindakan pertahanan dilakukan tanpa konteks: "Siapa aktor di balik serangan ini? Apakah ini kampanye global terorganisir atau pemindaian acak? Celah apa yang akan mereka serang berikutnya?"

### 1.2 Mengapa CTI Nexus Menjawab Kategori "Penangkalan" (Defensive Shield)?
CTI Nexus mengubah paradigma dari **Reaktif $\rightarrow$ Proaktif**:
1. **Early Warning Radar**: Mendeteksi rencana serangan musuh, tren eksploitasi zero-day, dan diskusi darkweb *sebelum* penyerang melancarkan aksinya ke infrastruktur lokal.
2. **Dari Informasi ke Aksi (Actionable Defense)**: Platform intelijen tradisional (seperti MISP standar) hanya mengumpulkan IOC dan mencatat taktik lawan (ATT&CK). CTI Nexus melangkah lebih jauh dengan memetakan temuan intelijen langsung ke **MITRE D3FEND** (tindakan teknis pertahanan seperti *Inbound Traffic Filtering, Decoy System, Process Hashing, Credential Rotation*).
3. **Kedaulatan Data (Sovereign Intelligence)**: Dibangun untuk beroperasi mandiri (*self-hosted* atau *air-gapped*), sehingga institusi militer dan pertahanan tidak perlu membocorkan log internal ke vendor cloud intelijen asing.

### 1.3 Siklus Intelijen Ancaman Siber (CTI Lifecycle)
CTI Nexus menerapkan standar siklus intelijen intelijen internasional:
```
Planning/Direction ──> Collection ──> Processing ──> Analysis ──> Dissemination ──> Feedback
      (PIRs)          (60+ Scrapers)  (NLP/NER/Queue) (Graph/D3FEND)   (STIX 2.1/UI)   (SOC Analyst)
```
- **Planning & Direction**: Berdasarkan *Priority Intelligence Requirements* (PIR).
- **Collection**: Pengumpulan otomatis dari 60+ sumber OSINT, vendor blog, radar CISA KEV, dan darkweb.
- **Processing**: Normalisasi teks, pembersihan tag HTML, deduplikasi dokumen via hash, dan deduplikasi URL.
- **Analysis**: Ekstraksi entitas TTP, CVE, aktor ancaman, dan skor probabilitas eksploitasi (EPSS).
- **Dissemination**: Visualisasi dashboard interaktif, ekspor paket OASIS STIX 2.1, dan notifikasi email briefing.

---

## BAB 2: ARSITEKTUR SISTEM & SPESIFIKASI INFRASTRUKTUR

CTI Nexus dirancang menggunakan arsitektur **Monorepo Terpisah (Decoupled Engines)** yang terdiri dari 2 subsistem utama:

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                                   CTI NEXUS MONOREPO                                   │
├─────────────────────────────────────────┬──────────────────────────────────────────────┤
│ 1. INGESTION ENGINE (ingestion/)        │ 2. DEFENSE PLATFORM (platform/)              │
│ - 60+ Autonomous OSINT Scrapers         │ - FastAPI Asynchronous ASGI Core             │
│ - MongoDB Job Queue Producer            │ - Jinja2 Responsive Dark-Mode UI             │
│ - spaCy NLP Multi-Worker Consumer       │ - IntelGraph Force-Directed Topology Engine  │
│ - iocSyncer & Liveness Health Daemons   │ - STIX 2.1 Serialization & API Routers       │
└─────────────────────────────────────────┴──────────────────────────────────────────────┘
                                          │
                                          ▼
                         MONGODB CLUSTER (Port 27017)
                 ├── Database: news_db (11,900+ Articles, IOCs)
                 └── Database: threatintel (CVE, Actors, Scenarios)
```

### 2.1 Spesifikasi Teknis Komponen

| Komponen | Teknologi | Peran & Detail Operasional |
| :--- | :--- | :--- |
| **Backend Core** | Python 3.11, FastAPI, Uvicorn | Menangani routing asynchronous, validasi schema Pydantic, autentikasi JWT token (cookie/bearer), dan rendering SSR. |
| **Database** | MongoDB 6.0+ | Document store terdistribusi untuk menyimpan artikel semi-terstruktur, graf entitas, relasi TTP, dan log audit. |
| **NLP Engine** | spaCy (`en_core_web_sm`), Regex | Ekstraksi entitas otomatis (NER) untuk mendeteksi nama APT, CVE, malware family, dan IOC (IPv4, CIDR, Domain, URL, MD5/SHA256). |
| **Frontend UI** | HTML5, Tailwind CSS, Chart.js, Vis.js | Antarmuka pengguna modern dengan tema gelap taktis militer (*tactical dark mode*), responsif tanpa framework berat. |
| **Topology Engine** | IntelGraph (React + Force Graph bundle) | Graf visual interaktif yang merender relasi multi-hop antar entitas intelijen siber secara real-time. |
| **Security Layer** | SSL/TLS (HTTPS Port 5443), Argon2 / Bcrypt | Komunikasi terenkripsi penuh dengan proteksi brute-force, rate limiting, dan role-based access control (Admin, Analyst, Viewer). |

### 2.2 Alur Data Ingestion (Pipeline Harvesting)
1. **Scraping**: Puluhan script harvester (`bleepcompThreat.py`, `cisaThreat.py`, `ransomwareLiveThreat.py`, dll.) berjalan via scheduler/cron.
2. **Deduplikasi**: Pengecekan riwayat crawl menggunakan `modules/offsetStore.py` agar artikel yang sama tidak diproses ulang.
3. **Queueing**: Artikel mentah dimasukkan ke koleksi antrean kerja (`jobQueue`) di MongoDB.
4. **NLP Worker (`nlp_worker.py`)**: Daemon worker mengambil tugas dari queue, menjalankan tokenisasi dan model spaCy, mengekstrak TTP MITRE, mendeteksi CVE, dan menandai aktor ancaman.
5. **IOC Syncer (`iocSyncer.py`)**: Mengekstrak indikator teknis (IP, domain, hash), melakukan *defanging* (mengubah `http` jadi `hxxp` agar aman), dan menjalankan uji *liveness* (apakah infrastruktur musuh masih aktif).
6. **Storage**: Data yang telah diperkaya (*enriched*) disimpan ke dalam basis data utama (`news_db.articles` & `news_db.iocs`).

---

## BAB 3: SKEMA BASIS DATA & MODEL DATA MONGODB

Basis data CTI Nexus terbagi menjadi dua kluster database utama di MongoDB:
- `news_db`: Pemanenan data dinamis (artikel intelijen mentah/diperkaya, IOC terekstraksi, dan manajemen pengguna).
- `threatintel`: Basis pengetahuan intelijen terstruktur (katalog CVE, profil Threat Actor, riwayat korban ransomware, dan skenario serangan).

### 3.1 Diagram Relasi Entitas (ER Diagram)

Berikut visualisasi diagram hubungan antar-koleksi dalam ekosistem CTI Nexus:

```mermaid
erDiagram
    ARTICLES ||--o{ IOCS : "mengekstraksi"
    ARTICLES }o--o{ THREAT_ACTORS : "mengidentifikasi"
    ARTICLES }o--o{ CVE_TRACKER : "membahas"
    
    THREAT_ACTORS ||--o{ IOCS : "mengoperasikan_infrastruktur"
    THREAT_ACTORS ||--o{ RANSOMWARE_VICTIMS : "mengklaim_serangan"
    
    CVE_TRACKER ||--o{ IOCS : "dieksploitasi_dalam"

    ARTICLES {
        ObjectId id PK "ID Unik Dokumen Artikel"
        string title "Judul Berita/Peringatan Siber"
        string source "Sumber Feed OSINT"
        datetime published_at "Waktu Publikasi Sumber"
        string summary "Ringkasan Hasil Ekstraksi NLP"
        string severity "Tingkat Keparahan (CRITICAL, HIGH, dll)"
        array threat_actors FK "Relasi ke nama Threat Actor"
        array ttp_tags "Daftar ID Teknik MITRE ATT&CK"
        array cve_tags FK "Relasi ke CVE Tracker"
        array targeted_sectors "Sektor Industri Target"
        array targeted_countries "Kode Negara Sasaran (ID, SG, dll)"
    }

    IOCS {
        ObjectId id PK "ID Unik Indikator Kompromi"
        string type "Tipe (ipv4, domain, url, hash)"
        string value "Nilai Asli Indikator"
        string defanged_value "Nilai Aman / Defanged"
        int confidence_score "Skor Kepercayaan (0 - 100)"
        boolean is_active "Status Liveness Infrastruktur"
        array related_threat_actors FK "Aktor Terkait"
        array related_cves FK "CVE Terkait"
        array mitre_d3fend_remedy "Rekomendasi Tindakan D3FEND"
        datetime last_seen "Waktu Terakhir Terdeteksi Aktif"
    }

    THREAT_ACTORS {
        ObjectId id PK "ID Unik Profil Aktor"
        string name "Nama Utama Aktor (e.g. APT29)"
        array aliases "Nama Alias (e.g. Cozy Bear, Midnight Blizzard)"
        string origin_country "Dugaan Negara Asal"
        array motivations "Motivasi (Espionage, Financial)"
        array targeted_sectors "Sektor Sasaran Utama"
        array tools "Alat / Malware yang Digunakan"
        array associated_ttps "Kompilasi TTP MITRE ATT&CK"
    }

    CVE_TRACKER {
        string cve_id PK "ID Standar CVE (e.g. CVE-2026-24090)"
        string description "Deskripsi Celah Keamanan"
        float cvss_v3 "Skor Keparahan Base CVSS v3.1"
        float epss_score "Probabilitas Eksploitasi (0.0 - 1.0)"
        boolean cisa_kev "Terdaftar di CISA Known Exploited"
        string vendor "Nama Vendor Perangkat Lunak"
        string product "Produk Terdampak"
        boolean poc_available "Ketersediaan Kode Eksploit Proof-of-Concept"
        array mitre_d3fend_countermeasures "Langkah Penangkalan D3FEND"
    }

    RANSOMWARE_VICTIMS {
        ObjectId id PK "ID Unik Korban Pemerasan"
        string victim_name "Nama Perusahaan/Institusi Korban"
        string group_name FK "Nama Kelompok Ransomware Pelaku"
        string country "Negara Korban"
        string industry "Sektor Korban"
        datetime leak_date "Tanggal Kebocoran Data"
        string ransom_status "Status (PAID, NEGOTIATING, DUMPED)"
        float data_size_gb "Ukuran Data yang Dicuri (GB)"
    }

    USERS {
        ObjectId id PK "ID Pengguna"
        string username "Username Pengguna"
        string email "Email Resmi Pengguna"
        string role "Hak Akses (Admin, Analyst, Viewer)"
        string hashed_password "Hash Password (Bcrypt/Argon2)"
        datetime created_at "Waktu Akun Dibuat"
    }
```

---

### 3.2 Kamus Data & Relasi Antar-Koleksi

| Koleksi | Basis Data | Fungsi Utama | Kunci Relasi (Foreign Key) |
| :--- | :--- | :--- | :--- |
| **`articles`** | `news_db` | Menyimpan 11.000+ dokumen berita intelijen hasil crawl yang telah diperkaya NLP. | `threat_actors` $\rightarrow$ `threat_actors.name`<br>`cve_tags` $\rightarrow$ `cve_tracker.cve_id` |
| **`iocs`** | `news_db` | Repositori teknis indikator jahat (IP, Domain, URL, Hash) hasil ekstrak artikel. | `related_threat_actors` $\rightarrow$ `threat_actors.name`<br>`related_cves` $\rightarrow$ `cve_tracker.cve_id` |
| **`cve_tracker`** | `threatintel` | Triase kerentanan terintegrasi dengan CVSS v3.1, skor probabilitas EPSS, dan CISA KEV. | `cve_id` dirujuk oleh `articles` dan `iocs` |
| **`threat_actors`** | `threatintel` | Profil intelijen kelompok peretas (APT, cybercriminal) beserta TTP dan malware yang digunakan. | Dirujuk oleh `articles`, `iocs`, dan `ransomware` |
| **`ransomware`** | `threatintel` | Rekaman 7.000+ insiden pemerasan ransomware global untuk visualisasi treemap eksekutif. | `group_name` $\rightarrow$ `threat_actors.name` |
| **`users`** | `news_db` | Manajemen hak akses peran (RBAC) dan sesi pengguna platform. | Terisolasi untuk sistem autentikasi |

---

### 3.3 Alur Relasi Data Terpadu (Data Flow Lifecycle)
1. **Pemanenan**: Artikel masuk ke `articles` dengan tag otomatis dari worker NLP (`ttp_tags`, `threat_actors`, `cve_tags`).
2. **Korelasi Silang**:
   - Jika artikel menyebut nama aktor ancaman (misal: `"APT29"`), sistem otomatis menarik profil dari `threat_actors` untuk ditampilkan di Newsroom.
   - Jika artikel menyebut celah keamanan (misal: `"CVE-2026-24090"`), sistem mencocokkan status eksploitasi dan skor prioritas dari `cve_tracker`.
3. **Ekstraksi IOC ke Aksi Penangkalan**:
   - Indikator teknis yang ditemukan dalam artikel disimpan ke koleksi `iocs`.
   - Tiap IOC dipasangkan dengan taktik defensif **MITRE D3FEND** yang relevan (contoh: IP jahat dipasangkan dengan *D3-FIP: IP Filtering*), sehingga analis bisa langsung mengambil tindakan pertahanan.

---

## BAB 4: DEEP-DIVE FITUR UNGGULAN (THE DEFENSIVE SHIELD)

### 4.1 Executive Cyber Radar Dashboard
- **Tujuan**: Memberikan ringkasan situasi (*situational awareness*) dalam hitungan detik kepada perwira komando atau Chief of SOC.
- **Komponen Utama**:
  - *KPI Cards*: Total insiden terpantau, volume IOC aktif, jumlah korban ransomware regional, dan total CVE berstatus kritikal.
  - *Ransomware Treemap*: Visualisasi proporsional kelompok ransomware paling aktif dan pembagian sektor industri yang menjadi korban.
  - *Target Geografis*: Peta distribusi negara target serangan, memudahkan identifikasi jika ada kampanye terkoordinasi yang menargetkan wilayah Asia Tenggara/Indonesia.

### 4.2 IntelGraph (Interactive Threat Topology)
- **Tujuan**: Menyelesaikan masalah analisis silo dengan menghubungkan semua titik ancaman ke dalam satu kanvas visual terpadu (*Force-Directed Graph*).
- **Relasi yang Dirender**:
  - `Aktor Ancaman` $\rightarrow$ menggunakan $\rightarrow$ `Tools / Malware`
  - `Malware` $\rightarrow$ mengeksploitasi $\rightarrow$ `CVE Kerentanan`
  - `CVE Kerentanan` $\rightarrow$ berkomunikasi ke $\rightarrow$ `C2 Server (IOC IP/Domain)`
  - `IOC` $\rightarrow$ ditangkal oleh $\rightarrow$ `Tindakan Defensif MITRE D3FEND`
- **Interaktivitas**: Analis dapat mengklik salah satu node (misal APT29) dan melihat seluruh rantai infrastruktur musuh terbentang seketika.

### 4.3 Matriks Penangkalan MITRE D3FEND (Core Differentiator)
- **Mengapa ini krusial di mata juri?** Hampir semua produk kompetitor berhenti di MITRE ATT&CK (hanya menjabarkan cara musuh menyerang). CTI Nexus melengkapi siklus pertahanan dengan memasangkan ATT&CK dengan **D3FEND**:
  - *Serangan*: T1566.001 (Phishing: Spearphishing Attachment)
  - *Penangkalan D3FEND*: D3-MFA (Multi-factor Authentication), D3-EFA (Executable File Analysis), D3-DNSR (DNS Reputation Filtering).
- Menghasilkan rekomendasi teknis yang langsung bisa disalin oleh operator firewall dan tim endpoint defense.

### 4.4 CVE Triase Otomatis (CVSS v3.1 + EPSS)
- **Kelemahan Penilaian Lama**: Skor CVSS murni hanya mengukur *keparahan teoretis*, bukan apakah celah tersebut benar-benar dieksploitasi oleh hacker di dunia nyata.
- **Inovasi CTI Nexus**: Menggabungkan:
  $$\text{Priority Score} = (\text{CVSS Base Score} \times 0.6) + (\text{EPSS Probability} \times 10 \times 0.4)$$
  Ditambah *flag* mutlak **CISA KEV** (jika celah tersebut sudah aktif dieksploitasi di alam liar, otomatis naik ke status **URGENT**).

### 4.5 Interoperabilitas OASIS STIX 2.1
- Platform menyediakan endpoint ekspor STIX 2.1 (`/api/stix/export`).
- Menghasilkan bundle JSON berstandar internasional yang mencakup `threat-actor`, `indicator`, `vulnerability`, dan `attack-pattern`.
- Memungkinkan data CTI Nexus langsung di-ingest oleh solusi SIEM militer (seperti Splunk, Elastic SIEM, Wazuh) atau SOAR tanpa perlu parser manual.

---

## BAB 5: SILABUS MATERI POKOK YANG WAJIB DIKUASAI ANGGOTA TIM

Agar seluruh anggota tim dapat berbicara dengan percaya diri saat demonstrasi, berikut konsep dasar yang harus dipahami:

```mermaid
graph TD
    A["Konsep Dasar Pertahanan"] --> B["Pyramid of Pain (David Bianco)"]
    A --> C["Diamond Model of Intrusion"]
    A --> D["Kerangka Taktis: ATT&CK vs D3FEND"]
    A --> E["Matriks Risiko: CVSS vs EPSS"]
```

### 5.1 The Pyramid of Pain (David Bianco)
Konsep seberapa sulit bagi musuh jika kita memblokir komponen serangan mereka:
1. **Hash Values (Trivial)**: Mudah diganti penyerang (cuma ubah 1 byte file).
2. **IP Addresses (Easy)**: Penyerang bisa sewa proxy/VPN baru.
3. **Domain Names (Simple)**: Penyerang ganti domain via DGA.
4. **Network/Host Artifacts (Annoying)**: Penyerang harus ubah URI pattern atau registry keys.
5. **Tools (Challenging)**: Penyerang harus membangun ulang malware atau crypter mereka.
6. **TTPs - Tactics, Techniques, & Procedures (Tough!)**: Sangat menyulitkan penyerang karena memaksa mereka mengubah cara berpikir dan taktik operasional mereka.
> *Argumen Tim*: "CTI Nexus tidak hanya berburu di level bawah (IP/Hash), tetapi memetakan hingga level tertinggi (TTPs & D3FEND)!"

### 5.2 Diamond Model of Intrusion
Model matematis intelijen ancaman siber yang terdiri dari 4 simpul:
- **Adversary (Pelaku)**: Siapa yang menyerang (misal: Sandworm, APT41).
- **Capability (Kemampuan)**: Alat atau malware apa yang dipakai (misal: Cobalt Strike, wiper).
- **Infrastructure (Infrastruktur)**: Server C2, IP, atau domain yang digunakan.
- **Victim (Korban)**: Organisasi, sektor industri, atau negara target.
> *Argumen Tim*: "IntelGraph kami adalah implementasi hidup dari Diamond Model, di mana analis bisa menelusuri hubungan keempat simpul ini secara grafis."

### 5.3 Perbedaan ATT&CK vs D3FEND
- **MITRE ATT&CK**: Matriks ofensif (sudut pandang musuh) — menjelaskan taktik bagaimana musuh menembus pertahanan (*Initial Access, Execution, Persistence, Exfiltration*).
- **MITRE D3FEND**: Matriks defensif (sudut pandang benteng pertahanan) — katalog tindakan teknik penangkalan siber (*Harden, Detect, Isolate, Deceive, Evict*).

### 5.4 CVSS vs EPSS
- **CVSS (Common Vulnerability Scoring System)**: Mengukur seberapa berbahaya dampak lubang keamanan jika berhasil ditembus (skor 0.0 - 10.0). Bersifat statis.
- **EPSS (Exploit Prediction Scoring System)**: Model kecerdasan buatan berbasis data empiris yang memprediksi probabilitas (0% - 100%) bahwa suatu CVE akan dieksploitasi di dunia nyata dalam 30 hari ke depan.

---

## BAB 6: BANK PERTANYAAN & STRATEGI MENJAWAB PERTANYAAN JURI

Berikut adalah simulasi pertanyaan teknis yang paling sering diajukan oleh juri hackathon pertahanan/militer, lengkap dengan panduan jawaban yang tepat:

#### Q1: "Darimana kalian mendapatkan data intelijen sebanyak ini? Apakah ini data dummy atau hasil scraping nyata?"
> **Jawaban Rekomendasi**:  
> *"Data kami 100% nyata dan berasal dari pipeline pengumpulan otonom kami sendiri di folder `ingestion/`. Kami menjalankan lebih dari 60 scraper OSINT yang terhubung ke situs vendor riset keamanan global, pembaruan resmi CISA KEV, pelacak kebocoran ransomware, dan monitoring darkweb. Data mentah tersebut kemudian diproses oleh worker NLP berbasis spaCy untuk ekstraksi entitas secara real-time dan disimpan ke dalam database MongoDB kami yang saat ini telah mengindeks lebih dari 11.000 artikel dan 7.000 korban ransomware."*

#### Q2: "Apa yang membedakan CTI Nexus dengan platform open-source lain seperti MISP atau OpenCTI?"
> **Jawaban Rekomendasi**:  
> *"Ada 3 pembeda utama:  
> Pertama, **Integrasi MITRE D3FEND**: MISP dan OpenCTI berfokus pada katalogisasi ATT&CK (apa yang dilakukan musuh). CTI Nexus langsung memberikan rekomendasi tindakan penangkalan teknis (D3FEND) yang siap dieksekusi analis.  
> Kedua, **Triase Kerentanan EPSS + KEV**: Kami tidak hanya menampilkan skor CVSS, melainkan mengkombinasikannya dengan prediksi probabilitas eksploitasi nyata di lapangan.  
> Ketiga, **Desain Sovereign & Ringan**: CTI Nexus dapat langsung dideploy secara on-premise atau air-gapped dengan dependensi minimal tanpa memerlukan arsitektur microservices yang rumit."*

#### Q3: "Bagaimana platform ini membantu operasional pertahanan jika diimplementasikan di lingkungan militer/TNI AD?"
> **Jawaban Rekomendasi**:  
> *"CTI Nexus bertindak sebagai 'Sovereign Cyber Radar'. Dalam skenario operasi militer tertutup (air-gapped SOC):  
> 1. Pimpinan mendapatkan gambaran situasi strategis instan melalui Executive Radar (sektor apa yang sedang menjadi target kampanye siber di kawasan regional).  
> 2. Analis teknis dapat memutus rantai serangan musuh sebelum masuk dengan mengekspor IOC terverifikasi ke format STIX 2.1 untuk langsung dipasang pada firewall perimeter.  
> 3. Tim rekayasa pertahanan mendapatkan rekomendasi mitigasi D3FEND untuk memperkuat sistem mereka terhadap TTP yang sedang aktif digunakan lawan."*

#### Q4: "Bagaimana kalian menangani False Positive pada IOC yang diekstrak?"
> **Jawaban Rekomendasi**:  
> *"Kami menerapkan sistem filter berlapis:  
> 1. Modul `iocExtractor` dilengkapi whitelist regex untuk membuang domain publik populer (seperti google.com, github.com) agar tidak tercatat sebagai IOC jahat.  
> 2. Skrip `iocLiveness` memverifikasi apakah server indikator tersebut masih aktif merespons.  
> 3. Algoritma `decay_sweep` di backend secara periodik mendegradasi skor confidence indikator yang sudah lama tidak terlihat, sehingga firewall tidak dibebani oleh rule usang."*

---

## RINGKASAN TINDAKAN UNTUK TIM (CHECKLIST 15 NOVEMBER):
1. **Pahami Poin Jual Utama**: CTI Nexus = **60+ Ingestion Harvester + spaCy NLP + MITRE D3FEND + IntelGraph**.
2. **Kuasai Demonstrasi Web**: Pastikan saat take video atau presentasi, urutan halaman yang dibuka adalah:  
   *Login $\rightarrow$ Exec Dashboard $\rightarrow$ Newsroom $\rightarrow$ CVE Tracker $\rightarrow$ IntelGraph $\rightarrow$ D3FEND Matrix*.
3. **Gunakan Istilah Profesional**: Gunakan istilah *Adversary, TTPs, D3FEND Countermeasures, Sovereign Deployment, EPSS Probability, STIX 2.1*.

*Aegis Nexus — Defending National Cyber Sovereignty with Actionable Intelligence.*
