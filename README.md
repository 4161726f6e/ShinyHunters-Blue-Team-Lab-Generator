# 🔴 ShinyHunters Blue Team Lab Generator

A **cloud / SaaS–focused cybersecurity lab generator** that simulates ShinyHunters tradecraft, including:

*   Identity-based compromise (OAuth / SSO abuse)
*   SaaS API data exfiltration
*   Hybrid infrastructure pivot (SSH)
*   **Ransomware deployment (ShinySp1d3r-style)**
*   Partial infrastructure disruption

***

## 🎯 Purpose

This project enables:

*   SOC analyst training
*   Blue team skills assessment
*   Detection engineering validation
*   Red vs Blue exercises

***

## 🧠 What Makes This Unique

✅ Identity-first attack simulation  
✅ SaaS + endpoint + network correlation  
✅ Behavioral detection (no signatures required)  
✅ Built-in false positives and noise  
✅ Deterministic reproducibility  
✅ Infinite lab variations

***

## 🚀 Quick Start

### 1. Install dependencies

```bash
pip install scapy
```

***

### 2. Generate a lab

```bash
python generate_lab.py
```

***

## ⚙️ CLI Options

| Option            | Description                                    |
| ----------------- | ---------------------------------------------- |
| `--output`        | Output directory (default: `ShinyHunters_Lab`) |
| `--seed`          | Deterministic generation                       |
| `--difficulty`    | `easy`, `medium`, `hard`                       |
| `--noise`         | `low`, `medium`, `high`                        |
| `--config`        | Reproduce lab from saved config                |
| `--list-defaults` | Show default parameters                        |
| `--version`       | Show generator version                         |

***

## 📘 Usage Examples

### 🟢 1. Generate Default Lab

Creates a standard lab with:

*   Medium difficulty
*   Medium noise
*   Randomized indicators

```bash
python generate_lab.py
```

Output:

    ShinyHunters_Lab/

***

### 🟡 2. Generate a Repeatable Lab (Deterministic)

```bash
python generate_lab.py --seed 42
```

✅ Produces identical dataset every run  
✅ Useful for training consistency

***

### 🔵 3. Generate a Custom Scenario

```bash
python generate_lab.py \
  --difficulty hard \
  --noise high \
  --output lab_hard_high \
  --seed 1337
```

***

### 🔴 4. Reproduce an Existing Lab

```bash
python generate_lab.py \
  --config lab_hard_high/config.json \
  --output lab_recreated
```

✅ Guarantees identical:

*   Attack path
*   Indicators
*   Answer key

***

### 🟣 5. Generate Multiple Variants

```bash
for i in 1 2 3 4 5; do
  python generate_lab.py --output lab_$i --seed $i
done
```

***

### 🧪 6. Inspect Defaults

```bash
python generate_lab.py --list-defaults
```

***

### 🔎 7. Check Version

```bash
python generate_lab.py --version
```

***

### 📦 8. Example SOC Training Workflow

```bash
# Generate lab
python generate_lab.py --difficulty medium --noise high --seed 100

# Distribute
zip -r lab_100.zip ShinyHunters_Lab/

# Reproduce for validation
python generate_lab.py --config ShinyHunters_Lab/config.json --output lab_review
```

***

## 🧪 Difficulty Levels

| Level  | Behavior                              |
| ------ | ------------------------------------- |
| easy   | Minimal noise, no decoys              |
| medium | Moderate noise + some false positives |
| hard   | High noise + multiple decoys          |

***

## 🔊 Noise Levels

| Level  | Effect                             |
| ------ | ---------------------------------- |
| low    | Minimal background traffic         |
| medium | Realistic enterprise traffic       |
| high   | High-volume noise (SOC difficulty) |

***

## 🔄 Reproducibility (Key Feature)

Each run generates:

    config.json

This file captures:

*   All randomized values
*   IP addresses
*   Attack flow
*   Ground truth

***

### ✅ Reproduce a Lab Exactly

```bash
python generate_lab.py --config path/to/config.json --output new_lab
```

***

## 📦 Output Structure

    ShinyHunters_Lab/
    ├── pcaps/
    ├── zeek/
    ├── windows/
    ├── saas_logs/
    ├── metadata/
    ├── ctf/
    ├── config.json

***

## 🔍 Scenario Overview

### Phase 1 — Initial Access

*   OAuth approval
*   Identity compromise

### Phase 2 — Data Exfiltration

*   SaaS API bulk export
*   TLS-based exfiltration

### Phase 3 — Lateral Movement

*   SSH pivot into infrastructure

### Phase 4 — Ransomware Deployment

*   Payload staging
*   **Partial VM encryption (subset only)**

***

## 🎯 Skills Tested

*   Identity compromise detection
*   SaaS log analysis
*   TLS traffic analysis
*   Lateral movement identification
*   Ransomware behavioral detection
*   False positive reduction

***

## 🧩 Ground Truth Design

✅ Only some systems are encrypted  
✅ Backup jobs create false positives  
✅ SaaS activity continues during attack  
✅ Analysts must **prove impact**, not assume it

***

## 📊 Example Output

    ✅ Lab generated successfully
    Compromised Host: 10.0.1.32
    Exfil IP: 185.193.88.77
    Payload IP: 91.215.85.12
    Encrypted VMs: VM-APP01, VM-DB01

***

## 🧠 Design Philosophy

This lab reflects modern attacks where:

*   Attackers use valid credentials
*   Traffic appears legitimate
*   Detection requires correlation across domains

Focus areas:

*   Identity-first compromise
*   SaaS abuse
*   Behavioral detection

***

## ⚠️ Disclaimer

This project generates **synthetic data for defensive cybersecurity training only**.

It does **not perform real attacks**.

***

## ⭐ Contributing

Contributions welcome:

*   Additional attack scenarios
*   Improved log realism
*   Detection engineering content

***

## 📄 License

MIT License

***
