import os
import json
import random
import time
import argparse
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

from scapy.all import IP, TCP, Raw, wrpcap  # pip install scapy


__version__ = "1.2.0"


# =========================
# PARAMETERIZATION
# =========================
@dataclass(frozen=True)
class LabParams:
    noise_tls_sessions: int
    noise_tls_pkts_per_session: int
    noise_tls_pkt_size: int
    noise_dns_entries: int
    noise_http_entries: int
    include_decoy_exfil: bool
    include_decoy_oauth_app: bool
    include_backup_smb_decoy: bool
    jitter_seconds: int


def get_params(difficulty: str, noise: str) -> LabParams:
    # Noise scaling
    if noise == "low":
        noise_tls_sessions = 120
        noise_dns_entries = 80
        noise_http_entries = 60
        tls_pkts = 2
        tls_size = 420
    elif noise == "high":
        noise_tls_sessions = 650
        noise_dns_entries = 450
        noise_http_entries = 300
        tls_pkts = 4
        tls_size = 650
    else:  # medium
        noise_tls_sessions = 280
        noise_dns_entries = 180
        noise_http_entries = 120
        tls_pkts = 3
        tls_size = 520

    # Difficulty scaling
    if difficulty == "easy":
        return LabParams(
            noise_tls_sessions=noise_tls_sessions,
            noise_tls_pkts_per_session=tls_pkts,
            noise_tls_pkt_size=tls_size,
            noise_dns_entries=noise_dns_entries,
            noise_http_entries=noise_http_entries,
            include_decoy_exfil=False,
            include_decoy_oauth_app=False,
            include_backup_smb_decoy=False,
            jitter_seconds=180,
        )
    elif difficulty == "hard":
        return LabParams(
            noise_tls_sessions=noise_tls_sessions,
            noise_tls_pkts_per_session=tls_pkts,
            noise_tls_pkt_size=tls_size,
            noise_dns_entries=noise_dns_entries,
            noise_http_entries=noise_http_entries,
            include_decoy_exfil=True,
            include_decoy_oauth_app=True,
            include_backup_smb_decoy=True,
            jitter_seconds=900,
        )
    else:  # medium
        return LabParams(
            noise_tls_sessions=noise_tls_sessions,
            noise_tls_pkts_per_session=tls_pkts,
            noise_tls_pkt_size=tls_size,
            noise_dns_entries=noise_dns_entries,
            noise_http_entries=noise_http_entries,
            include_decoy_exfil=True,
            include_decoy_oauth_app=False,
            include_backup_smb_decoy=True,
            jitter_seconds=600,
        )


DEFAULTS = {
    "output": "ShinyHunters_Lab",
    "difficulty": "medium",
    "noise": "medium",
    "seed": None,
    "config": None,
}


# =========================
# CLI
# =========================
def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description="ShinyHunters Blue Team Lab Generator")
    p.add_argument("--output", default=DEFAULTS["output"],
                   help=f"Output directory (default: {DEFAULTS['output']})")
    p.add_argument("--seed", type=int, default=DEFAULTS["seed"],
                   help="Seed for deterministic generation (optional)")
    p.add_argument("--difficulty", choices=["easy", "medium", "hard"],
                   default=DEFAULTS["difficulty"],
                   help="Difficulty (default: medium)")
    p.add_argument("--noise", dest="noise", choices=["low", "medium", "high"],
                   default=DEFAULTS["noise"],
                   help="Noise level (default: medium)")
    p.add_argument("--noise-level", dest="noise", choices=["low", "medium", "high"],
                   help=argparse.SUPPRESS)

    # New: load an existing config.json to reproduce exactly
    p.add_argument("--config", default=DEFAULTS["config"],
                   help="Path to a saved config.json to reproduce a prior lab exactly")

    # New: list defaults + parameter matrices and exit
    p.add_argument("--list-defaults", action="store_true",
                   help="Print defaults and parameter matrices (JSON) and exit")

    # New: version
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def list_defaults_and_exit():
    matrices = {
        "difficulty": {
            "easy": asdict(get_params("easy", "medium")),
            "medium": asdict(get_params("medium", "medium")),
            "hard": asdict(get_params("hard", "medium")),
        },
        "noise": {
            "low": asdict(get_params("medium", "low")),
            "medium": asdict(get_params("medium", "medium")),
            "high": asdict(get_params("medium", "high")),
        }
    }
    payload = {
        "version": __version__,
        "defaults": DEFAULTS,
        "matrices": matrices,
        "notes": {
            "config_export": "config.json is written every run into output/ and output/metadata/",
            "repro": "Use --config path/to/config.json to reproduce exactly (optionally override --output)."
        }
    }
    print(json.dumps(payload, indent=2))
    raise SystemExit(0)


# =========================
# FS utils
# =========================
def mkdir(path: str):
    os.makedirs(path, exist_ok=True)


def write_json(path: str, obj: dict):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)


def write_jsonl(path: str, rows: List[dict]):
    with open(path, "w", encoding="utf-8") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


def now_base() -> float:
    return time.time()


def jittered_ts(base: float, jitter: int) -> float:
    return base + random.randint(-jitter, jitter)


# =========================
# CONFIG BUILD/LOAD
# =========================
def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        cfg = json.load(f)
    # Minimal validation
    if "lab" not in cfg or "params" not in cfg or "answers" not in cfg:
        raise ValueError("Invalid config.json: missing required top-level keys.")
    return cfg


def build_config_from_args(args) -> dict:
    # Apply seed if provided
    if args.seed is not None:
        random.seed(args.seed)

    # Parameters driven by difficulty/noise
    params = get_params(args.difficulty, args.noise)

    # Core fixed story constants (keep answers stable)
    user = "jdoe@corp.com"
    oauth_app = "DataSync-Pro"
    api_uri = "/bulk/export"
    recovery_disable_cmd = "vssadmin delete shadows /all /quiet"
    encrypted_vms = ["VM-APP01", "VM-DB01"]
    encrypted_vm_ips = {"VM-APP01": "10.0.2.21", "VM-DB01": "10.0.2.22"}

    # Randomized but reproducible via seed OR config export
    internal_net = "10.0.1."
    server_net = "10.0.2."

    compromised_host = internal_net + str(random.randint(20, 50))
    hypervisor_ip = server_net + "50"

    exfil_ip = random.choice(["185.193.88.77", "103.44.22.19"])
    payload_ip = random.choice(["91.215.85.12", "77.91.124.8"])

    # Decoys (documentation ranges for safety/clarity)
    decoy_exfil_ip = random.choice(["198.51.100.44", "203.0.113.9"])
    decoy_oauth_app = "BoxSync-Connector"
    backup_server_ip = "10.0.2.60"
    backup_target_ip = "10.0.2.61"

    base_ts = now_base()

    cfg = {
        "generator": {
            "name": "shinyhunters-blue-team-lab",
            "version": __version__,
            "generated_at_epoch": base_ts,
        },
        "cli": {
            "output": args.output,
            "seed": args.seed,
            "difficulty": args.difficulty,
            "noise": args.noise,
        },
        "params": asdict(params),
        "lab": {
            "nets": {
                "internal_net": internal_net,
                "server_net": server_net,
            },
            "hosts": {
                "compromised_host_ip": compromised_host,
                "hypervisor_ip": hypervisor_ip,
                "encrypted_vms": encrypted_vms,
                "encrypted_vm_ips": encrypted_vm_ips,
                "backup_server_ip": backup_server_ip,
                "backup_target_ip": backup_target_ip,
            },
            "infra": {
                "exfil_ip": exfil_ip,
                "payload_ip": payload_ip,
                "decoy_exfil_ip": decoy_exfil_ip,
            },
            "saas": {
                "user": user,
                "oauth_app": oauth_app,
                "decoy_oauth_app": decoy_oauth_app,
                "api_uri": api_uri,
            },
            "ransomware": {
                "recovery_disable_cmd": recovery_disable_cmd,
            },
        },
        "answers": {
            "Q1": f"user:{user}",
            "Q2": f"ip:{exfil_ip}",
            "Q3": f"app:{oauth_app}",
            "Q4": f"ip:{exfil_ip}",
            "Q5": f"uri:{api_uri}",
            "Q6": "host:VM-CLUSTER01",
            "Q7": f"ip:{payload_ip}",
            "Q8": "host:VM-CLUSTER01",
            "Q9": "hosts:VM-APP01,VM-DB01",
            "Q10": f"cmd:{recovery_disable_cmd}",
        }
    }
    return cfg


def effective_config(args) -> dict:
    if args.config:
        cfg = load_config(args.config)

        # Allow output override (so you can reproduce into a new folder)
        cfg["cli"] = cfg.get("cli", {})
        cfg["cli"]["output"] = args.output if args.output else cfg["cli"].get("output", DEFAULTS["output"])

        # If user also passes seed/difficulty/noise while using --config,
        # we ignore them to preserve exact reproduction.
        return cfg

    return build_config_from_args(args)


# =========================
# GENERATORS (PCAP + LOGS)
# =========================
def create_structure(base_dir: str):
    for path in [
        base_dir,
        os.path.join(base_dir, "pcaps"),
        os.path.join(base_dir, "zeek"),
        os.path.join(base_dir, "windows"),
        os.path.join(base_dir, "saas_logs"),
        os.path.join(base_dir, "proxy"),
        os.path.join(base_dir, "metadata"),
        os.path.join(base_dir, "ctf"),
    ]:
        mkdir(path)


def generate_pcap(cfg: dict, base_dir: str):
    P = cfg["params"]
    lab = cfg["lab"]
    packets = []

    compromised = lab["hosts"]["compromised_host_ip"]
    hypervisor = lab["hosts"]["hypervisor_ip"]
    exfil_ip = lab["infra"]["exfil_ip"]
    payload_ip = lab["infra"]["payload_ip"]

    enc_vm_ips = list(lab["hosts"]["encrypted_vm_ips"].values())

    def tls_flow(src, dst, count, size):
        return [
            IP(src=src, dst=dst) /
            TCP(sport=random.randint(1024, 65535), dport=443, flags="PA") /
            Raw(load="X" * size)
            for _ in range(count)
        ]

    def ssh_flow(src, dst, pkts=12):
        return [
            IP(src=src, dst=dst) /
            TCP(sport=random.randint(1024, 65535), dport=22, flags="PA") /
            Raw(load="SSH")
            for _ in range(pkts)
        ]

    def smb_write_flow(src, dst, pkts=55):
        return [
            IP(src=src, dst=dst) /
            TCP(sport=random.randint(1024, 65535), dport=445, flags="PA") /
            Raw(load=("WRITE" * 500))
            for _ in range(pkts)
        ]

    def smb_backup_flow(src, dst, pkts=75):
        out = []
        for i in range(pkts):
            load = ("READ" * 400) if i % 2 == 0 else ("WRITE" * 400)
            out.append(
                IP(src=src, dst=dst) /
                TCP(sport=random.randint(1024, 65535), dport=445, flags="PA") /
                Raw(load=load)
            )
        return out

    # Noise TLS
    internal_net = lab["nets"]["internal_net"]
    for _ in range(P["noise_tls_sessions"]):
        src = internal_net + str(random.randint(10, 110))
        dst = random.choice(["52.23.194.12", "142.250.190.14", "13.107.42.12"])
        packets += tls_flow(src, dst, P["noise_tls_pkts_per_session"], P["noise_tls_pkt_size"])

    # Signal: exfil
    packets += tls_flow(compromised, exfil_ip, 110, 2000)

    # SSH pivot
    packets += ssh_flow(compromised, hypervisor, 12)

    # Payload download
    packets += tls_flow(hypervisor, payload_ip, 55, 3000)

    # SMB encryption-like writes (subset only)
    for ip in enc_vm_ips:
        packets += smb_write_flow(hypervisor, ip, 55)

    # Backup decoy
    if P["include_backup_smb_decoy"]:
        packets += smb_backup_flow(lab["hosts"]["backup_server_ip"], lab["hosts"]["backup_target_ip"], 75)

    # Decoy bulk TLS
    if P["include_decoy_exfil"]:
        decoy_src = lab["nets"]["server_net"] + str(random.randint(10, 90))
        packets += tls_flow(decoy_src, lab["infra"]["decoy_exfil_ip"], 85, 1800)

    random.shuffle(packets)
    wrpcap(os.path.join(base_dir, "pcaps", "cloud_hybrid_traffic.pcap"), packets)


def generate_zeek_logs(cfg: dict, base_dir: str):
    P = cfg["params"]
    lab = cfg["lab"]
    base = cfg["generator"]["generated_at_epoch"]

    compromised = lab["hosts"]["compromised_host_ip"]
    hypervisor = lab["hosts"]["hypervisor_ip"]
    exfil_ip = lab["infra"]["exfil_ip"]
    payload_ip = lab["infra"]["payload_ip"]
    decoy_exfil_ip = lab["infra"]["decoy_exfil_ip"]

    encrypted_vm_ips = lab["hosts"]["encrypted_vm_ips"]

    internal_net = lab["nets"]["internal_net"]
    server_net = lab["nets"]["server_net"]

    conn, dns, http, ssl, smb_files = [], [], [], [], []

    # DNS noise
    noise_domains = [
        "login.microsoftonline.com", "graph.microsoft.com", "teams.microsoft.com",
        "cdn.jsdelivr.net", "api.github.com", "updates.vendor.example",
        "telemetry.service.example",
    ]
    for _ in range(P["noise_dns_entries"]):
        src = internal_net + str(random.randint(10, 110))
        dns.append({
            "ts": jittered_ts(base, P["jitter_seconds"]),
            "uid": f"D{random.randint(10000, 99999)}",
            "id.orig_h": src,
            "query": random.choice(noise_domains),
            "qtype_name": "A",
            "answers": [random.choice(["13.107.42.12", "142.250.190.14", "52.23.194.12"])],
            "rcode_name": "NOERROR",
        })

    # DNS signals
    dns += [
        {
            "ts": jittered_ts(base + 60, P["jitter_seconds"]),
            "uid": "D_SIGNAL_1",
            "id.orig_h": compromised,
            "query": "api.salesforce-data.com",
            "qtype_name": "A",
            "answers": ["52.23.194.12"],
            "rcode_name": "NOERROR",
        },
        {
            "ts": jittered_ts(base + 180, P["jitter_seconds"]),
            "uid": "D_SIGNAL_2",
            "id.orig_h": compromised,
            "query": "cdn-secure-sync.net",
            "qtype_name": "A",
            "answers": [exfil_ip],
            "rcode_name": "NOERROR",
        },
        {
            "ts": jittered_ts(base + 600, P["jitter_seconds"]),
            "uid": "D_SIGNAL_3",
            "id.orig_h": hypervisor,
            "query": "stage-downloads.net",
            "qtype_name": "A",
            "answers": [payload_ip],
            "rcode_name": "NOERROR",
        },
    ]

    # HTTP noise
    for _ in range(P["noise_http_entries"]):
        src = internal_net + str(random.randint(10, 110))
        http.append({
            "ts": jittered_ts(base, P["jitter_seconds"]),
            "uid": f"H{random.randint(10000, 99999)}",
            "id.orig_h": src,
            "method": random.choice(["GET", "POST"]),
            "host": random.choice(["graph.microsoft.com", "api.github.com", "teams.microsoft.com"]),
            "uri": random.choice(["/v1.0/me", "/repos", "/api/messages", "/"]),
            "status_code": random.choice([200, 204, 301, 302]),
            "user_agent": random.choice(["Mozilla/5.0", "curl/7.81.0", "python-requests/2.28"]),
        })

    # HTTP signal: bulk export (answer Q5)
    api_uri = lab["saas"]["api_uri"]
    http.append({
        "ts": jittered_ts(base + 240, P["jitter_seconds"]),
        "uid": "H_SIGNAL_1",
        "id.orig_h": compromised,
        "method": "POST",
        "host": "api.salesforce-data.com",
        "uri": api_uri,
        "status_code": 200,
        "user_agent": "python-requests/2.28",
    })

    # SSL noise summary
    for _ in range(max(120, P["noise_tls_sessions"] // 2)):
        ssl.append({
            "ts": jittered_ts(base, P["jitter_seconds"]),
            "uid": f"S{random.randint(10000, 99999)}",
            "id.orig_h": internal_net + str(random.randint(10, 110)),
            "id.resp_h": random.choice(["52.23.194.12", "142.250.190.14", "13.107.42.12"]),
            "server_name": random.choice(["login.microsoftonline.com", "teams.microsoft.com", "cdn.jsdelivr.net"]),
            "version": random.choice(["TLSv1.2", "TLSv1.3"]),
        })

    # SSL signals
    ssl += [
        {
            "ts": jittered_ts(base + 320, P["jitter_seconds"]),
            "uid": "S_SIGNAL_EXFIL",
            "id.orig_h": compromised,
            "id.resp_h": exfil_ip,
            "server_name": "cdn-secure-sync.net",
            "version": "TLSv1.3",
        },
        {
            "ts": jittered_ts(base + 650, P["jitter_seconds"]),
            "uid": "S_SIGNAL_PAYLOAD",
            "id.orig_h": hypervisor,
            "id.resp_h": payload_ip,
            "server_name": "stage-downloads.net",
            "version": "TLSv1.2",
        },
    ]

    # conn.log noise (benign TLS)
    for _ in range(P["noise_tls_sessions"]):
        conn.append({
            "ts": jittered_ts(base, P["jitter_seconds"]),
            "uid": f"C{random.randint(10000, 99999)}",
            "id.orig_h": internal_net + str(random.randint(10, 110)),
            "id.orig_p": random.randint(1024, 65535),
            "id.resp_h": random.choice(["52.23.194.12", "142.250.190.14", "13.107.42.12"]),
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": round(random.random() * 2, 3),
            "orig_bytes": random.randint(200, 2500),
            "resp_bytes": random.randint(500, 8000),
            "conn_state": "SF",
        })

    # conn.log signals (answers Q4/Q6/Q7)
    conn += [
        {
            "ts": jittered_ts(base + 330, P["jitter_seconds"]),
            "uid": "C_SIGNAL_EXFIL",
            "id.orig_h": compromised,
            "id.orig_p": random.randint(1024, 65535),
            "id.resp_h": exfil_ip,
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 320.0,
            "orig_bytes": 10240,
            "resp_bytes": 125_000_000,
            "conn_state": "SF",
        },
        {
            "ts": jittered_ts(base + 520, P["jitter_seconds"]),
            "uid": "C_SIGNAL_SSH",
            "id.orig_h": compromised,
            "id.orig_p": random.randint(1024, 65535),
            "id.resp_h": hypervisor,
            "id.resp_p": 22,
            "proto": "tcp",
            "service": "ssh",
            "duration": 120.5,
            "orig_bytes": 2048,
            "resp_bytes": 4096,
            "conn_state": "SF",
        },
        {
            "ts": jittered_ts(base + 660, P["jitter_seconds"]),
            "uid": "C_SIGNAL_PAYLOAD",
            "id.orig_h": hypervisor,
            "id.orig_p": random.randint(1024, 65535),
            "id.resp_h": payload_ip,
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 18.2,
            "orig_bytes": 1400,
            "resp_bytes": 82_345_000,
            "conn_state": "SF",
        },
    ]

    # SMB encryption behavior (answers Q9)
    for vm, ip in encrypted_vm_ips.items():
        conn.append({
            "ts": jittered_ts(base + 720, P["jitter_seconds"]),
            "uid": f"C_SIGNAL_SMB_{vm}",
            "id.orig_h": hypervisor,
            "id.orig_p": random.randint(1024, 65535),
            "id.resp_h": ip,
            "id.resp_p": 445,
            "proto": "tcp",
            "service": "smb",
            "duration": 480.0,
            "orig_bytes": 150_000_000,
            "resp_bytes": 2048,
            "conn_state": "SF",
        })
        smb_files.append({
            "ts": jittered_ts(base + 735, P["jitter_seconds"]),
            "uid": f"F_{vm}",
            "id.orig_h": hypervisor,
            "id.resp_h": ip,
            "name": "data.db",
            "action": "SMB::FILE_WRITE",
            "note": "write-heavy pattern consistent with bulk overwrite",
        })

    # Backup SMB decoy
    if P["include_backup_smb_decoy"]:
        conn.append({
            "ts": jittered_ts(base + 900, P["jitter_seconds"]),
            "uid": "C_DECOY_BACKUP_SMB",
            "id.orig_h": lab["hosts"]["backup_server_ip"],
            "id.orig_p": random.randint(1024, 65535),
            "id.resp_h": lab["hosts"]["backup_target_ip"],
            "id.resp_p": 445,
            "proto": "tcp",
            "service": "smb",
            "duration": 600.0,
            "orig_bytes": 80_000_000,
            "resp_bytes": 75_000_000,
            "conn_state": "SF",
        })
        smb_files.append({
            "ts": jittered_ts(base + 905, P["jitter_seconds"]),
            "uid": "F_DECOY_BACKUP",
            "id.orig_h": lab["hosts"]["backup_server_ip"],
            "id.resp_h": lab["hosts"]["backup_target_ip"],
            "name": "backup.tar",
            "action": "SMB::FILE_READWRITE",
            "note": "balanced read/write typical of backup copy",
        })

    # Decoy bulk TLS (not the real exfil target)
    if P["include_decoy_exfil"]:
        decoy_src = server_net + str(random.randint(10, 90))
        conn.append({
            "ts": jittered_ts(base + 400, P["jitter_seconds"]),
            "uid": "C_DECOY_TLS_BULK",
            "id.orig_h": decoy_src,
            "id.orig_p": random.randint(1024, 65535),
            "id.resp_h": decoy_exfil_ip,
            "id.resp_p": 443,
            "proto": "tcp",
            "service": "ssl",
            "duration": 280.0,
            "orig_bytes": 9000,
            "resp_bytes": 95_000_000,
            "conn_state": "SF",
        })
        ssl.append({
            "ts": jittered_ts(base + 405, P["jitter_seconds"]),
            "uid": "S_DECOY_TLS_BULK",
            "id.orig_h": decoy_src,
            "id.resp_h": decoy_exfil_ip,
            "server_name": "backup-cloud-sync.example",
            "version": "TLSv1.3",
        })

    write_jsonl(os.path.join(base_dir, "zeek", "conn.log"), conn)
    write_jsonl(os.path.join(base_dir, "zeek", "dns.log"), dns)
    write_jsonl(os.path.join(base_dir, "zeek", "http.log"), http)
    write_jsonl(os.path.join(base_dir, "zeek", "ssl.log"), ssl)
    write_jsonl(os.path.join(base_dir, "zeek", "smb_files.log"), smb_files)


def generate_saas_logs(cfg: dict, base_dir: str):
    P = cfg["params"]
    lab = cfg["lab"]
    base = cfg["generator"]["generated_at_epoch"]

    user = lab["saas"]["user"]
    exfil_ip = lab["infra"]["exfil_ip"]
    oauth_app = lab["saas"]["oauth_app"]
    decoy_oauth_app = lab["saas"]["decoy_oauth_app"]
    api_uri = lab["saas"]["api_uri"]

    okta_logs = [
        {
            "ts": jittered_ts(base + 60, P["jitter_seconds"]),
            "eventType": "user.authentication.sso",
            "actor": {"alternateId": user},
            "client": {"ipAddress": exfil_ip},
            "outcome": {"result": "SUCCESS"},
        },
        {
            "ts": jittered_ts(base + 120, P["jitter_seconds"]),
            "eventType": "application.oauth.authorize",
            "displayMessage": f"User granted access to app: {oauth_app}",
            "client": {"ipAddress": exfil_ip},
        },
    ]

    if P["include_decoy_oauth_app"]:
        okta_logs.append({
            "ts": jittered_ts(base + 130, P["jitter_seconds"]),
            "eventType": "application.oauth.authorize",
            "displayMessage": f"User granted access to app: {decoy_oauth_app}",
            "client": {"ipAddress": random.choice(["10.0.1.10", "10.0.1.12", "10.0.1.18"])},
        })

    salesforce_api = [
        {
            "ts": jittered_ts(base + 240, P["jitter_seconds"]),
            "user": user,
            "operation": "BulkExport",
            "object": "CustomerRecords",
            "records_exported": random.randint(300_000, 600_000),
            "source_ip": exfil_ip,
            "endpoint": api_uri,
        }
    ]

    write_json(os.path.join(base_dir, "saas_logs", "okta_logs.json"), okta_logs)
    write_json(os.path.join(base_dir, "saas_logs", "salesforce_api.json"), salesforce_api)


def generate_windows_logs(cfg: dict, base_dir: str):
    P = cfg["params"]
    lab = cfg["lab"]
    base = cfg["generator"]["generated_at_epoch"]
    cmd = lab["ransomware"]["recovery_disable_cmd"]

    events = []

    # Execution on VM-CLUSTER01
    events.append({
        "ts": jittered_ts(base + 660, P["jitter_seconds"]),
        "EventID": 4688,
        "Host": "VM-CLUSTER01",
        "Process": "C:\\Temp\\shinysp1d3r.exe",
        "CommandLine": "shinysp1d3r.exe --encrypt",
    })

    # Recovery disable (answer Q10)
    events.append({
        "ts": jittered_ts(base + 670, P["jitter_seconds"]),
        "EventID": 4688,
        "Host": "VM-CLUSTER01",
        "Process": "C:\\Windows\\System32\\vssadmin.exe",
        "CommandLine": cmd,
    })

    # File overwrite indicators (answer Q9)
    for vm in lab["hosts"]["encrypted_vms"]:
        events.append({
            "ts": jittered_ts(base + 740, P["jitter_seconds"]),
            "EventID": 4663,
            "Host": vm,
            "ObjectName": "C:\\Data\\data.db",
            "AccessMask": "WRITE",
        })

    # Decoy scary PowerShell (medium/hard)
    if cfg["cli"]["difficulty"] in ("medium", "hard"):
        events.append({
            "ts": jittered_ts(base + 820, P["jitter_seconds"]),
            "EventID": 4688,
            "Host": "WS-015",
            "Process": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "CommandLine": "powershell -ExecutionPolicy Bypass -File C:\\ITTools\\backup_cleanup.ps1",
        })

    write_json(os.path.join(base_dir, "windows", "windows_events.json"), events)


def generate_timeline(cfg: dict, base_dir: str):
    P = cfg["params"]
    timeline = [
        {"time": "10:01", "event": "OAuth token granted"},
        {"time": "10:05", "event": "API bulk export begins"},
        {"time": "10:12", "event": "Data exfiltration over TLS"},
        {"time": "10:20", "event": "SSH pivot to hypervisor"},
        {"time": "10:23", "event": "Payload download"},
        {"time": "10:25", "event": "Encryption begins (subset of VMs)"},
    ]
    if P["include_backup_smb_decoy"]:
        timeline.append({"time": "10:40", "event": "Backup job runs (decoy noise)"})

    write_json(os.path.join(base_dir, "metadata", "timeline.json"), timeline)


def generate_ctf_answers(cfg: dict, base_dir: str):
    answers = cfg["answers"]
    # Write in Q order for convenience
    ordered = [answers[f"Q{i}"] for i in range(1, 11)]
    with open(os.path.join(base_dir, "ctf", "answers.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(ordered))


def export_config(cfg: dict, base_dir: str):
    # Always export config.json per run
    write_json(os.path.join(base_dir, "config.json"), cfg)
    write_json(os.path.join(base_dir, "metadata", "config.json"), cfg)


# =========================
# MAIN
# =========================
def main():
    parser = build_parser()
    args = parser.parse_args()

    if args.list_defaults:
        list_defaults_and_exit()

    cfg = effective_config(args)

    base_dir = cfg["cli"]["output"]
    create_structure(base_dir)

    # Important: if we're reproducing from config, don't reseed randomness;
    # the config already contains all derived values needed for deterministic reproduction.
    # (We still use randomness for noise payload sizes/etc, but signals/answers remain exact.)

    print("[+] ShinyHunters Lab Generator")
    print(f"[+] version     : {__version__}")
    print(f"[+] output      : {base_dir}")
    print(f"[+] seed        : {cfg['cli'].get('seed')}")
    print(f"[+] difficulty  : {cfg['cli'].get('difficulty')}")
    print(f"[+] noise       : {cfg['cli'].get('noise')}")
    if args.config:
        print(f"[+] config      : {args.config} (reproduce mode)")

    print("[+] Generating PCAP...")
    generate_pcap(cfg, base_dir)

    print("[+] Generating Zeek logs...")
    generate_zeek_logs(cfg, base_dir)

    print("[+] Generating SaaS logs...")
    generate_saas_logs(cfg, base_dir)

    print("[+] Generating Windows logs...")
    generate_windows_logs(cfg, base_dir)

    print("[+] Generating timeline...")
    generate_timeline(cfg, base_dir)

    print("[+] Generating CTF answers...")
    generate_ctf_answers(cfg, base_dir)

    print("[+] Exporting config.json...")
    export_config(cfg, base_dir)

    print("\n✅ Lab generated successfully!")
    print(f"   Compromised Host : {cfg['lab']['hosts']['compromised_host_ip']}")
    print(f"   Exfil IP         : {cfg['lab']['infra']['exfil_ip']}")
    print(f"   Payload IP       : {cfg['lab']['infra']['payload_ip']}")
    print(f"   Encrypted VMs     : {', '.join(cfg['lab']['hosts']['encrypted_vms'])}")
    print(f"   Config saved      : {os.path.join(base_dir, 'config.json')}")

if __name__ == "__main__":
    main()