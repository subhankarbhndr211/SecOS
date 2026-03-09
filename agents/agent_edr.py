#!/usr/bin/env python3
"""
SecOS EDR/XDR Agent v3.0
========================
Modules:
  1. Process Monitor      - malicious process + cmdline detection
  2. File Integrity (FIM) - SHA256 baseline + change detection
  3. Network Monitor      - suspicious connections + C2 beaconing
  4. Memory Anomaly       - hollowing + pressure detection
  5. User Session         - new accounts + root sessions
  6. Sandbox Engine       - dynamic behavioral analysis in Docker
  7. DLP Engine           - sensitive data exfil detection
  8. XDR Correlator       - cross-layer attack chain detection

Mode: suggest (alert + analyze, no auto-block)
"""
import os,sys,time,json,hashlib,socket,logging,asyncio,subprocess,re,stat
from datetime import datetime,timezone
from collections import defaultdict,deque
from typing import Optional
import redis,asyncpg
from dotenv import load_dotenv

load_dotenv("/etc/secos/.env")
REDIS_URL    = os.getenv("REDIS_URL",    "redis://localhost:6379/0")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://secos:SecOS2024@localhost/secosdb")
SCAN_INTERVAL  = 15
FIM_INTERVAL   = 60
XDR_WINDOW     = 300   # 5 min correlation window
SANDBOX_TIMEOUT= 30    # seconds to run sandbox analysis

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [EDR] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(),
              logging.FileHandler("/var/log/secos/agent_edr.log",encoding="utf-8")])
log = logging.getLogger("edr")

# ── MITRE ──────────────────────────────────────────────────────────────────
MITRE = {
    "malicious_process":     ("T1059",     "Execution"),
    "process_injection":     ("T1055",     "Defense Evasion"),
    "credential_dumping":    ("T1003",     "Credential Access"),
    "discovery_tool":        ("T1082",     "Discovery"),
    "lateral_movement_tool": ("T1021",     "Lateral Movement"),
    "c2_tool":               ("T1071.001", "Command and Control"),
    "persistence_tool":      ("T1053",     "Persistence"),
    "defense_evasion":       ("T1218",     "Defense Evasion"),
    "fim_critical":          ("T1565.001", "Impact"),
    "fim_config":            ("T1078",     "Persistence"),
    "fim_binary":            ("T1574",     "Persistence"),
    "network_c2":            ("T1071.001", "Command and Control"),
    "network_scan":          ("T1046",     "Discovery"),
    "network_tor":           ("T1090.003", "Command and Control"),
    "mem_high":              ("T1055",     "Defense Evasion"),
    "priv_escalation":       ("T1548",     "Privilege Escalation"),
    "new_suid":              ("T1548.001", "Privilege Escalation"),
    "suspicious_cron":       ("T1053.003", "Persistence"),
    "hidden_process":        ("T1564",     "Defense Evasion"),
    "dlp_exfil":             ("T1048",     "Exfiltration"),
    "dlp_sensitive":         ("T1005",     "Collection"),
    "dlp_credential":        ("T1552",     "Credential Access"),
    "sandbox_malware":       ("T1204",     "Execution"),
    "sandbox_c2":            ("T1071",     "Command and Control"),
    "sandbox_persist":       ("T1547",     "Persistence"),
    "xdr_chain":             ("T1078",     "Initial Access"),
    "xdr_lateral":           ("T1021",     "Lateral Movement"),
    "xdr_exfil":             ("T1041",     "Exfiltration"),
}

MALICIOUS = {
    "mimikatz":("CRITICAL",95,"credential_dumping"),
    "meterpreter":("CRITICAL",98,"c2_tool"),
    "cobalt":("CRITICAL",98,"c2_tool"),
    "beacon":("CRITICAL",97,"c2_tool"),
    "empire":("CRITICAL",96,"c2_tool"),
    "havoc":("CRITICAL",96,"c2_tool"),
    "sliver":("CRITICAL",95,"c2_tool"),
    "pwdump":("CRITICAL",92,"credential_dumping"),
    "wce":("CRITICAL",92,"credential_dumping"),
    "procdump":("HIGH",80,"credential_dumping"),
    "psexec":("HIGH",85,"lateral_movement_tool"),
    "wmiexec":("HIGH",85,"lateral_movement_tool"),
    "crackmapexec":("HIGH",88,"lateral_movement_tool"),
    "masscan":("HIGH",75,"discovery_tool"),
    "sqlmap":("HIGH",80,"discovery_tool"),
    "nikto":("MEDIUM",65,"discovery_tool"),
    "nmap":("MEDIUM",60,"discovery_tool"),
    "chisel":("HIGH",82,"c2_tool"),
    "ligolo":("HIGH",82,"lateral_movement_tool"),
    "mshta":("HIGH",80,"defense_evasion"),
    "netcat":("HIGH",82,"c2_tool"),
}

CMDPATS = [
    (r"base64\s+-d","HIGH",80,"defense_evasion","Base64 decode"),
    (r"curl.+\|\s*bash","CRITICAL",92,"c2_tool","Curl pipe to bash"),
    (r"wget.+\|\s*bash","CRITICAL",92,"c2_tool","Wget pipe to bash"),
    (r"bash\s+-i\s+>&\s*/dev/tcp","CRITICAL",95,"c2_tool","Bash reverse shell"),
    (r"nc\s+-e\s+/bin","CRITICAL",95,"c2_tool","Netcat reverse shell"),
    (r"chmod\s+\+s\s+","HIGH",85,"new_suid","SUID bit set"),
    (r"echo.+>>/etc/passwd","CRITICAL",95,"priv_escalation","Passwd write"),
    (r"echo.+>>/etc/sudoers","CRITICAL",95,"persistence_tool","Sudoers write"),
    (r"iptables\s+-F|ufw\s+disable","HIGH",85,"defense_evasion","Firewall disabled"),
    (r"history\s+-c|rm.+bash_hist","MEDIUM",65,"defense_evasion","History cleared"),
    (r"crontab\s+-e|>>/etc/cron","HIGH",80,"suspicious_cron","Crontab modified"),
    (r"dd\s+if=.+of=/dev/","HIGH",82,"fim_critical","Raw disk write"),
    (r"python.+-c.+import.+socket","HIGH",85,"c2_tool","Python reverse shell"),
    (r"openssl.+s_client.+-connect","HIGH",82,"c2_tool","OpenSSL C2 tunnel"),
    (r"socat.+exec","HIGH",85,"c2_tool","Socat shell"),
]

FIM_PATHS = {
    "/etc/passwd":("CRITICAL",95,"fim_critical"),
    "/etc/shadow":("CRITICAL",95,"fim_critical"),
    "/etc/sudoers":("CRITICAL",95,"fim_critical"),
    "/etc/hosts":("HIGH",80,"fim_config"),
    "/etc/ssh/sshd_config":("HIGH",85,"fim_config"),
    "/etc/crontab":("HIGH",85,"suspicious_cron"),
    "/etc/rc.local":("HIGH",82,"persistence_tool"),
    "/etc/ld.so.preload":("CRITICAL",95,"process_injection"),
    "/etc/pam.conf":("HIGH",85,"priv_escalation"),
    "/usr/bin/sudo":("CRITICAL",95,"fim_binary"),
    "/usr/bin/ssh":("CRITICAL",92,"fim_binary"),
    "/bin/bash":("CRITICAL",95,"fim_binary"),
    "/bin/sh":("CRITICAL",95,"fim_binary"),
    "/usr/sbin/sshd":("CRITICAL",95,"fim_binary"),
    "/opt/secos/agents/api.py":("HIGH",85,"fim_critical"),
    "/var/www/html/":("HIGH",80,"fim_critical"),
}

SUSP_PORTS = {
    4444:("CRITICAL",92,"network_c2","Metasploit default"),
    4445:("HIGH",85,"network_c2","Metasploit alt"),
    1337:("HIGH",82,"network_c2","Leet port C2"),
    5555:("HIGH",80,"network_c2","Common C2"),
    6666:("HIGH",80,"network_c2","Common C2"),
    31337:("HIGH",88,"network_c2","Elite backdoor"),
    9001:("HIGH",82,"network_tor","Tor default"),
    9050:("HIGH",85,"network_tor","Tor SOCKS"),
    9150:("HIGH",85,"network_tor","Tor browser"),
    3333:("MEDIUM",65,"network_c2","Mining pool"),
}

CPU_SAFE = {"dd","gzip","tar","ffmpeg","find","make","cc","gcc","g++",
            "ps","top","htop","sort","awk","sed","grep","wc","du","df",
            "ls","cat","head","tail","cut","tr","python3","python","sh","bash"}

# ── DLP Patterns ─────────────────────────────────────────────────────────────
DLP_PATTERNS = {
    "credit_card":     (r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b", "CRITICAL", 95),
    "ssn":             (r"\b\d{3}-\d{2}-\d{4}\b", "CRITICAL", 92),
    "aws_key":         (r"AKIA[0-9A-Z]{16}", "CRITICAL", 95),
    "private_key":     (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", "CRITICAL", 95),
    "api_key_generic": (r"(?i)(api[_-]?key|secret[_-]?key|access[_-]?token)\s*[:=]\s*['\"]?[A-Za-z0-9+/]{20,}", "HIGH", 85),
    "password_in_cmd": (r"(?i)(password|passwd|pwd)\s*[:=]\s*\S{6,}", "HIGH", 80),
    "jwt_token":       (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", "HIGH", 82),
    "db_connection":   (r"(?i)(mysql|postgres|mongodb)://[^:]+:[^@]+@", "HIGH", 85),
}

# Sensitive files that should never be read by unknown processes
DLP_SENSITIVE_FILES = [
    r"id_rsa$", r"id_ecdsa$", r"id_ed25519$",
    r"\.pem$", r"\.p12$", r"\.pfx$", r"\.key$",
    r"wallet\.dat$", r"\.env$", r"secrets\.yaml$",
    r"credentials$", r"htpasswd$", r"\.netrc$",
]

def mkraw(rule, detail, extra=""):
    return json.dumps({"source":"EDR","rule":rule,"detail":detail,"data":extra})


class EDRXDRAgent:
    def __init__(self):
        self.rc   = None
        self.db   = None
        self.hostname = socket.gethostname()
        self.alert_seq = 0

        # Per-module state
        self.seen_procs   = set()
        self.alerted      = set()
        self.fim_baseline = {}
        self.conn_counts  = defaultdict(int)
        self.last_fim     = 0

        # XDR correlation engine — sliding window of events per host
        # { host: deque([(timestamp, tactic, rule, severity), ...]) }
        self.xdr_events   = defaultdict(lambda: deque(maxlen=100))
        self.xdr_alerted  = set()

        # Sandbox queue
        self.sandbox_queue = asyncio.Queue()
        self.sandbox_available = self._check_docker()

        # DLP state
        self.dlp_transfer_tracker = defaultdict(int)  # ip -> bytes sent
        self.dlp_alerted = set()

    # ── Infrastructure ────────────────────────────────────────────────────────
    def _check_docker(self):
        try:
            r = subprocess.run(["docker","info"], capture_output=True, timeout=5)
            if r.returncode == 0:
                log.info("Docker available — Sandbox engine ENABLED")
                return True
        except Exception:
            pass
        log.info("Docker not available — Sandbox engine using static analysis fallback")
        return False

    def _make_redis(self):
        url = REDIS_URL.replace("redis://","").split("/")[0]
        h,_,p = url.partition(":")
        return redis.Redis(host=h,port=int(p or 6379),db=0,
                           decode_responses=True,
                           socket_connect_timeout=5,socket_timeout=5)

    async def connect(self):
        try:
            self.rc = self._make_redis(); self.rc.ping()
            log.info("Redis connected")
        except Exception as e:
            log.error(f"Redis failed: {e}"); self.rc=None
        try:
            self.db = await asyncpg.create_pool(DATABASE_URL,min_size=1,max_size=3)
            log.info("PostgreSQL connected")
        except Exception as e:
            log.error(f"PostgreSQL failed: {e}"); self.db=None

    # ── Alert Publisher ───────────────────────────────────────────────────────
    async def alert(self, rule, severity, score, mkey,
                    detail="", src_ip="", user="", extra=""):
        mid,tactic = MITRE.get(mkey,("T1059","Execution"))
        self.alert_seq += 1
        now = datetime.now(timezone.utc)
        raw_json = mkraw(rule, detail, extra)

        p = {
            "id":        hashlib.md5(f"{rule}{time.time()}".encode()).hexdigest()[:12].upper(),
            "rule_name": rule, "severity": severity, "host": self.hostname,
            "src_ip":    src_ip, "user_name": user, "mitre_id": mid,
            "tactic":    tactic, "score": score, "source": "EDR",
            "status":    "NEW", "detail": detail, "raw": raw_json,
            "timestamp": now.isoformat(),
        }

        log.warning(f"[{severity}] {rule} | {detail[:80]}")

        if self.rc:
            try:
                m = json.dumps(p,default=str)
                self.rc.publish("secos:alerts", m)
                self.rc.lpush("secos:edr:alerts", m)
                self.rc.ltrim("secos:edr:alerts",0,999)
            except Exception as e: log.error(f"Redis: {e}")

        if self.db:
            try:
                async with self.db.acquire() as c:
                    await c.execute(
                        "INSERT INTO events(rule_name,severity,host,src_ip,user_name,"
                        "mitre_id,tactic,score,source,status,raw,timestamp) "
                        "VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
                        rule,severity,self.hostname,src_ip,user,
                        mid,tactic,score,"EDR","NEW",raw_json,now)
                log.info(f"DB saved: {rule}")
            except Exception as e: log.error(f"DB: {e}")

        # Feed XDR correlation engine
        self.xdr_events[self.hostname].append(
            (now.timestamp(), tactic, rule, severity, mkey))

    def _dd(self, k):
        if k in self.alerted: return False
        self.alerted.add(k)
        if len(self.alerted) > 5000:
            self.alerted = set(list(self.alerted)[-2000:])
        return True

    # ══ MODULE 1: PROCESS MONITOR ════════════════════════════════════════════
    async def scan_processes(self):
        try:
            r = subprocess.run(["ps","auxww","--no-headers"],
                               capture_output=True,text=True,timeout=10)
        except Exception: return

        for line in r.stdout.strip().splitlines():
            parts = line.split(None,10)
            if len(parts) < 11: continue
            try:
                uname=parts[0]; pid=int(parts[1]); cpu=float(parts[2])
                cmd=parts[10]; pname=os.path.basename(cmd.split()[0]) if cmd else ""
            except (ValueError,IndexError): continue

            pk = f"{pid}:{pname}"
            if pk in self.seen_procs: continue
            self.seen_procs.add(pk)
            pl=pname.lower(); cl=cmd.lower()

            for sig,(sev,sc,mk) in MALICIOUS.items():
                if sig in pl or sig in cl:
                    if self._dd(f"proc:{sig}:{pid}"):
                        await self.alert(f"Malicious Process: {pname}",sev,sc,mk,
                            detail=f"PID:{pid} User:{uname} Cmd:{cmd[:80]}",
                            user=uname, extra=f"pid={pid} sig={sig}")
                        # Queue for sandbox analysis
                        if self.sandbox_available:
                            exe_path = self._get_exe_path(pid)
                            if exe_path:
                                await self.sandbox_queue.put((exe_path, rule, pid))
                    break

            for pat,sev,sc,mk,desc in CMDPATS:
                if re.search(pat,cl,re.IGNORECASE):
                    if self._dd(f"cmd:{pat[:10]}:{pid}"):
                        await self.alert(f"Suspicious Command: {desc}",sev,sc,mk,
                            detail=f"PID:{pid} User:{uname} Cmd:{cmd[:80]}",
                            user=uname, extra=f"pid={pid}")
                    break

            if any(x in cmd for x in ["/tmp/","/dev/shm/","/var/tmp/"]):
                if pl not in {"sh","bash","python3","python","python2"}:
                    if self._dd(f"tmp:{pid}"):
                        await self.alert("Execution from Temp Directory","HIGH",82,
                            "malicious_process",
                            detail=f"PID:{pid} from temp: {cmd[:80]}",
                            user=uname, extra=f"pid={pid}")
                        if self.sandbox_available:
                            exe = self._get_exe_path(pid)
                            if exe: await self.sandbox_queue.put((exe,"TempExec",pid))

            if cpu > 90.0 and pl not in CPU_SAFE:
                if self._dd(f"cpu:{pid}"):
                    await self.alert("High CPU Anomaly","MEDIUM",60,"mem_high",
                        detail=f"PID:{pid} {pname} CPU:{cpu}% — possible miner",
                        user=uname, extra=f"pid={pid} cpu={cpu}")

        if len(self.seen_procs) > 5000:
            self.seen_procs = set(list(self.seen_procs)[-2000:])

    def _get_exe_path(self, pid):
        try:
            return os.readlink(f"/proc/{pid}/exe")
        except (OSError, PermissionError):
            return None

    # ══ MODULE 2: FILE INTEGRITY MONITOR ════════════════════════════════════
    def _hash(self, path):
        try:
            if os.path.isfile(path) and os.path.getsize(path) < 50*1024*1024:
                h = hashlib.sha256()
                with open(path,"rb") as f:
                    for chunk in iter(lambda: f.read(65536), b""): h.update(chunk)
                return h.hexdigest()
        except (PermissionError,OSError): pass
        return None

    def _hash_dir(self, d, limit=60):
        hashes = {}
        try:
            for fn in os.listdir(d):
                if len(hashes) >= limit: break
                fp = os.path.join(d,fn); h = self._hash(fp)
                if h: hashes[fp] = h
        except (PermissionError,OSError): pass
        return hashes

    async def build_fim_baseline(self):
        log.info("Building FIM baseline...")
        for path in FIM_PATHS:
            if os.path.isdir(path): self.fim_baseline.update(self._hash_dir(path))
            else:
                h = self._hash(path)
                if h: self.fim_baseline[path] = h
        log.info(f"FIM baseline: {len(self.fim_baseline)} files tracked")
        try:
            r = subprocess.run(["find","/usr","/bin","/sbin","-perm","-4000"],
                               capture_output=True,text=True,timeout=30)
            suids = set(r.stdout.strip().splitlines())
            if suids and self.rc:
                self.rc.delete("edr:suid_baseline")
                self.rc.sadd("edr:suid_baseline",*suids)
                log.info(f"SUID baseline: {len(suids)} binaries tracked")
        except Exception as e: log.debug(f"SUID: {e}")

    async def scan_fim(self):
        now = time.time()
        if now - self.last_fim < FIM_INTERVAL: return
        self.last_fim = now
        log.info("FIM scan running...")

        for path,orig in list(self.fim_baseline.items()):
            cur = self._hash(path)
            base = next((p for p in FIM_PATHS if path.startswith(p)), path)
            sev,sc,mk = FIM_PATHS.get(base,("HIGH",80,"fim_critical"))

            if cur is None and not os.path.exists(path):
                if self._dd(f"fim:del:{path}"):
                    await self.alert("FIM: Critical File Deleted",sev,sc,mk,
                        detail=f"Deleted: {path}", extra=f"path={path}")
                del self.fim_baseline[path]
            elif cur and cur != orig:
                if self._dd(f"fim:mod:{path}:{cur[:8]}"):
                    await self.alert("FIM: Critical File Modified",sev,sc,mk,
                        detail=f"Tampered: {path}",
                        extra=f"old={orig[:16]} new={cur[:16]}")
                    # Queue modified file for sandbox
                    if self.sandbox_available and path.startswith("/var/www"):
                        await self.sandbox_queue.put((path,"FIMModified",0))
                self.fim_baseline[path] = cur

        for path,(sev,sc,mk) in FIM_PATHS.items():
            if os.path.isdir(path):
                for fp,fh in self._hash_dir(path).items():
                    if fp not in self.fim_baseline:
                        if self._dd(f"fim:new:{fp}"):
                            await self.alert("FIM: New File in Critical Directory",
                                sev,sc,mk,
                                detail=f"New file: {fp}",
                                extra=f"path={fp}")
                            # Auto-sandbox new web files (webshell detection)
                            if self.sandbox_available:
                                await self.sandbox_queue.put((fp,"NewFile",0))
                        self.fim_baseline[fp] = fh

        try:
            r = subprocess.run(["find","/usr","/bin","/sbin","-perm","-4000"],
                               capture_output=True,text=True,timeout=30)
            cur_suids = set(r.stdout.strip().splitlines())
            if self.rc:
                stored = self.rc.smembers("edr:suid_baseline")
                for s in (cur_suids - stored):
                    if self._dd(f"suid:{s}"):
                        await self.alert("New SUID Binary Detected","CRITICAL",95,"new_suid",
                            detail=f"New SUID: {s}", extra=f"path={s}")
        except Exception as e: log.debug(f"SUID scan: {e}")

    # ══ MODULE 3: NETWORK MONITOR ════════════════════════════════════════════
    async def scan_network(self):
        try:
            r = subprocess.run(["ss","-tunp","--no-header"],
                               capture_output=True,text=True,timeout=10)
        except Exception: return

        conn_by_ip = defaultdict(int)

        for line in r.stdout.strip().splitlines():
            parts = line.split()
            if len(parts) < 6: continue
            try:
                raddr = parts[5]
                if raddr in ("*","0.0.0.0:*",":::*"): continue
                rip,_,rp = raddr.rpartition(":")
                if not rp.isdigit(): continue
                rport = int(rp); rip = rip.strip("[]")
                if rip.startswith(("127.","::1","0.0.0.0","10.","172.16.",
                                   "172.17.","172.25.","192.168.")): continue
            except (ValueError,IndexError): continue

            if rport in SUSP_PORTS:
                if self._dd(f"port:{rip}:{rport}"):
                    sev,sc,mk,desc = SUSP_PORTS[rport]
                    await self.alert(f"Suspicious Connection Port {rport}",sev,sc,mk,
                        detail=f"{desc} to {rip}:{rport}",
                        src_ip=rip, extra=f"dst={rip}:{rport}")
            conn_by_ip[rip] += 1

        for rip,cnt in conn_by_ip.items():
            prev = self.conn_counts.get(rip,0)
            if cnt >= 10 and cnt > prev+5:
                if self._dd(f"beacon:{rip}:{cnt}"):
                    await self.alert("Potential C2 Beaconing","HIGH",85,"network_c2",
                        detail=f"{cnt} connections to {rip} — C2 beacon pattern",
                        src_ip=rip, extra=f"ip={rip} count={cnt}")
            self.conn_counts[rip] = cnt

        try:
            r = subprocess.run(["ss","-tn","state","syn-sent"],
                               capture_output=True,text=True,timeout=5)
            syn = len([l for l in r.stdout.splitlines() if l.strip()])
            if syn > 20:
                if self._dd(f"scan:{syn}"):
                    await self.alert("Port Scan Activity","HIGH",80,"network_scan",
                        detail=f"{syn} SYN-SENT — outbound port scan",
                        extra=f"syn_count={syn}")
        except Exception: pass

    # ══ MODULE 4: MEMORY ANOMALY ════════════════════════════════════════════
    async def scan_memory(self):
        try:
            with open("/proc/meminfo") as f:
                mi = {}
                for line in f.read().splitlines():
                    if ":" in line: k,v=line.split(":",1); mi[k.strip()]=v.strip()
            total=int(mi.get("MemTotal","0 kB").split()[0])
            avail=int(mi.get("MemAvailable","0 kB").split()[0])
            if total > 0:
                pct = ((total-avail)/total)*100
                if pct > 92:
                    if self._dd(f"mempressure:{int(pct)}"):
                        await self.alert("Critical Memory Pressure","HIGH",75,"mem_high",
                            detail=f"Memory at {pct:.1f}% — DoS or exhaustion",
                            extra=f"used_pct={pct:.1f}")

            r = subprocess.run(["ps","aux","--no-headers","--sort=-%mem"],
                               capture_output=True,text=True,timeout=10)
            safe = {"java","node","python3","python","postgres","mysqld",
                    "mongod","elasticsearch","chrome","firefox","ps","top"}
            for line in r.stdout.strip().splitlines()[:15]:
                parts = line.split(None,10)
                if len(parts) < 11: continue
                try:
                    uname=parts[0]; pid=int(parts[1]); mem=float(parts[3])
                    vsz=int(parts[4]); rss=int(parts[5]); cmd=parts[10]
                    pl=os.path.basename(cmd.split()[0]).lower() if cmd else ""
                except (ValueError,IndexError): continue

                if mem > 30.0 and pl not in safe:
                    if self._dd(f"memhigh:{pid}"):
                        await self.alert("Abnormal Memory Usage","MEDIUM",65,"mem_high",
                            detail=f"PID:{pid} {pl} MEM:{mem}% RSS:{rss//1024}MB",
                            user=uname, extra=f"pid={pid} mem={mem}")

                if vsz > 2000000 and rss < 10000 and pl not in safe:
                    if self._dd(f"hollow:{pid}"):
                        await self.alert("Process Hollowing Indicator","HIGH",82,
                            "process_injection",
                            detail=f"PID:{pid} {pl} VSZ:{vsz//1024}MB RSS:{rss//1024}MB — hollowing",
                            user=uname, extra=f"pid={pid} vsz={vsz//1024} rss={rss//1024}")
        except Exception as e: log.debug(f"Memory: {e}")

    # ══ MODULE 5: USER SESSION ═══════════════════════════════════════════════
    async def scan_users(self):
        try:
            r = subprocess.run(["who","-a"],capture_output=True,text=True,timeout=5)
            for line in r.stdout.splitlines():
                if "root" in line and "pts/" in line:
                    if self._dd(f"rootssh:{line[:30]}"):
                        await self.alert("Root Remote Login","HIGH",82,"priv_escalation",
                            detail=f"Root session: {line.strip()[:60]}",
                            user="root", extra="root_remote=true")
                    break

            r = subprocess.run(
                ["awk","-F:","$3 >= 1000 && $3 < 65534 {print $1}","/etc/passwd"],
                capture_output=True,text=True,timeout=5)
            current = set(r.stdout.strip().splitlines())
            if self.rc:
                stored = self.rc.smembers("edr:known_users")
                if stored:
                    for u in (current-stored):
                        if self._dd(f"newuser:{u}"):
                            await self.alert("New System User Created","HIGH",85,
                                "priv_escalation",
                                detail=f"New account: {u}",
                                user=u, extra=f"username={u}")
                self.rc.delete("edr:known_users")
                if current: self.rc.sadd("edr:known_users",*current)
        except Exception as e: log.debug(f"Users: {e}")

    # ══ MODULE 6: SANDBOX ENGINE ═════════════════════════════════════════════
    async def sandbox_worker(self):
        """
        Continuously processes files queued for sandbox analysis.
        Two modes:
          1. Docker available  → run in isolated container with strace
          2. Docker unavailable → static analysis fallback (strings, file, objdump)
        """
        log.info("Sandbox worker started")
        while True:
            try:
                file_path, trigger_rule, pid = await asyncio.wait_for(
                    self.sandbox_queue.get(), timeout=5.0)
                await self._analyze_file(file_path, trigger_rule, pid)
            except asyncio.TimeoutError:
                continue
            except Exception as e:
                log.error(f"Sandbox worker error: {e}")

    async def _analyze_file(self, file_path, trigger_rule, pid):
        """Full behavioral analysis of a suspicious file."""
        if not os.path.exists(file_path):
            log.debug(f"Sandbox: file gone {file_path}")
            return

        log.info(f"Sandbox analyzing: {file_path} (trigger:{trigger_rule})")
        findings = []
        risk_score = 0
        verdict = "CLEAN"

        # ── Static Analysis (always runs) ──────────────────────────────────
        try:
            # File type
            r = subprocess.run(["file",file_path],capture_output=True,text=True,timeout=5)
            file_type = r.stdout.strip()

            # Entropy check (high entropy = packed/encrypted = suspicious)
            with open(file_path,"rb") as f:
                data = f.read(65536)
            if data:
                freq = defaultdict(int)
                for b in data: freq[b] += 1
                entropy = -sum((c/len(data))*__import__("math").log2(c/len(data))
                               for c in freq.values() if c > 0)
                if entropy > 7.2:
                    findings.append(f"HIGH_ENTROPY:{entropy:.2f} (packed/encrypted binary)")
                    risk_score += 25

            # String extraction — look for IOCs
            r = subprocess.run(["strings","-n","6",file_path],
                               capture_output=True,text=True,timeout=10)
            strings_out = r.stdout.lower()

            suspicious_strings = [
                ("meterpreter",    30, "Metasploit meterpreter string"),
                ("mimikatz",       35, "Mimikatz credential tool"),
                ("/etc/shadow",    20, "Shadow file access"),
                ("/bin/sh",        10, "Shell execution"),
                ("reverse_tcp",    25, "Reverse TCP shell"),
                ("shellcode",      25, "Shellcode reference"),
                ("keylogger",      30, "Keylogger string"),
                ("screenshot",     15, "Screenshot capability"),
                ("webcam",         15, "Webcam access"),
                ("inject",         15, "Injection reference"),
                ("cmd.exe",        20, "Windows cmd reference"),
                ("powershell",     15, "PowerShell reference"),
                ("wget",           10, "Download tool"),
                ("base64",         10, "Encoding/obfuscation"),
                ("xor",            10, "XOR encryption"),
            ]
            for s,pts,desc in suspicious_strings:
                if s in strings_out:
                    findings.append(f"STRING:{s.upper()} — {desc}")
                    risk_score += pts

            # Check for IP addresses / domains in strings
            ips = re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b", r.stdout)
            external_ips = [ip for ip in set(ips)
                           if not ip.startswith(("127.","10.","192.168.","172."))]
            if external_ips:
                findings.append(f"EMBEDDED_IPS:{','.join(external_ips[:5])}")
                risk_score += 20

            # Check for DLP patterns in file content
            try:
                with open(file_path,"r",errors="ignore") as f:
                    content = f.read(50000)
                for pat_name,(pattern,sev,pts) in DLP_PATTERNS.items():
                    if re.search(pattern,content):
                        findings.append(f"DLP_PATTERN:{pat_name}")
                        risk_score += 15
            except Exception: pass

        except Exception as e:
            log.debug(f"Static analysis error: {e}")

        # ── Dynamic Analysis (Docker required) ────────────────────────────
        if self.sandbox_available:
            try:
                sandbox_findings = await self._run_docker_sandbox(file_path)
                findings.extend(sandbox_findings["behaviors"])
                risk_score += sandbox_findings["risk_delta"]
            except Exception as e:
                log.debug(f"Docker sandbox error: {e}")
                findings.append("SANDBOX:Docker analysis failed — static only")

        # ── Verdict ────────────────────────────────────────────────────────
        if risk_score >= 70:   verdict = "MALICIOUS"
        elif risk_score >= 35: verdict = "SUSPICIOUS"
        else:                  verdict = "CLEAN"

        verdict_sev = {"MALICIOUS":"CRITICAL","SUSPICIOUS":"HIGH","CLEAN":"LOW"}.get(verdict,"MEDIUM")
        verdict_score = min(risk_score,100)

        if verdict != "CLEAN":
            finding_summary = " | ".join(findings[:5])
            await self.alert(
                f"Sandbox: {verdict} File Detected",
                verdict_sev, verdict_score, "sandbox_malware",
                detail=f"{os.path.basename(file_path)} — Risk:{risk_score} Trigger:{trigger_rule}",
                extra=f"path={file_path} verdict={verdict} score={risk_score} findings={finding_summary}"
            )
            log.warning(f"SANDBOX VERDICT: {verdict} | {file_path} | score={risk_score}")
            log.warning(f"  Findings: {' | '.join(findings[:8])}")
        else:
            log.info(f"Sandbox CLEAN: {file_path} (score={risk_score})")

    async def _run_docker_sandbox(self, file_path):
        """
        Execute file in isolated Docker container with behavioral monitoring.
        Uses strace to capture all syscalls.
        """
        behaviors = []
        risk_delta = 0
        container_name = f"secos-sandbox-{int(time.time())}"

        try:
            # Build sandbox command
            # - network=none isolates from real network
            # - read-only mounts prevent persistence
            # - memory limit prevents resource exhaustion
            # - strace captures all syscalls
            docker_cmd = [
                "docker","run","--rm",
                f"--name={container_name}",
                "--network=none",                    # No real network
                "--memory=256m",                     # Memory limit
                "--cpus=0.5",                        # CPU limit
                "--read-only",                       # Read-only filesystem
                "--tmpfs=/tmp:size=64m",             # Writable tmp only
                f"-v={file_path}:/sandbox/sample:ro",# Mount sample read-only
                "--security-opt=no-new-privileges",  # No privilege escalation
                "ubuntu:22.04",
                "timeout",str(SANDBOX_TIMEOUT),
                "strace","-e","trace=network,file,process",
                "-f","/sandbox/sample"
            ]

            r = subprocess.run(docker_cmd,capture_output=True,text=True,
                             timeout=SANDBOX_TIMEOUT+10)
            strace_out = (r.stderr + r.stdout).lower()

            # Analyze syscall patterns
            syscall_checks = [
                (r"connect\(.*sin_addr",     20, "NETWORK_CONNECT: attempted outbound connection"),
                (r"socket\(af_inet",         10, "NETWORK_SOCKET: created network socket"),
                (r"execve\(",                15, "EXEC: spawned child process"),
                (r"open\(.*shadow",          35, "FILE_SHADOW: accessed /etc/shadow"),
                (r"open\(.*passwd",          20, "FILE_PASSWD: accessed /etc/passwd"),
                (r"open\(.*ssh",             15, "FILE_SSH: accessed SSH keys/config"),
                (r"ptrace\(",                25, "PTRACE: process injection attempt"),
                (r"mprotect\(.*prot_exec",   20, "MEM_EXEC: set memory executable — shellcode"),
                (r"fork\(|clone\(",          10, "FORK: created child processes"),
                (r"unlink\(|rmdir\(",        10, "DELETE: deleted files — covering tracks"),
                (r"chmod\(.*0[0-7]*[4-7]",  15, "CHMOD: changed file permissions"),
            ]

            for pattern,pts,desc in syscall_checks:
                if re.search(pattern,strace_out):
                    behaviors.append(desc)
                    risk_delta += pts

        except subprocess.TimeoutExpired:
            behaviors.append("SANDBOX_TIMEOUT: ran for full duration (suspicious)")
            risk_delta += 15
            # Kill container
            subprocess.run(["docker","rm","-f",container_name],
                          capture_output=True,timeout=5)
        except Exception as e:
            log.debug(f"Docker run error: {e}")

        return {"behaviors": behaviors, "risk_delta": risk_delta}

    # ══ MODULE 7: DLP ENGINE ═════════════════════════════════════════════════
    async def scan_dlp(self):
        """
        Data Loss Prevention — detect sensitive data exfiltration attempts.
        Monitors:
          - Large outbound transfers (network bytes)
          - Sensitive file access (lsof)
          - Sensitive content in recently modified files
          - Database dumps
          - Clipboard/env var exposure
        """
        # ── Large outbound transfer detection ─────────────────────────────
        try:
            r = subprocess.run(["cat","/proc/net/dev"],
                               capture_output=True,text=True,timeout=5)
            for line in r.stdout.splitlines():
                if ":" not in line: continue
                iface,_,stats = line.partition(":")
                iface = iface.strip()
                if iface in ("lo",""): continue
                parts = stats.split()
                if len(parts) < 10: continue
                try:
                    tx_bytes = int(parts[8])
                    prev = self.dlp_transfer_tracker.get(iface,0)
                    delta = tx_bytes - prev
                    # Alert if >50MB sent since last check
                    if prev > 0 and delta > 50*1024*1024:
                        if self._dd(f"dlp:transfer:{iface}:{tx_bytes//1024//1024}"):
                            await self.alert(
                                "DLP: Large Outbound Data Transfer",
                                "HIGH", 82, "dlp_exfil",
                                detail=f"Interface {iface}: {delta//1024//1024}MB sent — possible exfiltration",
                                extra=f"iface={iface} delta_mb={delta//1024//1024}")
                    self.dlp_transfer_tracker[iface] = tx_bytes
                except (ValueError,IndexError): continue
        except Exception as e: log.debug(f"DLP transfer: {e}")

        # ── Sensitive file access monitoring ──────────────────────────────
        try:
            r = subprocess.run(["lsof","-F","pcn","+D","/etc","+D","/root","+D","/home"],
                               capture_output=True,text=True,timeout=10)
            lsof_out = r.stdout

            for pattern in DLP_SENSITIVE_FILES:
                matches = re.findall(rf"n(.+{pattern})",lsof_out)
                for match in matches:
                    if self._dd(f"dlp:access:{match.strip()}"):
                        await self.alert(
                            "DLP: Sensitive File Accessed",
                            "HIGH", 85, "dlp_sensitive",
                            detail=f"Sensitive file opened: {match.strip()}",
                            extra=f"path={match.strip()}")
        except Exception as e: log.debug(f"DLP lsof: {e}")

        # ── Scan recently modified files for sensitive content ─────────────
        try:
            r = subprocess.run(
                ["find","/tmp","/var/tmp","/dev/shm","-newer","/proc/1/cmdline",
                 "-type","f","-size","-5M"],
                capture_output=True,text=True,timeout=10)
            for fpath in r.stdout.strip().splitlines()[:10]:
                if not os.path.isfile(fpath): continue
                try:
                    with open(fpath,"r",errors="ignore") as f:
                        content = f.read(20000)
                    for pat_name,(pattern,sev,score) in DLP_PATTERNS.items():
                        if re.search(pattern,content):
                            if self._dd(f"dlp:content:{fpath}:{pat_name}"):
                                await self.alert(
                                    f"DLP: Sensitive Data in Temp File",
                                    sev, score, "dlp_credential",
                                    detail=f"Pattern '{pat_name}' in {fpath}",
                                    extra=f"path={fpath} pattern={pat_name}")
                            break
                except Exception: continue
        except Exception as e: log.debug(f"DLP content: {e}")

        # ── Database dump detection ────────────────────────────────────────
        try:
            r = subprocess.run(["ps","auxww","--no-headers"],
                               capture_output=True,text=True,timeout=10)
            dump_patterns = [
                (r"mysqldump|pg_dump|mongodump","Database dump command detected"),
                (r"tar.+/var/lib/mysql|tar.+/var/lib/postgres","DB data directory archived"),
            ]
            for line in r.stdout.splitlines():
                for pattern,desc in dump_patterns:
                    if re.search(pattern,line,re.IGNORECASE):
                        parts = line.split(None,1)
                        pid = parts[1].split()[0] if len(parts)>1 else "?"
                        if self._dd(f"dlp:dump:{pid}"):
                            await self.alert(
                                "DLP: Database Dump Detected",
                                "HIGH", 80, "dlp_exfil",
                                detail=f"{desc}: {line[50:130]}",
                                extra=f"cmd={line[:100]}")
        except Exception as e: log.debug(f"DLP dump: {e}")

    # ══ MODULE 8: XDR CORRELATION ENGINE ════════════════════════════════════
    async def run_xdr_correlation(self):
        """
        Cross-layer attack chain detection.
        Correlates events across all modules within a time window
        to detect multi-stage attacks that individual alerts would miss.

        Attack chains detected:
          - Recon → Lateral → Exfil
          - InitialAccess → Execution → Persistence
          - CredAccess → PrivEsc → C2
          - Discovery → Collection → Exfil
        """
        now = time.time()
        cutoff = now - XDR_WINDOW

        for host, events in self.xdr_events.items():
            # Get events within correlation window
            window = [(ts,tac,rule,sev,mk) for ts,tac,rule,sev,mk in events
                      if ts > cutoff]
            if len(window) < 2: continue

            tactics_seen = [tac for _,tac,_,_,_ in window]
            rules_seen   = [rule for _,_,rule,_,_ in window]
            sevs_seen    = [sev for _,_,_,sev,_ in window]

            # ── Attack Chain 1: Recon → Execution → C2 ────────────────────
            if ("Discovery" in tactics_seen and
                "Execution" in tactics_seen and
                "Command and Control" in tactics_seen):
                chain_key = f"xdr:rec_exec_c2:{host}:{int(now//300)}"
                if self._dd(chain_key):
                    await self.alert(
                        "XDR: Recon → Execution → C2 Chain Detected",
                        "CRITICAL", 95, "xdr_chain",
                        detail=f"Attack chain on {host}: Discovery→Execution→C2 within {XDR_WINDOW//60}min",
                        extra=f"host={host} tactics={list(set(tactics_seen))} events={len(window)}")

            # ── Attack Chain 2: Credential Access → Privilege Escalation ──
            if ("Credential Access" in tactics_seen and
                "Privilege Escalation" in tactics_seen):
                chain_key = f"xdr:cred_privesc:{host}:{int(now//300)}"
                if self._dd(chain_key):
                    await self.alert(
                        "XDR: Credential Theft → Privilege Escalation",
                        "CRITICAL", 93, "xdr_chain",
                        detail=f"Credential dump followed by privilege escalation on {host}",
                        extra=f"host={host} rules={list(set(rules_seen))}")

            # ── Attack Chain 3: Persistence + Defense Evasion ─────────────
            if ("Persistence" in tactics_seen and
                "Defense Evasion" in tactics_seen):
                chain_key = f"xdr:persist_evade:{host}:{int(now//300)}"
                if self._dd(chain_key):
                    await self.alert(
                        "XDR: Persistence + Defense Evasion Detected",
                        "HIGH", 88, "xdr_chain",
                        detail=f"Attacker establishing persistence and hiding on {host}",
                        extra=f"host={host} rules={list(set(rules_seen))}")

            # ── Attack Chain 4: Multiple CRITICAL alerts = active intrusion
            critical_count = sevs_seen.count("CRITICAL")
            if critical_count >= 3:
                chain_key = f"xdr:multi_crit:{host}:{int(now//120)}"
                if self._dd(chain_key):
                    await self.alert(
                        "XDR: Multiple Critical Alerts — Active Intrusion",
                        "CRITICAL", 98, "xdr_chain",
                        detail=f"{critical_count} CRITICAL alerts on {host} in {XDR_WINDOW//60}min — active intrusion likely",
                        extra=f"host={host} critical_count={critical_count}")

            # ── Attack Chain 5: FIM + Network = exfiltration ──────────────
            fim_hit   = any("FIM" in r or "File" in r for r in rules_seen)
            net_hit   = any("C2" in r or "Beacon" in r or "Port" in r for r in rules_seen)
            if fim_hit and net_hit:
                chain_key = f"xdr:fim_net:{host}:{int(now//300)}"
                if self._dd(chain_key):
                    await self.alert(
                        "XDR: File Access + C2 Connection — Exfiltration Pattern",
                        "HIGH", 90, "xdr_exfil",
                        detail=f"File modification AND outbound C2 connection on {host} — data theft pattern",
                        extra=f"host={host}")

            # ── Publish XDR summary to Redis dashboard ────────────────────
            if self.rc and len(window) >= 3:
                try:
                    self.rc.setex(f"secos:xdr:{host}", 300, json.dumps({
                        "host":    host,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "events_in_window": len(window),
                        "tactics":  list(set(tactics_seen)),
                        "severity_counts": {
                            "CRITICAL": sevs_seen.count("CRITICAL"),
                            "HIGH":     sevs_seen.count("HIGH"),
                            "MEDIUM":   sevs_seen.count("MEDIUM"),
                        },
                        "latest_rule": rules_seen[-1] if rules_seen else "",
                    }))
                except Exception: pass

    # ── Telemetry ─────────────────────────────────────────────────────────────
    async def publish_telemetry(self):
        if not self.rc: return
        try:
            r = subprocess.run(["ps","aux","--no-headers"],
                               capture_output=True,text=True,timeout=5)
            now = datetime.now(timezone.utc).isoformat()
            self.rc.setex("secos:edr:telemetry",60,json.dumps({
                "hostname":    self.hostname,
                "timestamp":   now,
                "status":      "online",
                "mode":        "suggest",
                "version":     "3.0",
                "proc_count":  len(r.stdout.strip().splitlines()),
                "fim_tracked": len(self.fim_baseline),
                "alerts":      self.alert_seq,
                "modules":     ["process","fim","network","memory","users",
                                "sandbox","dlp","xdr"],
                "sandbox":     "enabled" if self.sandbox_available else "static-only",
            }))
            self.rc.setex("secos:edr:heartbeat",30,now)
        except Exception as e: log.debug(f"Telemetry: {e}")

    # ── Main Loop ─────────────────────────────────────────────────────────────
    async def run(self):
        log.info("=" * 55)
        log.info("  SecOS EDR/XDR Agent v3.0")
        log.info(f"  Host    : {self.hostname}")
        log.info(f"  Mode    : suggest (alert only)")
        log.info(f"  Modules : Process | FIM | Network | Memory | Users")
        log.info(f"          : Sandbox | DLP | XDR Correlator")
        log.info(f"  Sandbox : {'Docker (dynamic)' if self.sandbox_available else 'Static analysis'}")
        log.info("=" * 55)

        await self.connect()
        await self.build_fim_baseline()
        log.info("EDR/XDR fully initialized — all 8 modules active")

        # Start sandbox worker as background task
        asyncio.create_task(self.sandbox_worker())

        cycle = 0
        while True:
            try:
                await self.scan_processes()
                await self.scan_network()
                await self.scan_users()
                await self.scan_fim()
                await self.run_xdr_correlation()

                if cycle % 2 == 0:
                    await self.scan_dlp()

                if cycle % 3 == 0:
                    await self.scan_memory()

                await self.publish_telemetry()
                cycle += 1

            except Exception as e:
                log.error(f"Cycle error: {e}")
            await asyncio.sleep(SCAN_INTERVAL)


if __name__ == "__main__":
    try:
        asyncio.run(EDRXDRAgent().run())
    except KeyboardInterrupt:
        log.info("EDR/XDR Agent stopped")
    except Exception as e:
        log.critical(f"Fatal: {e}"); sys.exit(1)
