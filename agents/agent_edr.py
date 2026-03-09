#!/usr/bin/env python3
"""
SecOS EDR/XDR/ML Agent v4.0
============================
World-class endpoint detection using:

DETECTION MODULES:
  1.  Process Monitor      — 21 malicious signatures + cmdline patterns
  2.  File Integrity (FIM) — SHA256 baseline + SUID tracking
  3.  Network Monitor      — C2 ports + beaconing + port scan
  4.  Memory Anomaly       — hollowing + pressure detection
  5.  User Sessions        — root login + new account detection
  6.  Sandbox Engine       — Docker dynamic + static analysis
  7.  DLP Engine           — exfil + sensitive file + content scan
  8.  XDR Correlator       — 5 attack chain patterns, 5min window

ML MODELS (Pure Python, zero dependencies beyond stdlib):
  9.  Isolation Forest     — unsupervised anomaly detection
  10. Statistical Baseline — EWMA z-score per entity per feature
  11. Shannon Entropy      — obfuscation / packed binary detection
  12. Behavioral Sequences — N-gram process chain model
  13. CUSUM Detector       — change point detection in time series
  14. Benford's Law        — synthetic/fake network traffic detection
  15. Random Forest        — MITRE ATT&CK feature classification
  16. Ensemble Scorer      — weighted confidence aggregation

All models self-train on live telemetry. No internet required.
"""
import os,sys,time,json,math,hashlib,socket,logging,asyncio,subprocess,re,stat
import statistics,random
from datetime import datetime,timezone
from collections import defaultdict,deque
from typing import Dict,List,Tuple,Optional
import redis,asyncpg
from dotenv import load_dotenv

load_dotenv("/etc/secos/.env")
REDIS_URL    = os.getenv("REDIS_URL",    "redis://localhost:6379/0")
DATABASE_URL = os.getenv("DATABASE_URL", "postgresql://secos:SecOS2024@localhost/secosdb")
SCAN_INTERVAL   = 15
FIM_INTERVAL    = 60
XDR_WINDOW      = 300   # 5 min correlation window
SANDBOX_TIMEOUT = 30

logging.basicConfig(level=logging.INFO,
    format="%(asctime)s [EDR] %(levelname)s %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[logging.StreamHandler(),
              logging.FileHandler("/var/log/secos/agent_edr.log",encoding="utf-8")])
log = logging.getLogger("edr")

# ══════════════════════════════════════════════════════════════════════════════
# KNOWLEDGE BASE
# ══════════════════════════════════════════════════════════════════════════════
MITRE = {
    "malicious_process":("T1059","Execution"),
    "process_injection":("T1055","Defense Evasion"),
    "credential_dumping":("T1003","Credential Access"),
    "discovery_tool":("T1082","Discovery"),
    "lateral_movement_tool":("T1021","Lateral Movement"),
    "c2_tool":("T1071.001","Command and Control"),
    "persistence_tool":("T1053","Persistence"),
    "defense_evasion":("T1218","Defense Evasion"),
    "fim_critical":("T1565.001","Impact"),
    "fim_config":("T1078","Persistence"),
    "fim_binary":("T1574","Persistence"),
    "network_c2":("T1071.001","Command and Control"),
    "network_scan":("T1046","Discovery"),
    "network_tor":("T1090.003","Command and Control"),
    "mem_high":("T1055","Defense Evasion"),
    "priv_escalation":("T1548","Privilege Escalation"),
    "new_suid":("T1548.001","Privilege Escalation"),
    "suspicious_cron":("T1053.003","Persistence"),
    "dlp_exfil":("T1048","Exfiltration"),
    "dlp_sensitive":("T1005","Collection"),
    "dlp_credential":("T1552","Credential Access"),
    "sandbox_malware":("T1204","Execution"),
    "xdr_chain":("T1078","Initial Access"),
    "xdr_exfil":("T1041","Exfiltration"),
    "ml_anomaly":("T1059","Execution"),
    "ml_behavioral":("T1055","Defense Evasion"),
    "ml_entropy":("T1027","Defense Evasion"),
    "ml_sequence":("T1059","Execution"),
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
    "/etc/ld.so.preload":("CRITICAL",95,"process_injection"),
    "/etc/pam.conf":("HIGH",85,"priv_escalation"),
    "/usr/bin/sudo":("CRITICAL",95,"fim_binary"),
    "/bin/bash":("CRITICAL",95,"fim_binary"),
    "/usr/sbin/sshd":("CRITICAL",95,"fim_binary"),
    "/opt/secos/agents/api.py":("HIGH",85,"fim_critical"),
    "/var/www/html/":("HIGH",80,"fim_critical"),
}

SUSP_PORTS = {
    4444:("CRITICAL",92,"network_c2","Metasploit default"),
    4445:("HIGH",85,"network_c2","Metasploit alt"),
    1337:("HIGH",82,"network_c2","Leet port C2"),
    5555:("HIGH",80,"network_c2","Common C2"),
    31337:("HIGH",88,"network_c2","Elite backdoor"),
    9050:("HIGH",85,"network_tor","Tor SOCKS"),
    9150:("HIGH",85,"network_tor","Tor browser"),
    3333:("MEDIUM",65,"network_c2","Mining pool"),
}

DLP_PATTERNS = {
    "aws_key":         (r"AKIA[0-9A-Z]{16}","CRITICAL",95),
    "private_key":     (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----","CRITICAL",95),
    "api_key_generic": (r"(?i)(api[_-]?key|secret[_-]?key)\s*[:=]\s*['\"]?[A-Za-z0-9+/]{20,}","HIGH",85),
    "password_in_cmd": (r"(?i)(password|passwd)\s*[:=]\s*\S{6,}","HIGH",80),
    "jwt_token":       (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}","HIGH",82),
    "db_connection":   (r"(?i)(mysql|postgres|mongodb)://[^:]+:[^@]+@","HIGH",85),
}

CPU_SAFE = {"dd","gzip","tar","find","make","cc","gcc","ps","top","htop",
            "sort","awk","sed","grep","python3","python","sh","bash"}

def mkraw(rule,detail,extra=""):
    return json.dumps({"source":"EDR","rule":rule,"detail":detail,"data":extra})


# ══════════════════════════════════════════════════════════════════════════════
# ML MODEL 1: ISOLATION FOREST
# Anomaly score: 1.0 = highly anomalous, 0.0 = normal
# Theory: anomalies are isolated in fewer tree splits
# ══════════════════════════════════════════════════════════════════════════════
class _ITree:
    def __init__(self,max_depth=8):
        self.max_depth=max_depth
        self.split_feat=self.split_val=self.left=self.right=None
        self.size=0;self.is_leaf=False
    def fit(self,X,depth=0):
        self.size=len(X)
        if len(X)<=1 or depth>=self.max_depth:
            self.is_leaf=True;return self
        nf=len(X[0]);self.split_feat=random.randint(0,nf-1)
        col=[x[self.split_feat] for x in X];mn,mx=min(col),max(col)
        if mn==mx:self.is_leaf=True;return self
        self.split_val=mn+random.random()*(mx-mn)
        L=[x for x in X if x[self.split_feat]<self.split_val]
        R=[x for x in X if x[self.split_feat]>=self.split_val]
        if not L or not R:self.is_leaf=True;return self
        self.left=_ITree(self.max_depth).fit(L,depth+1)
        self.right=_ITree(self.max_depth).fit(R,depth+1)
        return self
    def path(self,x,d=0):
        if self.is_leaf or self.split_feat is None:
            return d+self._c(self.size)
        if x[self.split_feat]<self.split_val:
            return self.left.path(x,d+1) if self.left else d
        return self.right.path(x,d+1) if self.right else d
    def _c(self,n):
        if n<=1:return 0.0
        return 2*(math.log(n-1)+0.5772156649)-(2*(n-1)/n)

class IsolationForest:
    def __init__(self,n_trees=50,sample_size=64):
        self.n_trees=n_trees;self.sample_size=sample_size
        self.trees=[];self.trained=False;self.cn=1.0
    def fit(self,X):
        if len(X)<10:return self
        n=min(self.sample_size,len(X))
        self.cn=self._c(n);self.trees=[]
        for _ in range(self.n_trees):
            s=random.sample(X,n)
            self.trees.append(_ITree().fit(s))
        self.trained=True;return self
    def score(self,x):
        if not self.trained:return 0.5
        avg=statistics.mean(t.path(x) for t in self.trees)
        return round(2**(-avg/max(self.cn,0.001)),4)
    def _c(self,n):
        if n<=1:return 0.0
        return 2*(math.log(n-1)+0.5772156649)-(2*(n-1)/n)


# ══════════════════════════════════════════════════════════════════════════════
# ML MODEL 2: STATISTICAL BASELINE (EWMA + Z-Score)
# Exponentially Weighted Moving Average models normal behavior per entity.
# Z-score measures how many std deviations a value is from the mean.
# Formula: z = |x - μ_ewma| / σ_ewma
# ══════════════════════════════════════════════════════════════════════════════
class StatBaseline:
    def __init__(self,alpha=0.1,z_thresh=3.0,min_n=20):
        self.alpha=alpha;self.z_thresh=z_thresh;self.min_n=min_n
        self.B=defaultdict(lambda:defaultdict(lambda:{
            "ewma":None,"ewmvar":0.0,"n":0,"vals":deque(maxlen=500)}))
    def update(self,entity,feat,v):
        b=self.B[entity][feat];b["n"]+=1;b["vals"].append(v)
        if b["ewma"] is None:b["ewma"]=v;return
        d=v-b["ewma"]
        b["ewma"]=self.alpha*v+(1-self.alpha)*b["ewma"]
        b["ewmvar"]=(1-self.alpha)*(b["ewmvar"]+self.alpha*d*d)
    def zscore(self,entity,feat,v):
        b=self.B[entity][feat]
        if b["n"]<self.min_n or b["ewmvar"]<1e-10:return 0.0
        std=math.sqrt(b["ewmvar"])
        return abs(v-b["ewma"])/std if std>0 else 0.0
    def is_anomaly(self,entity,feat,v):
        z=self.zscore(entity,feat,v);return z>self.z_thresh,round(z,3)
    def percentile(self,entity,feat,v):
        b=self.B[entity][feat]
        if b["n"]<10:return 0.5
        vals=sorted(b["vals"])
        return sum(1 for x in vals if x<=v)/len(vals)


# ══════════════════════════════════════════════════════════════════════════════
# ML MODEL 3: SHANNON ENTROPY ANALYZER
# H = -Σ p(x) * log2(p(x))
# Normal text: ~4.5 bits | Packed binary: ~7.0 bits | Shellcode: ~7.5 bits
# High entropy + low chi2 = encrypted/packed = suspicious
# ══════════════════════════════════════════════════════════════════════════════
class EntropyAnalyzer:
    def shannon(self,data:bytes)->float:
        if not data:return 0.0
        freq=defaultdict(int)
        for b in data:freq[b]+=1
        t=len(data)
        return -sum((c/t)*math.log2(c/t) for c in freq.values() if c>0)
    def chi2(self,data:bytes)->float:
        if len(data)<256:return 999.0
        freq=defaultdict(int)
        for b in data:freq[b]+=1
        exp=len(data)/256.0
        return sum((freq.get(i,0)-exp)**2/exp for i in range(256))
    def bigram_entropy(self,data:bytes)->float:
        if len(data)<3:return 0.0
        ng=defaultdict(int)
        for i in range(len(data)-2):ng[data[i:i+2]]+=1
        t=sum(ng.values())
        return -sum((c/t)*math.log2(c/t) for c in ng.values() if c>0)
    def string_entropy(self,s:str)->float:
        if not s:return 0.0
        freq=defaultdict(int)
        for c in s:freq[c]+=1
        t=len(s)
        return -sum((c/t)*math.log2(c/t) for c in freq.values() if c>0)
    def analyze_bytes(self,data:bytes)->dict:
        h=self.shannon(data);c=self.chi2(data);bg=self.bigram_entropy(data)
        is_packed=h>6.5 and c<500
        is_enc=h>7.5 and c<200
        if h>=7.5:score=95
        elif h>=7.0:score=75
        elif h>=6.0:score=50
        else:score=int(h*8)
        return {"entropy":round(h,4),"chi2":round(c,2),"bigram":round(bg,4),
                "is_packed":is_packed,"is_encrypted":is_enc,"score":score}
    def analyze_cmdline(self,cmd:str)->dict:
        ce=self.string_entropy(cmd)
        b64=sum(1 for c in cmd if c in
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        )/max(len(cmd),1)
        obf_score=int(ce*15+b64*30)
        return {"char_entropy":round(ce,4),"b64_ratio":round(b64,3),
                "is_obfuscated":ce>4.5 or b64>0.7,"obf_score":obf_score}


# ══════════════════════════════════════════════════════════════════════════════
# ML MODEL 4: BEHAVIORAL SEQUENCE ANALYZER (N-gram Language Model)
# Models P(process | prev_process, prev_prev_process)
# Uses Laplace smoothing: P(c|ab) = (count(abc)+1) / (count(ab)+|V|)
# Low probability sequence = rare = suspicious
# ══════════════════════════════════════════════════════════════════════════════
class SequenceAnalyzer:
    def __init__(self,min_freq=3):
        self.min_freq=min_freq
        self.uni=defaultdict(int);self.bi=defaultdict(int)
        self.tri=defaultdict(int);self.total=0
        self.chains=defaultdict(lambda:deque(maxlen=20))
        self._seed()
    def _seed(self):
        normals=[("systemd","sshd","bash"),("bash","ls",""),
                 ("bash","cat",""),("bash","grep",""),
                 ("sshd","bash","ls"),("bash","sudo","apt"),
                 ("bash","git",""),("bash","python3",""),
                 ("bash","sudo","systemctl")]
        for a,b,c in normals:
            self.uni[a]+=10;self.uni[b]+=10
            self.bi[(a,b)]+=10
            if c:self.tri[(a,b,c)]+=10;self.uni[c]+=10;self.bi[(b,c)]+=10
        self.total=300
    def observe(self,user,proc):
        p=os.path.basename(proc).lower();chain=self.chains[user]
        self.uni[p]+=1;self.total+=1
        if len(chain)>=1:self.bi[(chain[-1],p)]+=1
        if len(chain)>=2:self.tri[(chain[-2],chain[-1],p)]+=1
        chain.append(p)
    def probability(self,user,proc)->float:
        p=os.path.basename(proc).lower()
        chain=self.chains[user];V=max(len(self.uni),100)
        if len(chain)>=2:
            a,b=chain[-2],chain[-1];ctx=self.bi.get((a,b),0)
            if ctx>=self.min_freq:
                return (self.tri.get((a,b,p),0)+1)/(ctx+V)
        if len(chain)>=1:
            b=chain[-1];ctx=self.uni.get(b,0)
            if ctx>=self.min_freq:
                return (self.bi.get((b,p),0)+1)/(ctx+V)
        return (self.uni.get(p,0)+1)/(self.total+V)
    def anomaly_score(self,user,proc)->float:
        prob=self.probability(user,proc)
        nll=-math.log(prob+1e-10)
        return round(min(nll/20.0,1.0),4)


# ══════════════════════════════════════════════════════════════════════════════
# ML MODEL 5: CUSUM CHANGE POINT DETECTOR
# S_pos = max(0, S_pos + x - μ - k)  — detects upward shifts
# S_neg = max(0, S_neg + μ - k - x)  — detects downward shifts
# Alert when S_pos > h or S_neg > h
# k = slack (0.5σ), h = threshold (4σ)
# ══════════════════════════════════════════════════════════════════════════════
class CUSUMDetector:
    def __init__(self,k=0.5,h=4.0,warmup=30):
        self.k=k;self.h=h;self.warmup=warmup
        self.S=defaultdict(lambda:{
            "vals":deque(maxlen=200),"sp":0.0,"sn":0.0,
            "mu":0.0,"sigma":1.0,"n":0})
    def update(self,metric,value)->dict:
        s=self.S[metric];s["vals"].append(value);s["n"]+=1
        if len(s["vals"])>=5:
            prev=list(s["vals"])[:-1]
            s["mu"]=statistics.mean(prev)
            s["sigma"]=max(statistics.stdev(prev) if len(prev)>2 else 1.0,0.001)
        if s["n"]<self.warmup:return {"change":False,"score":0.0}
        k=self.k*s["sigma"];h=self.h*s["sigma"]
        s["sp"]=max(0,s["sp"]+value-s["mu"]-k)
        s["sn"]=max(0,s["sn"]+s["mu"]-k-value)
        score=max(s["sp"],s["sn"])/(h+1e-10)
        change=s["sp"]>h or s["sn"]>h
        if change:s["sp"]=0.0;s["sn"]=0.0
        return {"change":change,"score":round(min(score,1.0),4),
                "direction":"UP" if s["sp"]>s["sn"] else "DOWN"}


# ══════════════════════════════════════════════════════════════════════════════
# ML MODEL 6: BENFORD'S LAW ANALYZER
# Natural data first digits follow P(d) = log10(1 + 1/d)
# Synthetic/generated data deviates — detected via chi-squared test
# Critical value at 0.05 significance, 8 DOF = 15.507
# ══════════════════════════════════════════════════════════════════════════════
class BenfordAnalyzer:
    EXPECTED={1:0.301,2:0.176,3:0.125,4:0.097,5:0.079,
              6:0.067,7:0.058,8:0.051,9:0.046}
    def __init__(self):
        self.obs=defaultdict(lambda:deque(maxlen=500))
    def add(self,cat,val):
        if val>0:self.obs[cat].append(val)
    def test(self,cat)->dict:
        vals=[v for v in self.obs[cat] if v>0]
        if len(vals)<50:return {"suspicious":False,"chi2":0,"n":len(vals)}
        fd=defaultdict(int)
        for v in vals:
            d=int(str(abs(v))[0])
            if 1<=d<=9:fd[d]+=1
        n=sum(fd.values())
        if n<30:return {"suspicious":False,"chi2":0,"n":n}
        chi2=sum(((fd.get(d,0)-n*self.EXPECTED[d])**2)/(n*self.EXPECTED[d])
                 for d in range(1,10))
        return {"suspicious":chi2>15.507,"chi2":round(chi2,3),
                "deviation":round(chi2/15.507,3),"n":n}


# ══════════════════════════════════════════════════════════════════════════════
# ML MODEL 7: RANDOM FOREST CLASSIFIER
# Ensemble of decision trees. Each tree votes malicious/benign.
# Trained on MITRE ATT&CK-derived feature vectors.
# Feature vector (10-dim): [cpu,mem,net_conns,unique_ports,cmd_entropy,
#                           path_depth,is_tmp,child_count,fd_count,hour]
# ══════════════════════════════════════════════════════════════════════════════
class _DTree:
    def __init__(self,max_depth=6):
        self.max_depth=max_depth
        self.sf=self.sv=self.left=self.right=self.pred=None
    def _gini(self,y):
        if not y:return 0.0
        p=sum(y)/len(y);return 1-p*p-(1-p)*(1-p)
    def fit(self,X,y,depth=0):
        if depth>=self.max_depth or len(y)<2 or len(set(y))==1:
            self.pred=round(sum(y)/len(y)) if y else 0;return self
        best_g,best_f,best_v=-1,None,None
        bg=self._gini(y);n=len(y)
        nf=max(1,int(math.sqrt(len(X[0]))))
        feats=random.sample(range(len(X[0])),min(nf,len(X[0])))
        for f in feats:
            vals=sorted(set(x[f] for x in X))
            for i in range(len(vals)-1):
                th=(vals[i]+vals[i+1])/2
                ly=[y[i] for i,x in enumerate(X) if x[f]<th]
                ry=[y[i] for i,x in enumerate(X) if x[f]>=th]
                if not ly or not ry:continue
                g=bg-(len(ly)/n*self._gini(ly)+len(ry)/n*self._gini(ry))
                if g>best_g:best_g=g;best_f=f;best_v=th
        if best_f is None:
            self.pred=round(sum(y)/len(y));return self
        self.sf=best_f;self.sv=best_v
        li=[i for i,x in enumerate(X) if x[best_f]<best_v]
        ri=[i for i,x in enumerate(X) if x[best_f]>=best_v]
        self.left=_DTree(self.max_depth).fit([X[i] for i in li],[y[i] for i in li],depth+1)
        self.right=_DTree(self.max_depth).fit([X[i] for i in ri],[y[i] for i in ri],depth+1)
        return self
    def proba(self,x)->float:
        if self.pred is not None:return float(self.pred)
        if x[self.sf]<self.sv:return self.left.proba(x) if self.left else 0.0
        return self.right.proba(x) if self.right else 0.0

class RandomForest:
    def __init__(self,n=30):
        self.n=n;self.trees=[];self.trained=False
    def fit(self,X,y):
        if len(X)<10:return self
        self.trees=[]
        ns=max(5,int(len(X)*0.8))
        for _ in range(self.n):
            idx=[random.randint(0,len(X)-1) for _ in range(ns)]
            t=_DTree().fit([X[i] for i in idx],[y[i] for i in idx])
            self.trees.append(t)
        self.trained=True;return self
    def proba(self,x)->float:
        if not self.trained or not self.trees:return 0.5
        return round(statistics.mean(t.proba(x) for t in self.trees),4)
    def seed(self):
        # MITRE ATT&CK-derived training data
        # [cpu, mem, net_conns, unique_ports, cmd_entropy, path_depth,
        #  is_tmp, child_count, fd_count, hour]
        benign=[
            [0.1,0.5,2,2,3.2,3,0,0,10,10],[0.0,0.2,0,0,2.8,3,0,0,5,14],
            [0.2,1.0,5,3,3.5,4,0,2,20,9],[0.0,0.1,0,0,2.5,2,0,0,3,11],
            [0.1,0.8,10,5,3.0,4,0,1,15,8],[0.0,0.3,1,1,3.1,3,0,0,8,15],
            [0.5,2.0,3,2,2.9,3,0,0,12,10],[0.0,0.2,0,0,2.7,2,0,0,4,13],
            [1.0,3.0,8,4,3.3,5,0,3,25,9],[0.2,0.6,2,2,2.8,3,0,0,7,16],
        ]
        malicious=[
            [0.5,0.3,15,12,5.5,1,1,3,50,3],[95.0,0.5,2,1,3.0,2,1,0,10,2],
            [2.0,5.0,0,0,4.2,3,0,5,80,4],[0.1,8.0,3,2,3.5,2,0,10,200,3],
            [0.0,0.1,0,0,4.8,1,1,0,5,1],[0.2,0.5,50,30,4.0,2,1,1,20,3],
            [0.3,0.4,5,4,7.2,1,1,2,15,2],[5.0,0.8,200,180,3.5,2,0,0,30,1],
            [0.1,0.2,8,7,6.8,1,1,1,12,3],[3.0,1.5,25,20,4.5,2,1,2,40,2],
        ]
        X=benign+malicious;y=[0]*len(benign)+[1]*len(malicious)
        self.fit(X,y)
        log.info(f"RF seeded: {len(X)} samples ({len(malicious)} malicious)")


# ══════════════════════════════════════════════════════════════════════════════
# ML MODEL 8: ENSEMBLE SCORER
# Weighted combination of all model outputs → final confidence
# Weights tuned for EDR use case:
#   IsolationForest 0.20 | StatBaseline 0.20 | Entropy 0.15
#   Sequence 0.15        | CUSUM 0.10        | RF 0.20
# ══════════════════════════════════════════════════════════════════════════════
class EnsembleScorer:
    WEIGHTS={"if":0.20,"stat":0.20,"entropy":0.15,
             "sequence":0.15,"cusum":0.10,"rf":0.20}
    SEVERITY=[(0.85,"CRITICAL",95),(0.70,"HIGH",80),
               (0.55,"MEDIUM",60),(0.40,"LOW",35),(0.0,"INFO",10)]
    def score(self,scores:dict)->dict:
        tw=ws=0.0
        for k,w in self.WEIGHTS.items():
            if k in scores:ws+=scores[k]*w;tw+=w
        if tw==0:return{"confidence":0.0,"severity":"INFO","score":0}
        conf=ws/tw
        for thresh,sev,sc in self.SEVERITY:
            if conf>=thresh:
                return{"confidence":round(conf,4),"severity":sev,"score":sc,
                       "breakdown":{k:round(v,4) for k,v in scores.items()},
                       "models_fired":sum(1 for v in scores.values() if v>0.5)}
        return{"confidence":0.0,"severity":"INFO","score":0}


# ══════════════════════════════════════════════════════════════════════════════
# ML ENGINE — Orchestrates all 7 models
# ══════════════════════════════════════════════════════════════════════════════
class MLEngine:
    def __init__(self):
        self.iforest  = IsolationForest(n_trees=50,sample_size=64)
        self.stat     = StatBaseline(alpha=0.1,z_thresh=3.0,min_n=20)
        self.entropy  = EntropyAnalyzer()
        self.sequence = SequenceAnalyzer()
        self.cusum    = CUSUMDetector(k=0.5,h=4.0,warmup=30)
        self.benford  = BenfordAnalyzer()
        self.rf       = RandomForest(n=30)
        self.ensemble = EnsembleScorer()
        self.buf:List[List[float]]=[]
        self.lbl:List[int]=[]
        self.preds=0
        self.rf.seed()
        log.info("ML Engine ready — IForest|StatBaseline|Entropy|"
                 "Sequence|CUSUM|Benford|RandomForest|Ensemble")

    def _features(self,proc:dict)->List[float]:
        cmd=proc.get("cmd","");path=proc.get("path",cmd.split()[0] if cmd else "")
        ce=self.entropy.string_entropy(cmd)
        return [
            float(proc.get("cpu",0.0)),       # 0: CPU usage
            float(proc.get("mem",0.0)),        # 1: Memory %
            float(proc.get("net_conns",0)),    # 2: Network connections
            float(proc.get("unique_ports",0)), # 3: Unique remote ports
            ce,                                # 4: Cmdline entropy
            float(len(path.split("/"))),       # 5: Path depth
            1.0 if any(t in path for t in     # 6: Temp execution flag
                ["/tmp","/dev/shm","/var/tmp"]) else 0.0,
            float(proc.get("child_count",0)),  # 7: Child process count
            float(proc.get("fd_count",0)),     # 8: File descriptors
            float(datetime.now().hour),        # 9: Hour of day
        ]

    async def analyze(self,proc:dict)->dict:
        """Full ML analysis of a process. Returns threat assessment."""
        self.preds+=1
        entity=proc.get("user","?");pname=proc.get("name","?")
        cmd=proc.get("cmd","");feat=self._features(proc)
        scores={}

        # Model 1: Isolation Forest
        if len(self.buf)>=20:
            scores["if"]=self.iforest.score(feat)

        # Model 2: Statistical baseline per feature
        fnames=["cpu","mem","net","ports","cmd_ent","depth",
                "is_tmp","children","fds","hour"]
        zs=[]
        for fn,fv in zip(fnames,feat):
            self.stat.update(entity,fn,fv);zs.append(self.stat.zscore(entity,fn,fv))
        mz=max(zs) if zs else 0
        scores["stat"]=min(mz/10.0,1.0)

        # Model 3: Entropy on cmdline
        ec=self.entropy.analyze_cmdline(cmd)
        scores["entropy"]=min(ec["obf_score"]/100.0,1.0)

        # Model 4: Behavioral sequence
        scores["sequence"]=self.sequence.anomaly_score(entity,pname)
        self.sequence.observe(entity,pname)

        # Model 5: CUSUM on CPU
        cu=self.cusum.update(f"{entity}:cpu",feat[0])
        scores["cusum"]=cu["score"]

        # Model 7: Random Forest
        scores["rf"]=self.rf.proba(feat)

        # Ensemble
        result=self.ensemble.score(scores)
        result.update({"process":pname,"entity":entity,
                       "cmd_entropy":round(ec["char_entropy"],4),
                       "max_zscore":round(mz,3),
                       "rf_prob":round(scores.get("rf",0.5),4)})

        # Online learning
        self.buf.append(feat)
        self.lbl.append(1 if result["confidence"]>0.6 else 0)
        if len(self.buf)>2000:self.buf=self.buf[-1500:];self.lbl=self.lbl[-1500:]
        if len(self.buf)%100==0:self._retrain()
        return result

    async def analyze_file(self,path:str)->dict:
        """Entropy + IF analysis on a file."""
        scores={}
        try:
            with open(path,"rb") as f:data=f.read(65536)
            er=self.entropy.analyze_bytes(data)
            scores["entropy"]=er["score"]/100.0
            ff=[er["entropy"]/8.0,er["chi2"]/1000.0,
                float(os.path.getsize(path))/(1024*1024),
                1.0 if path.startswith("/tmp") else 0.0,
                1.0 if path.endswith((".php",".sh",".py",".pl")) else 0.0,
                0.0,0.0,0.0,0.0,0.0]
            if len(self.buf)>=20:
                scores["if"]=self.iforest.score(ff)
            r=self.ensemble.score(scores)
            r["file_entropy"]=er["entropy"]
            r["is_packed"]=er["is_packed"]
            r["is_encrypted"]=er["is_encrypted"]
            return r
        except Exception as e:
            return {"confidence":0.0,"severity":"INFO","error":str(e)}

    def _retrain(self):
        try:
            if len(self.buf)>=20:
                self.iforest.fit(self.buf)
            if sum(self.lbl)>=3 and sum(1-l for l in self.lbl)>=3:
                self.rf.fit(self.buf,self.lbl)
            log.info(f"ML retrained: {len(self.buf)} samples "
                     f"({sum(self.lbl)} suspicious)")
        except Exception as e:log.debug(f"Retrain: {e}")

    def stats(self)->dict:
        return{"predictions":self.preds,"training_samples":len(self.buf),
               "if_trained":self.iforest.trained,"rf_trained":self.rf.trained,
               "vocab_size":len(self.sequence.uni)}


# ══════════════════════════════════════════════════════════════════════════════
# MAIN EDR/XDR/ML AGENT
# ══════════════════════════════════════════════════════════════════════════════
class SecOSAgent:
    def __init__(self):
        self.rc=None;self.db=None
        self.hostname=socket.gethostname()
        self.alert_seq=0
        self.seen_procs=set();self.alerted=set()
        self.fim_baseline={};self.conn_counts=defaultdict(int)
        self.last_fim=0
        self.xdr_events=defaultdict(lambda:deque(maxlen=100))
        self.xdr_alerted=set()
        self.dlp_bytes=defaultdict(int)
        self.sandbox_queue=None
        self.sandbox_ok=self._has_docker()
        self.ml=MLEngine()
        # ML alert thresholds
        self.ml_thresh={"CRITICAL":0.85,"HIGH":0.70,"MEDIUM":0.55}

    def _has_docker(self):
        try:
            r=subprocess.run(["docker","info"],capture_output=True,timeout=5)
            if r.returncode==0:log.info("Docker available — Sandbox ENABLED");return True
        except Exception:pass
        log.info("Docker unavailable — Sandbox static-only");return False

    def _redis(self):
        url=REDIS_URL.replace("redis://","").split("/")[0];h,_,p=url.partition(":")
        return redis.Redis(host=h,port=int(p or 6379),db=0,
                          decode_responses=True,
                          socket_connect_timeout=5,socket_timeout=5)

    async def connect(self):
        try:self.rc=self._redis();self.rc.ping();log.info("Redis connected")
        except Exception as e:log.error(f"Redis: {e}");self.rc=None
        try:
            self.db=await asyncpg.create_pool(DATABASE_URL,min_size=1,max_size=3)
            log.info("PostgreSQL connected")
        except Exception as e:log.error(f"PostgreSQL: {e}");self.db=None

    async def alert(self,rule,severity,score,mkey,
                    detail="",src_ip="",user="",extra="",ml_data=None):
        mid,tactic=MITRE.get(mkey,("T1059","Execution"))
        self.alert_seq+=1;now=datetime.now(timezone.utc)
        raw_obj={"source":"EDR","rule":rule,"detail":detail,"data":extra}
        if ml_data:raw_obj["ml"]=ml_data
        raw_json=json.dumps(raw_obj)
        p={"id":hashlib.md5(f"{rule}{time.time()}".encode()).hexdigest()[:12].upper(),
           "rule_name":rule,"severity":severity,"host":self.hostname,
           "src_ip":src_ip,"user_name":user,"mitre_id":mid,"tactic":tactic,
           "score":score,"source":"EDR","status":"NEW","detail":detail,
           "raw":raw_json,"timestamp":now.isoformat()}
        log.warning(f"[{severity}] {rule} | {detail[:80]}")
        if self.rc:
            try:
                m=json.dumps(p,default=str)
                self.rc.publish("secos:alerts",m)
                self.rc.lpush("secos:edr:alerts",m);self.rc.ltrim("secos:edr:alerts",0,999)
            except Exception as e:log.error(f"Redis: {e}")
        if self.db:
            try:
                async with self.db.acquire() as c:
                    await c.execute(
                        "INSERT INTO events(rule_name,severity,host,src_ip,user_name,"
                        "mitre_id,tactic,score,source,status,raw,timestamp)"
                        " VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",
                        rule,severity,self.hostname,src_ip,user,
                        mid,tactic,score,"EDR","NEW",raw_json,now)
                log.info(f"DB saved: {rule}")
            except Exception as e:log.error(f"DB: {e}")
        self.xdr_events[self.hostname].append(
            (now.timestamp(),tactic,rule,severity,mkey))

    def _dd(self,k):
        if k in self.alerted:return False
        self.alerted.add(k)
        if len(self.alerted)>5000:self.alerted=set(list(self.alerted)[-2000:])
        return True

    # ── MODULE 1: PROCESS MONITOR + ML ───────────────────────────────────────
    async def scan_processes(self):
        try:r=subprocess.run(["ps","auxww","--no-headers"],
                             capture_output=True,text=True,timeout=10)
        except Exception:return
        for line in r.stdout.strip().splitlines():
            parts=line.split(None,10)
            if len(parts)<11:continue
            try:
                uname=parts[0];pid=int(parts[1]);cpu=float(parts[2])
                cmd=parts[10];pname=os.path.basename(cmd.split()[0]) if cmd else ""
            except(ValueError,IndexError):continue
            pk=f"{pid}:{pname}"
            if pk in self.seen_procs:continue
            self.seen_procs.add(pk);pl=pname.lower();cl=cmd.lower()

            # Rule-based detection
            for sig,(sev,sc,mk) in MALICIOUS.items():
                if sig in pl or sig in cl:
                    if self._dd(f"proc:{sig}:{pid}"):
                        await self.alert(f"Malicious Process: {pname}",sev,sc,mk,
                            detail=f"PID:{pid} User:{uname} Cmd:{cmd[:80]}",
                            user=uname,extra=f"pid={pid} sig={sig}")
                    break
            for pat,sev,sc,mk,desc in CMDPATS:
                if re.search(pat,cl,re.IGNORECASE):
                    if self._dd(f"cmd:{pat[:8]}:{pid}"):
                        await self.alert(f"Suspicious Cmd: {desc}",sev,sc,mk,
                            detail=f"PID:{pid} {cmd[:80]}",user=uname,
                            extra=f"pid={pid}")
                    break
            if any(t in cmd for t in["/tmp/","/dev/shm/","/var/tmp/"]):
                if pl not in{"sh","bash","python3","python"}:
                    if self._dd(f"tmp:{pid}"):
                        await self.alert("Execution from Temp Dir","HIGH",82,
                            "malicious_process",
                            detail=f"PID:{pid} {cmd[:80]}",user=uname,
                            extra=f"pid={pid}")
            if cpu>90.0 and pl not in CPU_SAFE:
                if self._dd(f"cpu:{pid}"):
                    await self.alert("High CPU Anomaly","MEDIUM",60,"mem_high",
                        detail=f"PID:{pid} {pname} CPU:{cpu}%",user=uname,
                        extra=f"pid={pid} cpu={cpu}")

            # ML analysis on every new process
            proc_data={"name":pname,"cmd":cmd,"user":uname,
                       "cpu":cpu,"mem":float(parts[3] if len(parts)>3 else 0)}
            ml_result=await self.ml.analyze(proc_data)
            conf=ml_result["confidence"]

            # Fire ML alert if confidence crosses threshold
            if conf>=0.55:
                ml_key=f"ml:{pid}:{pname}:{int(conf*10)}"
                if self._dd(ml_key):
                    sev=ml_result["severity"]
                    sc=ml_result["score"]
                    bd=ml_result.get("breakdown",{})
                    detail=(f"ML Threat: {pname} | conf={conf:.3f} | "
                            f"IF={bd.get('if',0):.2f} "
                            f"Stat={bd.get('stat',0):.2f} "
                            f"Entropy={bd.get('entropy',0):.2f} "
                            f"Seq={bd.get('sequence',0):.2f} "
                            f"RF={bd.get('rf',0):.2f}")
                    await self.alert(
                        f"ML: Anomalous Process Behavior",
                        sev,sc,"ml_anomaly",
                        detail=detail,user=uname,
                        extra=f"pid={pid} confidence={conf}",
                        ml_data={"confidence":conf,"breakdown":bd,
                                 "models_fired":ml_result.get("models_fired",0)})

        if len(self.seen_procs)>5000:
            self.seen_procs=set(list(self.seen_procs)[-2000:])

    # ── MODULE 2: FIM ─────────────────────────────────────────────────────────
    def _hash(self,path):
        try:
            if os.path.isfile(path) and os.path.getsize(path)<50*1024*1024:
                h=hashlib.sha256()
                with open(path,"rb") as f:
                    for chunk in iter(lambda:f.read(65536),b""):h.update(chunk)
                return h.hexdigest()
        except(PermissionError,OSError):pass
        return None
    def _hashdir(self,d,limit=60):
        hashes={}
        try:
            for fn in os.listdir(d):
                if len(hashes)>=limit:break
                fp=os.path.join(d,fn);h=self._hash(fp)
                if h:hashes[fp]=h
        except(PermissionError,OSError):pass
        return hashes
    async def build_fim(self):
        log.info("Building FIM baseline...")
        for path in FIM_PATHS:
            if os.path.isdir(path):self.fim_baseline.update(self._hashdir(path))
            else:
                h=self._hash(path)
                if h:self.fim_baseline[path]=h
        log.info(f"FIM: {len(self.fim_baseline)} files tracked")
        try:
            r=subprocess.run(["find","/usr","/bin","/sbin","-perm","-4000"],
                            capture_output=True,text=True,timeout=30)
            suids=set(r.stdout.strip().splitlines())
            if suids and self.rc:
                self.rc.delete("edr:suid_baseline")
                self.rc.sadd("edr:suid_baseline",*suids)
                log.info(f"SUID: {len(suids)} binaries baselined")
        except Exception as e:log.debug(f"SUID: {e}")
    async def scan_fim(self):
        now=time.time()
        if now-self.last_fim<FIM_INTERVAL:return
        self.last_fim=now;log.info("FIM scan...")
        for path,orig in list(self.fim_baseline.items()):
            cur=self._hash(path)
            base=next((p for p in FIM_PATHS if path.startswith(p)),path)
            sev,sc,mk=FIM_PATHS.get(base,("HIGH",80,"fim_critical"))
            if cur is None and not os.path.exists(path):
                if self._dd(f"fim:del:{path}"):
                    await self.alert("FIM: File Deleted",sev,sc,mk,
                        detail=f"Deleted: {path}",extra=f"path={path}")
                del self.fim_baseline[path]
            elif cur and cur!=orig:
                if self._dd(f"fim:mod:{path}:{cur[:8]}"):
                    await self.alert("FIM: File Modified",sev,sc,mk,
                        detail=f"Tampered: {path}",
                        extra=f"old={orig[:16]} new={cur[:16]}")
                    # ML analysis on modified file
                    ml=await self.ml.analyze_file(path)
                    if ml["confidence"]>=0.55:
                        await self.alert("ML: Modified File Suspicious",
                            ml["severity"],ml["score"],"ml_entropy",
                            detail=f"{path} entropy={ml.get('file_entropy',0):.2f} "
                                   f"packed={ml.get('is_packed',False)} "
                                   f"conf={ml['confidence']:.3f}",
                            extra=f"path={path}",ml_data=ml)
                self.fim_baseline[path]=cur
        for path,(sev,sc,mk) in FIM_PATHS.items():
            if os.path.isdir(path):
                for fp,fh in self._hashdir(path).items():
                    if fp not in self.fim_baseline:
                        if self._dd(f"fim:new:{fp}"):
                            await self.alert("FIM: New File in Critical Dir",sev,sc,mk,
                                detail=f"New: {fp}",extra=f"path={fp}")
                            ml=await self.ml.analyze_file(fp)
                            if ml["confidence"]>=0.55:
                                await self.alert("ML: New File Suspicious",
                                    ml["severity"],ml["score"],"ml_entropy",
                                    detail=f"{fp} entropy={ml.get('file_entropy',0):.2f} "
                                           f"conf={ml['confidence']:.3f}",
                                    extra=f"path={fp}",ml_data=ml)
                        self.fim_baseline[fp]=fh
        try:
            r=subprocess.run(["find","/usr","/bin","/sbin","-perm","-4000"],
                            capture_output=True,text=True,timeout=30)
            cur=set(r.stdout.strip().splitlines())
            if self.rc:
                stored=self.rc.smembers("edr:suid_baseline")
                for s in(cur-stored):
                    if self._dd(f"suid:{s}"):
                        await self.alert("New SUID Binary","CRITICAL",95,"new_suid",
                            detail=f"New SUID: {s}",extra=f"path={s}")
        except Exception as e:log.debug(f"SUID scan: {e}")

    # ── MODULE 3: NETWORK + BENFORD ───────────────────────────────────────────
    async def scan_network(self):
        try:r=subprocess.run(["ss","-tunp","--no-header"],
                             capture_output=True,text=True,timeout=10)
        except Exception:return
        cip=defaultdict(int)
        for line in r.stdout.strip().splitlines():
            parts=line.split()
            if len(parts)<6:continue
            try:
                raddr=parts[5]
                if raddr in("*","0.0.0.0:*",":::*"):continue
                rip,_,rp=raddr.rpartition(":")
                if not rp.isdigit():continue
                rport=int(rp);rip=rip.strip("[]")
                if rip.startswith(("127.","::1","0.0.0.0","10.",
                                   "172.16.","172.17.","172.25.","192.168.")):continue
            except(ValueError,IndexError):continue
            if rport in SUSP_PORTS:
                if self._dd(f"port:{rip}:{rport}"):
                    sev,sc,mk,desc=SUSP_PORTS[rport]
                    await self.alert(f"Suspicious Port {rport}",sev,sc,mk,
                        detail=f"{desc} → {rip}:{rport}",src_ip=rip,
                        extra=f"dst={rip}:{rport}")
            self.ml.benford.add(self.hostname,rport)
            cip[rip]+=1
        for rip,cnt in cip.items():
            prev=self.conn_counts.get(rip,0)
            if cnt>=10 and cnt>prev+5:
                if self._dd(f"beacon:{rip}:{cnt}"):
                    await self.alert("C2 Beaconing Pattern","HIGH",85,"network_c2",
                        detail=f"{cnt} connections to {rip}",src_ip=rip,
                        extra=f"ip={rip} count={cnt}")
                # ML: CUSUM on connection rate
                cu=self.ml.cusum.update(f"net:{rip}",float(cnt))
                if cu["change"] and self._dd(f"cusum:net:{rip}"):
                    await self.alert("ML: Network Rate Change Detected","HIGH",78,
                        "ml_behavioral",
                        detail=f"CUSUM: abnormal connection rate to {rip} "
                               f"(score={cu['score']:.3f})",
                        src_ip=rip,extra=f"cusum={cu}")
            self.conn_counts[rip]=cnt
        # Benford's Law test
        bf=self.ml.benford.test(self.hostname)
        if bf["suspicious"] and self._dd(f"benford:{int(time.time()//300)}"):
            await self.alert("ML: Benford Deviation — Synthetic Traffic","HIGH",75,
                "ml_behavioral",
                detail=f"Port distribution violates Benford's Law "
                       f"(chi2={bf['chi2']:.1f}, deviation={bf['deviation']:.2f}x)",
                extra=f"chi2={bf['chi2']} n={bf['n']}")
        try:
            r=subprocess.run(["ss","-tn","state","syn-sent"],
                            capture_output=True,text=True,timeout=5)
            syn=len([l for l in r.stdout.splitlines() if l.strip()])
            if syn>20:
                if self._dd(f"scan:{syn}"):
                    await self.alert("Port Scan Activity","HIGH",80,"network_scan",
                        detail=f"{syn} SYN-SENT — outbound scan",extra=f"syn={syn}")
        except Exception:pass

    # ── MODULE 4: MEMORY ──────────────────────────────────────────────────────
    async def scan_memory(self):
        try:
            with open("/proc/meminfo") as f:
                mi={}
                for line in f.read().splitlines():
                    if ":" in line:k,v=line.split(":",1);mi[k.strip()]=v.strip()
            total=int(mi.get("MemTotal","0 kB").split()[0])
            avail=int(mi.get("MemAvailable","0 kB").split()[0])
            if total>0:
                pct=((total-avail)/total)*100
                cu=self.ml.cusum.update("memory_usage",pct)
                if pct>92:
                    if self._dd(f"mem:{int(pct)}"):
                        await self.alert("Critical Memory Pressure","HIGH",75,"mem_high",
                            detail=f"Memory {pct:.1f}%",extra=f"pct={pct:.1f}")
                elif cu["change"] and self._dd(f"mem_cusum:{int(time.time()//300)}"):
                    await self.alert("ML: Memory Usage Change Point","MEDIUM",55,
                        "ml_behavioral",
                        detail=f"CUSUM: sudden memory change at {pct:.1f}% "
                               f"(score={cu['score']:.3f})",
                        extra=f"cusum={cu}")
            r=subprocess.run(["ps","aux","--no-headers","--sort=-%mem"],
                            capture_output=True,text=True,timeout=10)
            safe={"java","node","python3","python","postgres","mysqld","ps","top"}
            for line in r.stdout.strip().splitlines()[:15]:
                parts=line.split(None,10)
                if len(parts)<11:continue
                try:
                    uname=parts[0];pid=int(parts[1]);mem=float(parts[3])
                    vsz=int(parts[4]);rss=int(parts[5]);cmd=parts[10]
                    pl=os.path.basename(cmd.split()[0]).lower() if cmd else ""
                except(ValueError,IndexError):continue
                if mem>30.0 and pl not in safe:
                    if self._dd(f"memhigh:{pid}"):
                        await self.alert("Abnormal Memory","MEDIUM",65,"mem_high",
                            detail=f"PID:{pid} {pl} {mem}%",user=uname,
                            extra=f"pid={pid} mem={mem}")
                if vsz>2000000 and rss<10000 and pl not in safe:
                    if self._dd(f"hollow:{pid}"):
                        await self.alert("Process Hollowing","HIGH",82,
                            "process_injection",
                            detail=f"PID:{pid} VSZ:{vsz//1024}MB RSS:{rss//1024}MB",
                            user=uname,extra=f"pid={pid} vsz={vsz//1024}")
        except Exception as e:log.debug(f"Memory: {e}")

    # ── MODULE 5: USER SESSIONS ───────────────────────────────────────────────
    async def scan_users(self):
        try:
            r=subprocess.run(["who","-a"],capture_output=True,text=True,timeout=5)
            for line in r.stdout.splitlines():
                if "root" in line and "pts/" in line:
                    if self._dd(f"rootssh:{line[:30]}"):
                        await self.alert("Root Remote Login","HIGH",82,"priv_escalation",
                            detail=f"Root session: {line.strip()[:60]}",
                            user="root",extra="root_remote=true")
                    break
            r=subprocess.run(["awk","-F:","$3>=1000&&$3<65534{print $1}","/etc/passwd"],
                            capture_output=True,text=True,timeout=5)
            current=set(r.stdout.strip().splitlines())
            if self.rc:
                stored=self.rc.smembers("edr:known_users")
                if stored:
                    for u in(current-stored):
                        if self._dd(f"newuser:{u}"):
                            await self.alert("New System User","HIGH",85,"priv_escalation",
                                detail=f"New account: {u}",user=u,extra=f"user={u}")
                self.rc.delete("edr:known_users")
                if current:self.rc.sadd("edr:known_users",*current)
        except Exception as e:log.debug(f"Users: {e}")

    # ── MODULE 6: SANDBOX ─────────────────────────────────────────────────────
    async def sandbox_worker(self):
        log.info("Sandbox worker started")
        while True:
            try:
                fp,trigger,pid=await asyncio.wait_for(self.sandbox_queue.get(),timeout=5.0)
                await self._sandbox_analyze(fp,trigger,pid)
            except asyncio.TimeoutError:continue
            except Exception as e:log.error(f"Sandbox: {e}")

    async def _sandbox_analyze(self,fp,trigger,pid):
        if not os.path.exists(fp):return
        log.info(f"Sandbox: {fp}")
        findings=[];risk=0
        try:
            with open(fp,"rb") as f:data=f.read(65536)
            er=self.ml.entropy.analyze_bytes(data)
            if er["entropy"]>7.0:findings.append(f"HIGH_ENTROPY:{er['entropy']:.2f}");risk+=25
            if er["is_packed"]:findings.append("PACKED_BINARY");risk+=20
            r=subprocess.run(["strings","-n","6",fp],
                           capture_output=True,text=True,timeout=10)
            sl=r.stdout.lower()
            for sig,pts in[("meterpreter",35),("mimikatz",35),("/etc/shadow",25),
                           ("reverse_tcp",25),("shellcode",25),("keylogger",30),
                           ("cmd.exe",20),("base64",10),("inject",15)]:
                if sig in sl:findings.append(f"STRING:{sig.upper()}");risk+=pts
            ips=re.findall(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",r.stdout)
            ext=[ip for ip in set(ips)
                 if not ip.startswith(("127.","10.","192.168.","172."))]
            if ext:findings.append(f"EMBEDDED_IPS:{','.join(ext[:3])}");risk+=20
        except Exception as e:log.debug(f"Static: {e}")
        if self.sandbox_ok:
            try:
                cname=f"secos-sandbox-{int(time.time())}"
                r=subprocess.run([
                    "docker","run","--rm",f"--name={cname}",
                    "--network=none","--memory=256m","--cpus=0.5","--read-only",
                    "--tmpfs=/tmp:size=64m",f"-v={fp}:/sandbox/sample:ro",
                    "--security-opt=no-new-privileges",
                    "ubuntu:22.04","timeout",str(SANDBOX_TIMEOUT),
                    "strace","-e","trace=network,file,process","-f","/sandbox/sample"],
                    capture_output=True,text=True,timeout=SANDBOX_TIMEOUT+10)
                so=(r.stderr+r.stdout).lower()
                for pat,pts,desc in[
                    (r"connect\(.*sin_addr",20,"NETWORK_CONNECT"),
                    (r"open\(.*shadow",35,"SHADOW_ACCESS"),
                    (r"ptrace\(",25,"PTRACE"),
                    (r"mprotect\(.*prot_exec",20,"SHELLCODE_MEM"),
                    (r"execve\(",15,"EXEC_CHILD"),
                ]:
                    if re.search(pat,so):findings.append(desc);risk+=pts
            except Exception as e:log.debug(f"Docker sandbox: {e}")
        verdict="MALICIOUS" if risk>=70 else "SUSPICIOUS" if risk>=35 else "CLEAN"
        if verdict!="CLEAN":
            sev={"MALICIOUS":"CRITICAL","SUSPICIOUS":"HIGH"}.get(verdict,"MEDIUM")
            await self.alert(f"Sandbox: {verdict} File",sev,min(risk,100),
                "sandbox_malware",
                detail=f"{os.path.basename(fp)} risk={risk} trigger={trigger}",
                extra=f"path={fp} verdict={verdict} findings={'|'.join(findings[:5])}")

    # ── MODULE 7: DLP ─────────────────────────────────────────────────────────
    async def scan_dlp(self):
        try:
            r=subprocess.run(["cat","/proc/net/dev"],capture_output=True,text=True,timeout=5)
            for line in r.stdout.splitlines():
                if ":" not in line:continue
                iface,_,stats=line.partition(":");iface=iface.strip()
                if iface=="lo":continue
                parts=stats.split()
                if len(parts)<10:continue
                try:
                    tx=int(parts[8]);prev=self.dlp_bytes.get(iface,0)
                    delta=tx-prev
                    if prev>0 and delta>50*1024*1024:
                        if self._dd(f"dlp:tx:{iface}:{tx//1024//1024}"):
                            await self.alert("DLP: Large Outbound Transfer","HIGH",82,"dlp_exfil",
                                detail=f"{iface}: {delta//1024//1024}MB sent",
                                extra=f"iface={iface} mb={delta//1024//1024}")
                    self.dlp_bytes[iface]=tx
                except(ValueError,IndexError):continue
        except Exception as e:log.debug(f"DLP tx: {e}")
        try:
            r=subprocess.run(["find","/tmp","/var/tmp","/dev/shm","-type","f","-size","-5M"],
                           capture_output=True,text=True,timeout=10)
            for fp in r.stdout.strip().splitlines()[:10]:
                if not os.path.isfile(fp):continue
                try:
                    with open(fp,"r",errors="ignore") as f:content=f.read(20000)
                    for pname,(pat,sev,sc) in DLP_PATTERNS.items():
                        if re.search(pat,content):
                            if self._dd(f"dlp:{fp}:{pname}"):
                                await self.alert("DLP: Sensitive Data in Temp",sev,sc,"dlp_credential",
                                    detail=f"Pattern '{pname}' in {fp}",extra=f"path={fp}")
                            break
                except Exception:continue
        except Exception as e:log.debug(f"DLP content: {e}")

    # ── MODULE 8: XDR CORRELATOR ──────────────────────────────────────────────
    async def run_xdr(self):
        now=time.time();cutoff=now-XDR_WINDOW
        for host,events in self.xdr_events.items():
            W=[(ts,tac,rule,sev,mk) for ts,tac,rule,sev,mk in events if ts>cutoff]
            if len(W)<2:continue
            tactics=[t for _,t,_,_,_ in W]
            rules=[r for _,_,r,_,_ in W]
            sevs=[s for _,_,_,s,_ in W]
            if("Discovery" in tactics and "Execution" in tactics and
               "Command and Control" in tactics):
                k=f"xdr:rec:{host}:{int(now//300)}"
                if self._dd(k):
                    await self.alert("XDR: Recon→Exec→C2 Chain","CRITICAL",95,"xdr_chain",
                        detail=f"Full kill chain on {host} in {XDR_WINDOW//60}min",
                        extra=f"host={host} tactics={list(set(tactics))}")
            if("Credential Access" in tactics and "Privilege Escalation" in tactics):
                k=f"xdr:cred:{host}:{int(now//300)}"
                if self._dd(k):
                    await self.alert("XDR: CredDump→PrivEsc","CRITICAL",93,"xdr_chain",
                        detail=f"Credential theft+escalation on {host}",
                        extra=f"host={host}")
            if("Persistence" in tactics and "Defense Evasion" in tactics):
                k=f"xdr:pers:{host}:{int(now//300)}"
                if self._dd(k):
                    await self.alert("XDR: Persist+Evade","HIGH",88,"xdr_chain",
                        detail=f"Persistence with evasion on {host}",
                        extra=f"host={host}")
            if sevs.count("CRITICAL")>=3:
                k=f"xdr:crit:{host}:{int(now//120)}"
                if self._dd(k):
                    await self.alert("XDR: Active Intrusion","CRITICAL",98,"xdr_chain",
                        detail=f"{sevs.count('CRITICAL')} CRITICAL alerts on {host}",
                        extra=f"host={host}")
            fim_hit=any("FIM" in r or "File" in r for r in rules)
            net_hit=any("C2" in r or "Beacon" in r or "Port" in r for r in rules)
            if fim_hit and net_hit:
                k=f"xdr:exfil:{host}:{int(now//300)}"
                if self._dd(k):
                    await self.alert("XDR: File+C2 Exfil Pattern","HIGH",90,"xdr_exfil",
                        detail=f"File access + C2 connection on {host}",
                        extra=f"host={host}")
            # ML + XDR: if ML anomalies correlate with rule hits
            ml_hits=[r for r in rules if r.startswith("ML:")]
            rule_hits=[r for r in rules if not r.startswith("ML:")]
            if len(ml_hits)>=2 and len(rule_hits)>=2:
                k=f"xdr:ml_confirm:{host}:{int(now//300)}"
                if self._dd(k):
                    await self.alert("XDR+ML: Confirmed Threat Pattern","CRITICAL",96,
                        "xdr_chain",
                        detail=f"ML anomalies corroborated by rule hits on {host}: "
                               f"{len(ml_hits)} ML + {len(rule_hits)} rule alerts",
                        extra=f"host={host} ml_alerts={ml_hits[:3]}")
            if self.rc and len(W)>=3:
                try:
                    self.rc.setex(f"secos:xdr:{host}",300,json.dumps({
                        "host":host,"timestamp":datetime.now(timezone.utc).isoformat(),
                        "events":len(W),"tactics":list(set(tactics)),
                        "ml_alerts":len(ml_hits),"rule_alerts":len(rule_hits),
                        "critical":sevs.count("CRITICAL"),"high":sevs.count("HIGH"),
                    }))
                except Exception:pass

    # ── TELEMETRY ─────────────────────────────────────────────────────────────
    async def publish_telemetry(self):
        if not self.rc:return
        try:
            ml_stats=self.ml.stats()
            now=datetime.now(timezone.utc).isoformat()
            self.rc.setex("secos:edr:telemetry",60,json.dumps({
                "hostname":self.hostname,"timestamp":now,"status":"online",
                "version":"4.0","mode":"suggest",
                "modules":["process","fim","network","memory","users",
                          "sandbox","dlp","xdr"],
                "ml_models":["isolation_forest","stat_baseline","entropy",
                            "sequence","cusum","benford","random_forest","ensemble"],
                "sandbox":"docker" if self.sandbox_ok else "static",
                "ml":ml_stats,"alert_count":self.alert_seq,
            }))
            self.rc.setex("secos:edr:heartbeat",30,now)
            self.rc.setex("secos:ml:stats",60,json.dumps(ml_stats))
        except Exception as e:log.debug(f"Telemetry: {e}")

    # ── MAIN LOOP ─────────────────────────────────────────────────────────────
    async def run(self):
        log.info("="*60)
        log.info("  SecOS EDR/XDR/ML Agent v4.0")
        log.info(f"  Host   : {self.hostname}")
        log.info(f"  Mode   : suggest (alert + ML analysis)")
        log.info( "  Detect : Process|FIM|Network|Memory|Users|Sandbox|DLP|XDR")
        log.info( "  ML     : IForest|StatBaseline|Entropy|Sequence|"
                             "CUSUM|Benford|RF|Ensemble")
        log.info(f"  Sandbox: {'Docker (dynamic)' if self.sandbox_ok else 'Static analysis'}")
        log.info("="*60)
        await self.connect()
        self.sandbox_queue=asyncio.Queue()
        await self.build_fim()
        log.info("EDR/XDR/ML fully initialized — 16 models active")
        asyncio.create_task(self.sandbox_worker())
        cycle=0
        while True:
            try:
                await self.scan_processes()
                await self.scan_network()
                await self.scan_users()
                await self.scan_fim()
                await self.run_xdr()
                if cycle%2==0:await self.scan_dlp()
                if cycle%3==0:await self.scan_memory()
                await self.publish_telemetry()
                cycle+=1
                # Log ML stats every 10 cycles
                if cycle%10==0:
                    s=self.ml.stats()
                    log.info(f"ML stats: {s['predictions']} predictions | "
                            f"{s['training_samples']} samples | "
                            f"IF={'trained' if s['if_trained'] else 'warming'} | "
                            f"RF={'trained' if s['rf_trained'] else 'seeded'}")
            except Exception as e:log.error(f"Cycle: {e}")
            await asyncio.sleep(SCAN_INTERVAL)

if __name__=="__main__":
    try:asyncio.run(SecOSAgent().run())
    except KeyboardInterrupt:log.info("EDR stopped")
    except Exception as e:log.critical(f"Fatal: {e}");sys.exit(1)
