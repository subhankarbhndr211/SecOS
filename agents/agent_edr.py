#!/usr/bin/env python3
import os,sys,time,json,hashlib,socket,logging,asyncio,subprocess,re
from datetime import datetime,timezone
from collections import defaultdict
import redis,asyncpg
from dotenv import load_dotenv
load_dotenv("/etc/secos/.env")
REDIS_URL=os.getenv("REDIS_URL","redis://localhost:6379/0")
DATABASE_URL=os.getenv("DATABASE_URL","postgresql://secos:SecOS2024@localhost/secosdb")
SCAN_INTERVAL=15
FIM_INTERVAL=60
logging.basicConfig(level=logging.INFO,format="%(asctime)s [EDR] %(levelname)s %(message)s",datefmt="%Y-%m-%d %H:%M:%S",handlers=[logging.StreamHandler(),logging.FileHandler("/var/log/secos/agent_edr.log",encoding="utf-8")])
log=logging.getLogger("edr")
MITRE={"malicious_process":("T1059","Execution"),"process_injection":("T1055","Defense Evasion"),"credential_dumping":("T1003","Credential Access"),"discovery_tool":("T1082","Discovery"),"lateral_movement_tool":("T1021","Lateral Movement"),"c2_tool":("T1071.001","Command and Control"),"persistence_tool":("T1053","Persistence"),"defense_evasion":("T1218","Defense Evasion"),"fim_critical":("T1565.001","Impact"),"fim_config":("T1078","Persistence"),"fim_binary":("T1574","Persistence"),"network_c2":("T1071.001","Command and Control"),"network_scan":("T1046","Discovery"),"network_tor":("T1090.003","Command and Control"),"mem_high":("T1055","Defense Evasion"),"priv_escalation":("T1548","Privilege Escalation"),"new_suid":("T1548.001","Privilege Escalation"),"suspicious_cron":("T1053.003","Persistence"),"hidden_process":("T1564","Defense Evasion")}
MALICIOUS={"mimikatz":("CRITICAL",95,"credential_dumping"),"meterpreter":("CRITICAL",98,"c2_tool"),"cobalt":("CRITICAL",98,"c2_tool"),"beacon":("CRITICAL",97,"c2_tool"),"empire":("CRITICAL",96,"c2_tool"),"havoc":("CRITICAL",96,"c2_tool"),"sliver":("CRITICAL",95,"c2_tool"),"pwdump":("CRITICAL",92,"credential_dumping"),"wce":("CRITICAL",92,"credential_dumping"),"procdump":("HIGH",80,"credential_dumping"),"psexec":("HIGH",85,"lateral_movement_tool"),"wmiexec":("HIGH",85,"lateral_movement_tool"),"crackmapexec":("HIGH",88,"lateral_movement_tool"),"masscan":("HIGH",75,"discovery_tool"),"sqlmap":("HIGH",80,"discovery_tool"),"nikto":("MEDIUM",65,"discovery_tool"),"nmap":("MEDIUM",60,"discovery_tool"),"chisel":("HIGH",82,"c2_tool"),"ligolo":("HIGH",82,"lateral_movement_tool"),"mshta":("HIGH",80,"defense_evasion"),"netcat":("HIGH",82,"c2_tool")}
CMDPATS=[(r"base64\s+-d","HIGH",80,"defense_evasion","Base64 decode"),(r"curl.+\|\s*bash","CRITICAL",92,"c2_tool","Curl pipe to bash"),(r"wget.+\|\s*bash","CRITICAL",92,"c2_tool","Wget pipe to bash"),(r"bash\s+-i\s+>&\s*/dev/tcp","CRITICAL",95,"c2_tool","Bash reverse shell"),(r"nc\s+-e\s+/bin","CRITICAL",95,"c2_tool","Netcat reverse shell"),(r"chmod\s+\+s\s+","HIGH",85,"new_suid","SUID bit set"),(r"echo.+>>/etc/passwd","CRITICAL",95,"priv_escalation","Passwd write"),(r"echo.+>>/etc/sudoers","CRITICAL",95,"persistence_tool","Sudoers write"),(r"iptables\s+-F|ufw\s+disable","HIGH",85,"defense_evasion","Firewall disabled")]
FIM_PATHS={"/etc/passwd":("CRITICAL",95,"fim_critical"),"/etc/shadow":("CRITICAL",95,"fim_critical"),"/etc/sudoers":("CRITICAL",95,"fim_critical"),"/etc/hosts":("HIGH",80,"fim_config"),"/etc/ssh/sshd_config":("HIGH",85,"fim_config"),"/etc/crontab":("HIGH",85,"suspicious_cron"),"/etc/ld.so.preload":("CRITICAL",95,"process_injection"),"/etc/pam.conf":("HIGH",85,"priv_escalation"),"/usr/bin/sudo":("CRITICAL",95,"fim_binary"),"/usr/bin/ssh":("CRITICAL",92,"fim_binary"),"/bin/bash":("CRITICAL",95,"fim_binary"),"/bin/sh":("CRITICAL",95,"fim_binary"),"/usr/sbin/sshd":("CRITICAL",95,"fim_binary"),"/opt/secos/agents/api.py":("HIGH",85,"fim_critical"),"/var/www/html/":("HIGH",80,"fim_critical")}
SUSP_PORTS={4444:("CRITICAL",92,"network_c2","Metasploit default"),4445:("HIGH",85,"network_c2","Metasploit alt"),1337:("HIGH",82,"network_c2","Leet port"),5555:("HIGH",80,"network_c2","C2 port"),6666:("HIGH",80,"network_c2","C2 port"),31337:("HIGH",88,"network_c2","Elite backdoor"),9001:("HIGH",82,"network_tor","Tor"),9050:("HIGH",85,"network_tor","Tor SOCKS"),9150:("HIGH",85,"network_tor","Tor browser"),3333:("MEDIUM",65,"network_c2","Mining pool")}
CPU_SAFE={"dd","gzip","tar","ffmpeg","find","make","cc","gcc","g++","ps","top","htop","sort","awk","sed","grep","wc","du","df","ls","cat","head","tail","cut","tr","python3","python","sh","bash"}

def mkraw(rule,detail,extra=""):
    return json.dumps({"source":"EDR","rule":rule,"detail":detail,"data":extra})

class EDRAgent:
    def __init__(self):
        self.rc=None;self.db=None;self.hostname=socket.gethostname()
        self.alert_seq=0;self.seen_procs=set();self.alerted=set()
        self.fim_baseline={};self.conn_counts=defaultdict(int);self.last_fim=0
    def _make_redis(self):
        url=REDIS_URL.replace("redis://","").split("/")[0];h,_,p=url.partition(":")
        return redis.Redis(host=h,port=int(p or 6379),db=0,decode_responses=True,socket_connect_timeout=5,socket_timeout=5)
    async def connect(self):
        try:
            self.rc=self._make_redis();self.rc.ping();log.info("Redis connected")
        except Exception as e:
            log.error(f"Redis failed: {e}");self.rc=None
        try:
            self.db=await asyncpg.create_pool(DATABASE_URL,min_size=1,max_size=3);log.info("PostgreSQL connected")
        except Exception as e:
            log.error(f"PostgreSQL failed: {e}");self.db=None
    async def alert(self,rule,severity,score,mkey,detail="",src_ip="",user="",extra=""):
        mid,tactic=MITRE.get(mkey,("T1059","Execution"))
        self.alert_seq+=1;now=datetime.now(timezone.utc)
        raw_json=mkraw(rule,detail,extra)
        p={"id":hashlib.md5(f"{rule}{time.time()}".encode()).hexdigest()[:12].upper(),"rule_name":rule,"severity":severity,"host":self.hostname,"src_ip":src_ip,"user_name":user,"mitre_id":mid,"tactic":tactic,"score":score,"source":"EDR","status":"NEW","detail":detail,"raw":raw_json,"timestamp":now.isoformat()}
        log.warning(f"[{severity}] {rule} | {detail[:80]}")
        if self.rc:
            try:
                m=json.dumps(p,default=str);self.rc.publish("secos:alerts",m);self.rc.lpush("secos:edr:alerts",m);self.rc.ltrim("secos:edr:alerts",0,999)
            except Exception as e:log.error(f"Redis: {e}")
        if self.db:
            try:
                async with self.db.acquire() as c:
                    await c.execute("INSERT INTO events(rule_name,severity,host,src_ip,user_name,mitre_id,tactic,score,source,status,raw,timestamp) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)",rule,severity,self.hostname,src_ip,user,mid,tactic,score,"EDR","NEW",raw_json,now)
                log.info(f"DB saved: {rule}")
            except Exception as e:log.error(f"DB: {e}")
    def _dd(self,k):
        if k in self.alerted:return False
        self.alerted.add(k)
        if len(self.alerted)>5000:self.alerted=set(list(self.alerted)[-2000:])
        return True
    async def scan_processes(self):
        try:r=subprocess.run(["ps","auxww","--no-headers"],capture_output=True,text=True,timeout=10)
        except Exception:return
        for line in r.stdout.strip().splitlines():
            parts=line.split(None,10)
            if len(parts)<11:continue
            try:uname=parts[0];pid=int(parts[1]);cpu=float(parts[2]);cmd=parts[10];pname=os.path.basename(cmd.split()[0]) if cmd else ""
            except(ValueError,IndexError):continue
            pk=f"{pid}:{pname}"
            if pk in self.seen_procs:continue
            self.seen_procs.add(pk);pl=pname.lower();cl=cmd.lower()
            for sig,(sev,sc,mk) in MALICIOUS.items():
                if sig in pl or sig in cl:
                    if self._dd(f"proc:{sig}:{pid}"):
                        await self.alert(f"Malicious Process: {pname}",sev,sc,mk,detail=f"PID:{pid} User:{uname} Cmd:{cmd[:80]}",user=uname,extra=f"pid={pid} sig={sig}")
                    break
            for pat,sev,sc,mk,desc in CMDPATS:
                if re.search(pat,cl,re.IGNORECASE):
                    if self._dd(f"cmd:{pat[:10]}:{pid}"):
                        await self.alert(f"Suspicious Command: {desc}",sev,sc,mk,detail=f"PID:{pid} User:{uname} Cmd:{cmd[:80]}",user=uname,extra=f"pid={pid}")
                    break
            if any(x in cmd for x in["/tmp/","/dev/shm/","/var/tmp/"]):
                if pl not in{"sh","bash","python3","python","python2"}:
                    if self._dd(f"tmp:{pid}"):
                        await self.alert("Execution from Temp Directory","HIGH",82,"malicious_process",detail=f"PID:{pid} path:{cmd[:80]}",user=uname,extra=f"pid={pid}")
            if cpu>90.0 and pl not in CPU_SAFE:
                if self._dd(f"cpu:{pid}"):
                    await self.alert("High CPU Anomaly","MEDIUM",60,"mem_high",detail=f"PID:{pid} {pname} CPU:{cpu}%",user=uname,extra=f"pid={pid} cpu={cpu}")
        if len(self.seen_procs)>5000:self.seen_procs=set(list(self.seen_procs)[-2000:])
    def _hash(self,path):
        try:
            if os.path.isfile(path) and os.path.getsize(path)<50*1024*1024:
                h=hashlib.sha256()
                with open(path,"rb") as f:
                    for chunk in iter(lambda:f.read(65536),b""):h.update(chunk)
                return h.hexdigest()
        except(PermissionError,OSError):pass
        return None
    def _hash_dir(self,d,limit=60):
        hashes={}
        try:
            for fn in os.listdir(d):
                if len(hashes)>=limit:break
                fp=os.path.join(d,fn);h=self._hash(fp)
                if h:hashes[fp]=h
        except(PermissionError,OSError):pass
        return hashes
    async def build_fim_baseline(self):
        log.info("Building FIM baseline...")
        for path in FIM_PATHS:
            if os.path.isdir(path):self.fim_baseline.update(self._hash_dir(path))
            else:
                h=self._hash(path)
                if h:self.fim_baseline[path]=h
        log.info(f"FIM baseline: {len(self.fim_baseline)} files tracked")
        try:
            r=subprocess.run(["find","/usr","/bin","/sbin","-perm","-4000"],capture_output=True,text=True,timeout=30)
            suids=set(r.stdout.strip().splitlines())
            if suids and self.rc:
                self.rc.delete("edr:suid_baseline");self.rc.sadd("edr:suid_baseline",*suids)
                log.info(f"SUID baseline: {len(suids)} binaries tracked")
        except Exception as e:log.debug(f"SUID: {e}")
    async def scan_fim(self):
        now=time.time()
        if now-self.last_fim<FIM_INTERVAL:return
        self.last_fim=now;log.info("FIM scan running...")
        for path,orig in list(self.fim_baseline.items()):
            cur=self._hash(path);base=next((p for p in FIM_PATHS if path.startswith(p)),path)
            sev,sc,mk=FIM_PATHS.get(base,("HIGH",80,"fim_critical"))
            if cur is None and not os.path.exists(path):
                if self._dd(f"fim:del:{path}"):
                    await self.alert("FIM: Critical File Deleted",sev,sc,mk,detail=f"Deleted: {path}",extra=f"path={path}")
                del self.fim_baseline[path]
            elif cur and cur!=orig:
                if self._dd(f"fim:mod:{path}:{cur[:8]}"):
                    await self.alert("FIM: Critical File Modified",sev,sc,mk,detail=f"Tampered: {path}",extra=f"old={orig[:16]} new={cur[:16]}")
                self.fim_baseline[path]=cur
        for path,(sev,sc,mk) in FIM_PATHS.items():
            if os.path.isdir(path):
                for fp,fh in self._hash_dir(path).items():
                    if fp not in self.fim_baseline:
                        if self._dd(f"fim:new:{fp}"):
                            await self.alert("FIM: New File in Critical Directory",sev,sc,mk,detail=f"New file: {fp}",extra=f"path={fp}")
                        self.fim_baseline[fp]=fh
        try:
            r=subprocess.run(["find","/usr","/bin","/sbin","-perm","-4000"],capture_output=True,text=True,timeout=30)
            cur_suids=set(r.stdout.strip().splitlines())
            if self.rc:
                stored=self.rc.smembers("edr:suid_baseline")
                for s in(cur_suids-stored):
                    if self._dd(f"suid:{s}"):
                        await self.alert("New SUID Binary Detected","CRITICAL",95,"new_suid",detail=f"New SUID: {s}",extra=f"path={s}")
        except Exception as e:log.debug(f"SUID scan: {e}")
    async def scan_network(self):
        try:r=subprocess.run(["ss","-tunp","--no-header"],capture_output=True,text=True,timeout=10)
        except Exception:return
        conn_by_ip=defaultdict(int)
        for line in r.stdout.strip().splitlines():
            parts=line.split()
            if len(parts)<6:continue
            try:
                raddr=parts[5]
                if raddr in("*","0.0.0.0:*",":::*"):continue
                rip,_,rp=raddr.rpartition(":");
                if not rp.isdigit():continue
                rport=int(rp);rip=rip.strip("[]")
                if rip.startswith(("127.","::1","0.0.0.0","10.","172.16.","172.17.","172.25.","192.168.")):continue
            except(ValueError,IndexError):continue
            if rport in SUSP_PORTS:
                if self._dd(f"port:{rip}:{rport}"):
                    sev,sc,mk,desc=SUSP_PORTS[rport]
                    await self.alert(f"Suspicious Connection Port {rport}",sev,sc,mk,detail=f"{desc} to {rip}:{rport}",src_ip=rip,extra=f"dst={rip}:{rport}")
            conn_by_ip[rip]+=1
        for rip,cnt in conn_by_ip.items():
            prev=self.conn_counts.get(rip,0)
            if cnt>=10 and cnt>prev+5:
                if self._dd(f"beacon:{rip}:{cnt}"):
                    await self.alert("Potential C2 Beaconing","HIGH",85,"network_c2",detail=f"{cnt} connections to {rip}",src_ip=rip,extra=f"ip={rip} count={cnt}")
            self.conn_counts[rip]=cnt
        try:
            r=subprocess.run(["ss","-tn","state","syn-sent"],capture_output=True,text=True,timeout=5)
            syn=len([l for l in r.stdout.splitlines() if l.strip()])
            if syn>20:
                if self._dd(f"scan:{syn}"):
                    await self.alert("Port Scan Activity","HIGH",80,"network_scan",detail=f"{syn} SYN-SENT — outbound scan",extra=f"syn_count={syn}")
        except Exception:pass
    async def scan_memory(self):
        try:
            with open("/proc/meminfo") as f:
                mi={}
                for line in f.read().splitlines():
                    if ":" in line:k,v=line.split(":",1);mi[k.strip()]=v.strip()
            total=int(mi.get("MemTotal","0 kB").split()[0]);avail=int(mi.get("MemAvailable","0 kB").split()[0])
            if total>0:
                pct=((total-avail)/total)*100
                if pct>92:
                    if self._dd(f"mempressure:{int(pct)}"):
                        await self.alert("Critical Memory Pressure","HIGH",75,"mem_high",detail=f"Memory at {pct:.1f}%",extra=f"used_pct={pct:.1f}")
            r=subprocess.run(["ps","aux","--no-headers","--sort=-%mem"],capture_output=True,text=True,timeout=10)
            safe={"java","node","python3","python","postgres","mysqld","mongod","elasticsearch","chrome","firefox","ps","top"}
            for line in r.stdout.strip().splitlines()[:15]:
                parts=line.split(None,10)
                if len(parts)<11:continue
                try:uname=parts[0];pid=int(parts[1]);mem=float(parts[3]);vsz=int(parts[4]);rss=int(parts[5]);cmd=parts[10];pl=os.path.basename(cmd.split()[0]).lower() if cmd else ""
                except(ValueError,IndexError):continue
                if mem>30.0 and pl not in safe:
                    if self._dd(f"memhigh:{pid}"):
                        await self.alert("Abnormal Memory Usage","MEDIUM",65,"mem_high",detail=f"PID:{pid} {pl} MEM:{mem}% RSS:{rss//1024}MB",user=uname,extra=f"pid={pid} mem={mem}")
                if vsz>2000000 and rss<10000 and pl not in safe:
                    if self._dd(f"hollow:{pid}"):
                        await self.alert("Process Hollowing Indicator","HIGH",82,"process_injection",detail=f"PID:{pid} {pl} VSZ:{vsz//1024}MB RSS:{rss//1024}MB",user=uname,extra=f"pid={pid} vsz={vsz//1024} rss={rss//1024}")
        except Exception as e:log.debug(f"Memory: {e}")
    async def scan_users(self):
        try:
            r=subprocess.run(["who","-a"],capture_output=True,text=True,timeout=5)
            for line in r.stdout.splitlines():
                if "root" in line and "pts/" in line:
                    if self._dd(f"rootssh:{line[:30]}"):
                        await self.alert("Root Remote Login","HIGH",82,"priv_escalation",detail=f"Root session: {line.strip()[:60]}",user="root",extra="root_remote=true")
                    break
            r=subprocess.run(["awk","-F:","$3 >= 1000 && $3 < 65534 {print $1}","/etc/passwd"],capture_output=True,text=True,timeout=5)
            current=set(r.stdout.strip().splitlines())
            if self.rc:
                stored=self.rc.smembers("edr:known_users")
                if stored:
                    for u in(current-stored):
                        if self._dd(f"newuser:{u}"):
                            await self.alert("New System User Created","HIGH",85,"priv_escalation",detail=f"New account: {u}",user=u,extra=f"username={u}")
                self.rc.delete("edr:known_users")
                if current:self.rc.sadd("edr:known_users",*current)
        except Exception as e:log.debug(f"Users: {e}")
    async def publish_telemetry(self):
        if not self.rc:return
        try:
            r=subprocess.run(["ps","aux","--no-headers"],capture_output=True,text=True,timeout=5)
            now=datetime.now(timezone.utc).isoformat()
            self.rc.setex("secos:edr:telemetry",60,json.dumps({"hostname":self.hostname,"timestamp":now,"status":"online","mode":"suggest","proc_count":len(r.stdout.strip().splitlines()),"fim_tracked":len(self.fim_baseline),"alerts":self.alert_seq,"modules":["process","fim","network","memory","users"]}))
            self.rc.setex("secos:edr:heartbeat",30,now)
        except Exception as e:log.debug(f"Telemetry: {e}")
    async def run(self):
        log.info("SecOS EDR Agent v2.0 starting")
        log.info(f"Host:{self.hostname} | Mode:suggest | Scan:{SCAN_INTERVAL}s")
        log.info("Modules: Process | FIM | Network | Memory | Users")
        await self.connect()
        await self.build_fim_baseline()
        log.info("EDR fully initialized — all modules active")
        cycle=0
        while True:
            try:
                await self.scan_processes()
                await self.scan_network()
                await self.scan_users()
                await self.scan_fim()
                if cycle%3==0:await self.scan_memory()
                await self.publish_telemetry()
                cycle+=1
            except Exception as e:log.error(f"Cycle error: {e}")
            await asyncio.sleep(SCAN_INTERVAL)

if __name__=="__main__":
    try:asyncio.run(EDRAgent().run())
    except KeyboardInterrupt:log.info("EDR stopped")
    except Exception as e:log.critical(f"Fatal: {e}");sys.exit(1)
