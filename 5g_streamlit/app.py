
"""
5G Network Traffic Analyzer — app.py
Stack : Flask (backend API) + Scapy (capture) + Chart.js (frontend)
Theme : Matrix green terminal  |  Layout: Multi-tab dashboard
Run   : python app.py  ->  http://127.0.0.1:5000
"""

import threading, time, random, json
from datetime import datetime
from collections import defaultdict, deque
from flask import Flask, render_template_string, jsonify, request

app = Flask(__name__)

# ═══════════════════════════════════════════════
#  GLOBAL STATE
# ═══════════════════════════════════════════════
capture_active = False
capture_thread  = None
selected_iface  = "Simulated"
packet_log      = deque(maxlen=500)

stats = dict(
    total_packets=0, total_bytes=0, start_time=None,
    protocols=defaultdict(int), traffic_types=defaultdict(int),
    encrypted=0, unencrypted=0,
    src_ip=defaultdict(int), dst_ip=defaultdict(int),
    ports=defaultdict(int), slice_counts=defaultdict(int),
    throughput=deque(maxlen=60), pkt_rate=deque(maxlen=60),
    edge_lat=deque(maxlen=60), cloud_lat=deque(maxlen=60),
    timeline=deque(maxlen=60), anomalies=deque(maxlen=100),
)

# ═══════════════════════════════════════════════
#  CLASSIFICATION TABLES
# ═══════════════════════════════════════════════
PORT_MAP = {
    80:("Web","HTTP",False), 443:("Web","HTTPS",True),
    8080:("Web","HTTP-Alt",False), 8443:("Web","HTTPS-Alt",True),
    53:("DNS","DNS",False), 5353:("DNS","mDNS",False),
    1935:("Streaming","RTMP",False), 554:("Streaming","RTSP",False),
    3478:("Streaming","WebRTC",True), 8888:("Streaming","HLS",True),
    22:("General","SSH",True), 21:("General","FTP",False),
    25:("General","SMTP",False), 110:("General","POP3",False),
    143:("General","IMAP",False), 3389:("General","RDP",True),
    5900:("General","VNC",False), 123:("General","NTP",False),
    67:("General","DHCP",False),
}
SLICE_MAP = {"Web":"eMBB","Streaming":"eMBB","DNS":"mMTC","General":"URLLC"}
LAT_EDGE  = {"Web":5,"DNS":2,"Streaming":8,"General":10}
LAT_CLOUD = {"Web":30,"DNS":15,"Streaming":45,"General":40}
SUSPICIOUS = [4444,31337,1337,6667,9001,6697]
SUSPICIOUS_SET = set(SUSPICIOUS)

def classify(sp, dp, proto):
    for p in (dp, sp):
        if p in PORT_MAP:
            return PORT_MAP[p]
    return ("General","UDP-Generic",False) if proto=="UDP" else ("General","TCP-Generic",False)

def sim_lat(cat):
    e = LAT_EDGE.get(cat,10)  + random.uniform(-2,5)
    c = LAT_CLOUD.get(cat,40) + random.uniform(-5,15)
    return max(1,e), max(10,c)

# ═══════════════════════════════════════════════
#  ANOMALY DETECTION
# ═══════════════════════════════════════════════
def detect_anomalies(pkt):
    alerts = []
    src = pkt["src_ip"]
    cnt = stats["src_ip"][src]
    if cnt > 50 and cnt % 25 == 0:
        alerts.append({"time":pkt["time"],"severity":"HIGH",
            "type":"High-Frequency Source",
            "detail":f"{src} has sent {cnt} packets — possible DoS/scan"})
    if stats["pkt_rate"] and stats["pkt_rate"][-1] > 80:
        alerts.append({"time":pkt["time"],"severity":"MEDIUM",
            "type":"Packet Rate Spike",
            "detail":f"Rate {stats['pkt_rate'][-1]:.0f} pkt/s exceeds threshold (80)"})
    if pkt["dst_port"] in SUSPICIOUS_SET:
        alerts.append({"time":pkt["time"],"severity":"HIGH",
            "type":"Suspicious Port",
            "detail":f"Traffic to port {pkt['dst_port']} from {src} — C2/backdoor indicator"})
    return alerts

# ═══════════════════════════════════════════════
#  SIMULATION ENGINE
# ═══════════════════════════════════════════════
SAMPLE_IPS = (
    ["192.168.1."+str(i) for i in range(2,15)] +
    ["10.0.0."+str(i)    for i in range(1,8)]  +
    ["8.8.8.8","8.8.4.4","1.1.1.1","172.217.160.142",
     "151.101.1.140","104.18.22.61","13.107.42.14"]
)
PORTS = list(PORT_MAP.keys()) + list(range(1025,9000,500))

def gen_packet():
    src = random.choice(SAMPLE_IPS)
    dst = random.choice([ip for ip in SAMPLE_IPS if ip!=src])
    dp  = random.choice(SUSPICIOUS) if random.random()<0.02 else random.choice(PORTS)
    sp  = random.choice(PORTS)
    pr  = random.choices(["TCP","UDP"],[70,30])[0]
    sz  = random.randint(64,1500)
    cat,svc,enc = classify(sp,dp,pr)
    el,cl = sim_lat(cat)
    return dict(time=datetime.now().strftime("%H:%M:%S.%f")[:-3],
                src_ip=src, dst_ip=dst, src_port=sp, dst_port=dp,
                protocol=pr, size=sz, category=cat, service=svc,
                encrypted=enc, slice=SLICE_MAP.get(cat,"eMBB"),
                edge_lat=round(el,2), cloud_lat=round(cl,2))

def record(pkt):
    stats["total_packets"] += 1
    stats["total_bytes"]   += pkt["size"]
    stats["protocols"][pkt["protocol"]] += 1
    stats["traffic_types"][pkt["category"]] += 1
    stats["src_ip"][pkt["src_ip"]] += 1
    stats["dst_ip"][pkt["dst_ip"]] += 1
    stats["ports"][str(pkt["dst_port"])] += 1
    stats["slice_counts"][pkt["slice"]] += 1
    if pkt["encrypted"]: stats["encrypted"] += 1
    else:                stats["unencrypted"] += 1
    stats["edge_lat"].append(pkt["edge_lat"])
    stats["cloud_lat"].append(pkt["cloud_lat"])
    packet_log.appendleft(pkt)
    for a in detect_anomalies(pkt):
        stats["anomalies"].appendleft(a)

# ═══════════════════════════════════════════════
#  SCAPY REAL CAPTURE
# ═══════════════════════════════════════════════
def real_capture(iface):
    try:
        from scapy.all import sniff, IP, TCP, UDP
    except ImportError:
        return False
    def cb(pkt):
        if not capture_active or IP not in pkt: return
        ip=pkt[IP]; pr="TCP" if TCP in pkt else ("UDP" if UDP in pkt else "OTHER")
        sp=pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
        dp=pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
        cat,svc,enc=classify(sp,dp,pr); el,cl=sim_lat(cat)
        record(dict(time=datetime.now().strftime("%H:%M:%S.%f")[:-3],
            src_ip=ip.src,dst_ip=ip.dst,src_port=sp,dst_port=dp,
            protocol=pr,size=len(pkt),category=cat,service=svc,
            encrypted=enc,slice=SLICE_MAP.get(cat,"eMBB"),
            edge_lat=round(el,2),cloud_lat=round(cl,2)))
    try:
        sniff(iface=iface,prn=cb,store=False,stop_filter=lambda _:not capture_active)
        return True
    except Exception:
        return False

def sim_loop():
    last=time.time(); cnt=0; byt=0
    while capture_active:
        for _ in range(random.randint(2,8)):
            if not capture_active: break
            p=gen_packet(); record(p); cnt+=1; byt+=p["size"]
        if time.time()-last >= 1.0:
            stats["pkt_rate"].append(cnt)
            stats["throughput"].append(round(byt*8/1000,1))
            stats["timeline"].append({"t":datetime.now().strftime("%H:%M:%S"),"r":cnt,"k":round(byt*8/1000,1)})
            cnt=0; byt=0; last=time.time()
        time.sleep(0.06)

def run_capture(iface):
    stats["start_time"]=time.time()
    if iface!="Simulated" and real_capture(iface): return
    sim_loop()

# ═══════════════════════════════════════════════
#  API ROUTES
# ═══════════════════════════════════════════════
@app.route("/")
def index():
    return render_template_string(HTML)

@app.route("/api/interfaces")
def get_ifaces():
    ifaces=["Simulated"]
    try:
        from scapy.all import get_if_list
        ifaces+=[i for i in get_if_list() if i not in ifaces]
    except: pass
    return jsonify({"interfaces":ifaces})

@app.route("/api/start",methods=["POST"])
def start():
    global capture_active,capture_thread,selected_iface
    if capture_active: return jsonify({"status":"already_running"})
    d=request.get_json() or {}
    selected_iface=d.get("interface","Simulated")
    stats.update(total_packets=0,total_bytes=0,encrypted=0,unencrypted=0)
    for k in ["protocols","traffic_types","src_ip","dst_ip","ports","slice_counts"]:
        stats[k].clear()
    for k in ["throughput","pkt_rate","edge_lat","cloud_lat","timeline","anomalies"]:
        stats[k].clear()
    packet_log.clear()
    capture_active=True
    capture_thread=threading.Thread(target=run_capture,args=(selected_iface,),daemon=True)
    capture_thread.start()
    return jsonify({"status":"started","interface":selected_iface})

@app.route("/api/stop",methods=["POST"])
def stop():
    global capture_active
    capture_active=False
    return jsonify({"status":"stopped"})

@app.route("/api/status")
def status():
    el=time.time()-stats["start_time"] if stats["start_time"] and capture_active else 0
    tp=list(stats["throughput"]); pr=list(stats["pkt_rate"])
    ed=list(stats["edge_lat"]);   cl=list(stats["cloud_lat"])
    return jsonify(dict(
        active=capture_active, interface=selected_iface, elapsed=round(el,1),
        total_packets=stats["total_packets"], total_bytes=stats["total_bytes"],
        avg_tp=round(sum(tp[-10:])/len(tp[-10:]),1) if tp else 0,
        avg_rate=round(sum(pr[-10:])/len(pr[-10:]),1) if pr else 0,
        protocols=dict(stats["protocols"]),
        traffic_types=dict(stats["traffic_types"]),
        encrypted=stats["encrypted"], unencrypted=stats["unencrypted"],
        top_src=sorted(stats["src_ip"].items(),key=lambda x:x[1],reverse=True)[:10],
        top_dst=sorted(stats["dst_ip"].items(),key=lambda x:x[1],reverse=True)[:10],
        top_ports=sorted(stats["ports"].items(),key=lambda x:x[1],reverse=True)[:10],
        slice_counts=dict(stats["slice_counts"]),
        anomaly_count=len(stats["anomalies"]),
        avg_edge=round(sum(ed)/len(ed),2) if ed else 0,
        avg_cloud=round(sum(cl)/len(cl),2) if cl else 0,
        timeline=list(stats["timeline"]),
    ))

@app.route("/api/packets")
def packets():
    limit=int(request.args.get("limit",150))
    return jsonify({"packets":list(packet_log)[:limit]})

@app.route("/api/anomalies")
def anomalies():
    return jsonify({"anomalies":list(stats["anomalies"])})

# ═══════════════════════════════════════════════
#  EMBEDDED HTML (single-file delivery)
# ═══════════════════════════════════════════════
HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>5G NET ANALYZER</title>
<link href="https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=VT323&display=swap" rel="stylesheet">
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
/* ═══════════════════════════════════════════════════
   MATRIX GREEN TERMINAL THEME
   ═══════════════════════════════════════════════════ */
:root{
  --bg:      #000300;
  --bg2:     #010801;
  --bg3:     #021002;
  --panel:   #011501;
  --border:  #0a3a0a;
  --border2: #0f5a0f;
  --g1:      #00ff41;  /* matrix bright green */
  --g2:      #00cc33;  /* mid green */
  --g3:      #008f20;  /* dim green */
  --g4:      #005a14;  /* dark green */
  --g5:      #002a08;  /* very dark */
  --amber:   #ffb300;
  --red:     #ff2222;
  --text:    #b8ffb8;
  --text2:   #5a9a5a;
  --text3:   #1a4a1a;
  --glow:    0 0 10px rgba(0,255,65,0.4), 0 0 30px rgba(0,255,65,0.15);
  --glow2:   0 0 4px rgba(0,255,65,0.3);
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}

body{
  font-family:'Share Tech Mono',monospace;
  background:var(--bg);
  color:var(--text);
  min-height:100vh;
  overflow-x:hidden;
}

/* Scanline + rain overlay */
body::before{
  content:'';position:fixed;top:0;left:0;right:0;bottom:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 2px,rgba(0,255,65,0.02) 2px,rgba(0,255,65,0.02) 4px);
  pointer-events:none;z-index:9999;
}

/* ── HEADER ── */
.header{
  display:flex;align-items:center;justify-content:space-between;
  padding:.6rem 1.4rem;
  background:var(--bg2);
  border-bottom:1px solid var(--border2);
  box-shadow:0 2px 20px rgba(0,255,65,0.1);
  position:sticky;top:0;z-index:100;
}
.logo{display:flex;align-items:center;gap:.75rem}
.logo-glyph{
  font-family:'VT323',monospace;font-size:2rem;color:var(--g1);
  text-shadow:var(--glow);animation:flicker 8s infinite;
}
@keyframes flicker{0%,95%,100%{opacity:1}96%,98%{opacity:.4}97%,99%{opacity:.9}}
.logo-text{line-height:1.2}
.logo-title{
  font-family:'VT323',monospace;font-size:1.5rem;color:var(--g1);
  letter-spacing:.1em;text-shadow:var(--glow2);
}
.logo-sub{font-size:.58rem;color:var(--g3);letter-spacing:.2em}

.hdr-status{display:flex;align-items:center;gap:.75rem;font-size:.75rem;color:var(--text2)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--g4);transition:all .3s}
.dot.on{background:var(--g1);box-shadow:var(--glow);animation:blink 1.4s infinite}
@keyframes blink{0%,100%{opacity:1}50%{opacity:.4}}
.pipe{color:var(--border2)}

.hdr-right{display:flex;align-items:center;gap:.5rem}
select.iface{
  background:var(--bg3);border:1px solid var(--border2);
  color:var(--g2);padding:.35rem .5rem;font-family:'Share Tech Mono',monospace;
  font-size:.72rem;border-radius:3px;cursor:pointer;
}
select.iface:focus{outline:none;border-color:var(--g1)}
.btn{
  padding:.35rem .9rem;border-radius:3px;
  font-family:'Share Tech Mono',monospace;font-size:.75rem;
  cursor:pointer;font-weight:700;letter-spacing:.1em;
  transition:all .2s;border:1px solid;
}
.btn-start{
  background:var(--g5);border-color:var(--g3);color:var(--g2);
}
.btn-start:hover:not(:disabled){
  background:var(--g1);color:#000;border-color:var(--g1);
  box-shadow:var(--glow);
}
.btn-stop{background:rgba(255,34,34,.1);border-color:var(--red);color:var(--red)}
.btn-stop:hover:not(:disabled){background:var(--red);color:#fff;box-shadow:0 0 10px rgba(255,34,34,.5)}
.btn:disabled{opacity:.3;cursor:not-allowed}

/* ── TABS ── */
.tabs{
  display:flex;
  background:var(--bg2);
  border-bottom:1px solid var(--border);
  padding:0 1.4rem;
}
.tab{
  padding:.65rem 1.1rem;background:none;border:none;
  color:var(--text3);cursor:pointer;
  font-family:'Share Tech Mono',monospace;font-size:.72rem;
  letter-spacing:.12em;border-bottom:2px solid transparent;
  transition:all .2s;position:relative;
}
.tab:hover{color:var(--g2)}
.tab.active{color:var(--g1);border-bottom-color:var(--g1);background:rgba(0,255,65,.04)}
.badge{
  display:inline-block;background:var(--red);color:#fff;
  font-size:.58rem;padding:1px 5px;border-radius:8px;margin-left:4px;
}
.badge.h{display:none}

/* ── TAB CONTENT ── */
.tc{display:none;padding:1rem 1.4rem}
.tc.active{display:block}

/* ── KPI ROW ── */
.kpi-row{
  display:grid;grid-template-columns:repeat(6,1fr);
  gap:.6rem;margin-bottom:.9rem;
}
.kpi{
  background:var(--panel);border:1px solid var(--border);
  border-top:2px solid var(--border2);border-radius:4px;
  padding:.85rem .75rem;text-align:center;
  transition:border-color .3s;
}
.kpi:hover{border-color:var(--g3);box-shadow:var(--glow2)}
.kpi-lbl{font-size:.56rem;color:var(--text3);letter-spacing:.18em;margin-bottom:.35rem}
.kpi-val{
  font-family:'VT323',monospace;font-size:2rem;color:var(--g1);
  line-height:1;text-shadow:var(--glow2);
}
.kpi-val.g2{color:var(--g2)}
.kpi-val.red{color:var(--red);text-shadow:0 0 8px rgba(255,34,34,.5)}
.kpi-val.amber{color:var(--amber);text-shadow:0 0 8px rgba(255,179,0,.4)}
.kpi-u{font-family:'Share Tech Mono',monospace;font-size:.75rem;color:var(--text2)}
.kpi-sub{font-size:.58rem;color:var(--text3);margin-top:.25rem}

/* ── CHARTS ── */
.crow{display:flex;gap:.6rem;margin-bottom:.6rem;flex-wrap:nowrap;align-items:stretch}
.cp{
  background:var(--panel);border:1px solid var(--border);
  border-radius:4px;padding:.85rem;
  flex:1;min-width:0;
  display:flex;flex-direction:column;
  height:270px;overflow:hidden;
}
.cp canvas{flex:1;min-height:0;max-height:200px}
.cp.w{flex:2.5}.cp.w2{flex:2}.cp.info{min-height:auto}
.ph{
  font-size:.62rem;color:var(--g2);letter-spacing:.15em;
  margin-bottom:.65rem;
  display:flex;align-items:center;justify-content:space-between;
  flex-wrap:wrap;gap:.3rem;
}
.ph-sub{color:var(--text3);font-size:.58rem}

/* ── TABLE ── */
.panel{background:var(--panel);border:1px solid var(--border);border-radius:4px;padding:.85rem}
.tctrl{display:flex;gap:.4rem;flex-wrap:wrap}
.fi,.fs{
  background:var(--bg3);border:1px solid var(--border2);
  color:var(--text);padding:.28rem .45rem;
  font-family:'Share Tech Mono',monospace;font-size:.68rem;
  border-radius:3px;
}
.fi{width:180px}.fi:focus,.fs:focus{outline:none;border-color:var(--g1)}
.tw{overflow:auto;max-height:56vh;margin-top:.65rem;border:1px solid var(--border);border-radius:3px}
.pt{width:100%;border-collapse:collapse;font-size:.68rem}
.pt th{
  background:var(--bg2);color:var(--g2);padding:.45rem .65rem;
  text-align:left;font-size:.6rem;letter-spacing:.1em;
  border-bottom:1px solid var(--border2);position:sticky;top:0;z-index:1;
}
.pt td{
  padding:.3rem .65rem;border-bottom:1px solid rgba(10,58,10,.4);
  color:var(--text)
}
.pt tr:hover td{background:rgba(0,255,65,.03)}
.ey{color:var(--g1)}.en{color:var(--red)}
.cw{color:var(--g1)}.cd{color:var(--amber)}.cs{color:#00aaff}.cg{color:var(--text2)}
.pt{color:var(--g2)}.pu{color:var(--amber)}

/* ── ANOMALIES ── */
.alist{max-height:42vh;overflow-y:auto;display:flex;flex-direction:column;gap:.4rem}
.ai{
  background:var(--bg3);border:1px solid var(--border);
  border-left:3px solid var(--red);border-radius:3px;
  padding:.5rem .65rem;display:flex;align-items:center;gap:.6rem;
  animation:slidein .3s ease;
}
.ai.med{border-left-color:var(--amber)}
@keyframes slidein{from{opacity:0;transform:translateX(-8px)}to{opacity:1;transform:none}}
.at{font-size:.62rem;color:var(--text3);min-width:68px}
.asev{
  font-size:.58rem;padding:2px 5px;border-radius:2px;
  font-weight:700;letter-spacing:.1em;white-space:nowrap;
}
.sh{background:rgba(255,34,34,.15);color:var(--red);border:1px solid var(--red)}
.sm{background:rgba(255,179,0,.15);color:var(--amber);border:1px solid var(--amber)}
.atype{font-weight:600;font-size:.72rem;color:var(--g1)}
.adet{font-size:.65rem;color:var(--text2);font-family:'Share Tech Mono',monospace}
.empty{color:var(--text3);text-align:center;padding:2rem;font-size:.82rem}

.rule-list{display:flex;flex-direction:column;gap:.7rem}
.ri{display:flex;align-items:flex-start;gap:.65rem}
.ric{
  width:26px;height:26px;border-radius:3px;flex-shrink:0;
  display:flex;align-items:center;justify-content:center;
  font-weight:700;font-size:.8rem;
}
.ric.h{background:rgba(255,34,34,.15);color:var(--red);border:1px solid var(--red)}
.ric.m{background:rgba(255,179,0,.15);color:var(--amber);border:1px solid var(--amber)}
.rn{font-size:.75rem;color:var(--g1);font-weight:600}
.rd{font-size:.66rem;color:var(--text2);margin-top:.15rem}

/* ── 5G SLICES ── */
.sintro{margin-bottom:1.1rem}
.sintro h2{
  font-family:'VT323',monospace;font-size:1.6rem;
  color:var(--g1);text-shadow:var(--glow2);letter-spacing:.08em;margin-bottom:.25rem;
}
.sintro p{font-size:.75rem;color:var(--text2)}

.scards{display:grid;grid-template-columns:repeat(3,1fr);gap:.6rem}
.sc{
  background:var(--panel);border:1px solid var(--border);
  border-radius:4px;padding:1.1rem;
}
.sc.e{border-top:3px solid var(--g1)}
.sc.u{border-top:3px solid var(--amber)}
.sc.m{border-top:3px solid #00aaff}
.sbadge{
  display:inline-block;font-size:.62rem;font-weight:700;
  padding:2px 7px;border-radius:2px;letter-spacing:.1em;margin-bottom:.45rem;
}
.e .sbadge{background:rgba(0,255,65,.1);color:var(--g1);border:1px solid var(--g1)}
.u .sbadge{background:rgba(255,179,0,.1);color:var(--amber);border:1px solid var(--amber)}
.m .sbadge{background:rgba(0,170,255,.1);color:#00aaff;border:1px solid #00aaff}
.sname{font-size:.82rem;font-weight:600;margin-bottom:.35rem;color:var(--g2)}
.sdesc{font-size:.68rem;color:var(--text2);margin-bottom:.65rem;line-height:1.4}
.sstat{
  font-family:'VT323',monospace;font-size:1.3rem;
  color:var(--g1);text-shadow:var(--glow2);margin-bottom:.35rem;
}
.sbar{height:3px;background:var(--border);border-radius:2px;overflow:hidden}
.sbf{height:100%;transition:width .5s;border-radius:2px}
.e .sbf{background:linear-gradient(90deg,var(--g3),var(--g1))}
.u .sbf{background:linear-gradient(90deg,#aa7000,var(--amber))}
.m .sbf{background:linear-gradient(90deg,#0055aa,#00aaff)}

.mec{
  display:flex;align-items:center;justify-content:center;
  gap:1.25rem;margin-top:1.1rem;padding:1rem 1.4rem;
  background:var(--panel);border:1px solid var(--border);border-radius:4px;
}
.mb{text-align:center}
.mb.hl{background:rgba(0,255,65,.04);padding:.65rem 1rem;border-radius:4px;border:1px solid var(--border2)}
.mlbl{font-size:.58rem;color:var(--text3);letter-spacing:.18em;margin-bottom:.25rem}
.mval{
  font-family:'VT323',monospace;font-size:1.6rem;
  text-shadow:var(--glow2);
}
.mval.g{color:var(--g1)}.mval.a{color:var(--amber)}.mval.gr{color:var(--g2)}
.msub{font-size:.6rem;color:var(--text3);margin-top:.15rem}
.marr{font-size:1.2rem;color:var(--border2)}

/* Scrollbar */
::-webkit-scrollbar{width:5px;height:5px}
::-webkit-scrollbar-track{background:var(--bg2)}
::-webkit-scrollbar-thumb{background:var(--g4);border-radius:3px}
::-webkit-scrollbar-thumb:hover{background:var(--g3)}
</style>
</head>
<body>

<!-- HEADER -->
<header class="header">
  <div class="logo">
    <div class="logo-glyph">[5G]</div>
    <div class="logo-text">
      <div class="logo-title">NET_ANALYZER // MATRIX_ED</div>
      <div class="logo-sub">REAL-TIME PACKET INTELLIGENCE SYSTEM v3.1 &nbsp;|&nbsp; 5G NETWORK SLICING ENABLED</div>
    </div>
  </div>
  <div class="hdr-status">
    <span class="dot" id="dot"></span>
    <span id="stxt">OFFLINE</span>
    <span class="pipe">|</span>
    <span id="iflbl">IFACE: —</span>
    <span class="pipe">|</span>
    <span id="elbl" style="color:var(--g2)">00:00:00</span>
  </div>
  <div class="hdr-right">
    <select id="iface" class="iface"><option value="Simulated">Simulated</option></select>
    <button id="startBtn" class="btn btn-start" onclick="startCap()">&#9654; START</button>
    <button id="stopBtn"  class="btn btn-stop"  onclick="stopCap()" disabled>&#9632; STOP</button>
  </div>
</header>

<!-- TABS -->
<nav class="tabs">
  <button class="tab active" onclick="tab('overview',this)">&#9608; OVERVIEW</button>
  <button class="tab" onclick="tab('traffic',this)">&#9608; TRAFFIC</button>
  <button class="tab" onclick="tab('packets',this)">&#9608; PACKETS</button>
  <button class="tab" onclick="tab('anomalies',this)">&#9608; ANOMALIES <span class="badge h" id="abadge">0</span></button>
  <button class="tab" onclick="tab('fiveg',this)">&#9608; 5G_SLICES</button>
</nav>

<!-- ══ OVERVIEW ══ -->
<div id="tab-overview" class="tc active">
  <div class="kpi-row">
    <div class="kpi"><div class="kpi-lbl">TOTAL PACKETS</div><div class="kpi-val" id="kPkts">0</div><div class="kpi-sub">captured</div></div>
    <div class="kpi"><div class="kpi-lbl">THROUGHPUT</div><div class="kpi-val g2" id="kTp">0 <span class="kpi-u">kbps</span></div><div class="kpi-sub">avg 10s</div></div>
    <div class="kpi"><div class="kpi-lbl">PACKET RATE</div><div class="kpi-val g2" id="kRate">0 <span class="kpi-u">p/s</span></div><div class="kpi-sub">avg 10s</div></div>
    <div class="kpi"><div class="kpi-lbl">DATA VOLUME</div><div class="kpi-val" id="kBytes">0 <span class="kpi-u">B</span></div><div class="kpi-sub">total</div></div>
    <div class="kpi"><div class="kpi-lbl">ENCRYPTED</div><div class="kpi-val amber" id="kEnc">0<span class="kpi-u">%</span></div><div class="kpi-sub" id="kEncD">—</div></div>
    <div class="kpi"><div class="kpi-lbl">ANOMALIES</div><div class="kpi-val red" id="kAnm">0</div><div class="kpi-sub">detected</div></div>
  </div>
  <div class="crow">
    <div class="cp w" style="min-height:220px"><div class="ph">LIVE THROUGHPUT <span class="ph-sub">kbps</span></div><canvas id="cTp"></canvas></div>
    <div class="cp"   style="min-height:220px"><div class="ph">PROTOCOL SPLIT</div><canvas id="cProto"></canvas></div>
    <div class="cp"   style="min-height:220px"><div class="ph">TRAFFIC CATEGORIES</div><canvas id="cCat"></canvas></div>
  </div>
  <div class="crow">
    <div class="cp"  style="min-height:200px"><div class="ph">ENCRYPTION STATUS</div><canvas id="cEnc"></canvas></div>
    <div class="cp w2" style="min-height:200px"><div class="ph">PACKET RATE <span class="ph-sub">pkt/s</span></div><canvas id="cRate"></canvas></div>
  </div>
</div>

<!-- ══ TRAFFIC ══ -->
<div id="tab-traffic" class="tc">
  <div class="crow">
    <div class="cp w2" style="min-height:220px"><div class="ph">TOP SOURCE IPs</div><canvas id="cSrc"></canvas></div>
    <div class="cp"   style="min-height:220px"><div class="ph">TOP DESTINATION IPs</div><canvas id="cDst"></canvas></div>
  </div>
  <div class="crow">
    <div class="cp"  style="min-height:220px"><div class="ph">TOP PORTS</div><canvas id="cPorts"></canvas></div>
    <div class="cp w2" style="min-height:220px"><div class="ph">EDGE vs CLOUD LATENCY <span class="ph-sub">ms</span></div><canvas id="cLat"></canvas></div>
  </div>
</div>

<!-- ══ PACKETS ══ -->
<div id="tab-packets" class="tc">
  <div class="panel">
    <div class="ph">
      LIVE PACKET STREAM
      <div class="tctrl">
        <input type="text" id="fi" class="fi" placeholder="filter: ip / port / service..." oninput="filt()">
        <select id="fp" class="fs" onchange="filt()"><option value="">ALL PROTO</option><option>TCP</option><option>UDP</option></select>
        <select id="fc" class="fs" onchange="filt()"><option value="">ALL CATS</option><option>Web</option><option>DNS</option><option>Streaming</option><option>General</option></select>
      </div>
    </div>
    <div class="tw">
      <table class="pt">
        <thead><tr>
          <th>TIME</th><th>SRC IP</th><th>DST IP</th>
          <th>PROTO</th><th>SPORT</th><th>DPORT</th>
          <th>SERVICE</th><th>CATEGORY</th><th>BYTES</th><th>ENC</th>
        </tr></thead>
        <tbody id="ptbody"></tbody>
      </table>
    </div>
  </div>
</div>

<!-- ══ ANOMALIES ══ -->
<div id="tab-anomalies" class="tc">
  <div class="panel">
    <div class="ph">ANOMALY DETECTION LOG <span class="ph-sub">real-time threat intelligence</span></div>
    <div id="alist" class="alist"><div class="empty">:: SYSTEM NOMINAL — NO ANOMALIES DETECTED ::</div></div>
  </div>
  <div class="crow" style="margin-top:.8rem">
    <div class="cp info">
      <div class="ph">DETECTION RULES</div>
      <div class="rule-list">
        <div class="ri"><div class="ric h">!</div><div><div class="rn">High-Frequency Source IP</div><div class="rd">Single IP &gt; 50 packets — potential DoS / network scanner</div></div></div>
        <div class="ri"><div class="ric m">~</div><div><div class="rn">Packet Rate Spike</div><div class="rd">Rate &gt; 80 pkt/s — sudden traffic burst detected</div></div></div>
        <div class="ri"><div class="ric h">!</div><div><div class="rn">Suspicious Port Traffic</div><div class="rd">Ports 4444, 31337, 1337, 6667 — known C2 / backdoor indicators</div></div></div>
      </div>
    </div>
    <div class="cp w2" style="min-height:200px">
      <div class="ph">SEVERITY BREAKDOWN</div>
      <canvas id="cAnm"></canvas>
    </div>
  </div>
</div>

<!-- ══ 5G SLICES ══ -->
<div id="tab-fiveg" class="tc">
  <div class="sintro">
    <h2>&gt; 5G_NETWORK_SLICING_ENGINE</h2>
    <p>Traffic auto-classified into 3GPP-defined network slices. MEC (Multi-access Edge Computing) latency simulation active.</p>
  </div>
  <div class="scards">
    <div class="sc e">
      <div class="sbadge">eMBB</div>
      <div class="sname">Enhanced Mobile Broadband</div>
      <div class="sdesc">High-throughput traffic: web browsing, video streaming, large file transfers</div>
      <div class="sstat" id="sE">0 packets</div>
      <div class="sbar"><div class="sbf" id="sEb" style="width:0%"></div></div>
    </div>
    <div class="sc u">
      <div class="sbadge">URLLC</div>
      <div class="sname">Ultra-Reliable Low-Latency</div>
      <div class="sdesc">Mission-critical: autonomous systems, remote surgery, industrial control</div>
      <div class="sstat" id="sU">0 packets</div>
      <div class="sbar"><div class="sbf" id="sUb" style="width:0%"></div></div>
    </div>
    <div class="sc m">
      <div class="sbadge">mMTC</div>
      <div class="sname">Massive Machine-Type Comms</div>
      <div class="sdesc">IoT density: DNS queries, sensor telemetry, small device payloads</div>
      <div class="sstat" id="sM">0 packets</div>
      <div class="sbar"><div class="sbf" id="sMb" style="width:0%"></div></div>
    </div>
  </div>
  <div class="crow" style="margin-top:.8rem">
    <div class="cp" style="min-height:220px"><div class="ph">SLICE DISTRIBUTION</div><canvas id="cSlice"></canvas></div>
    <div class="cp w2" style="min-height:220px"><div class="ph">MEC vs CLOUD LATENCY OVER TIME <span class="ph-sub">ms</span></div><canvas id="cMEC"></canvas></div>
  </div>
  <div class="mec">
    <div class="mb"><div class="mlbl">AVG EDGE LATENCY</div><div class="mval g" id="mEdge">— ms</div><div class="msub">Multi-Access Edge Node</div></div>
    <div class="marr">&gt;&gt;</div>
    <div class="mb"><div class="mlbl">AVG CLOUD LATENCY</div><div class="mval a" id="mCloud">— ms</div><div class="msub">Central Cloud DC</div></div>
    <div class="marr">&gt;&gt;</div>
    <div class="mb hl"><div class="mlbl">EDGE ADVANTAGE</div><div class="mval gr" id="mAdv">— %</div><div class="msub">Latency saved via MEC</div></div>
  </div>
</div>

<script>
/* ═══════════════════════════════════════════════════
   DASHBOARD JS — Matrix Terminal Edition
   ═══════════════════════════════════════════════════ */
const G1='#00ff41',G2='#00cc33',G3='#008f20',AMBER='#ffb300',RED='#ff2222',BLUE='#00aaff';
const GRID='#0a3a0a', GRID2='rgba(0,255,65,0.06)';

Chart.defaults.color='#5a9a5a';
Chart.defaults.borderColor=GRID;
Chart.defaults.font.family="'Share Tech Mono', monospace";
Chart.defaults.font.size=10;

const C={};
function mk(id,cfg){
  const el=document.getElementById(id); if(!el)return null;
  if(C[id])C[id].destroy();
  C[id]=new Chart(el.getContext('2d'),cfg); return C[id];
}
function line(label,color){
  return{label,borderColor:color,backgroundColor:color+'18',
    borderWidth:1.5,pointRadius:0,tension:.4,fill:true};
}
function push(ch,label,val,max=40){
  ch.data.labels.push(label);
  ch.data.datasets[0].data.push(val);
  if(ch.data.labels.length>max){ch.data.labels.shift();ch.data.datasets[0].data.shift();}
  ch.update('none');
}
function doughnut(ch,labels,data){
  ch.data.labels=labels;ch.data.datasets[0].data=data;ch.update('none');
}
function barH(ch,labels,data){
  ch.data.labels=labels;ch.data.datasets[0].data=data;ch.update('none');
}

function initCharts(){
  const lineOpts=(yFmt)=>({
    animation:false,responsive:true,maintainAspectRatio:false,
    scales:{
      x:{ticks:{maxTicksLimit:8,color:'#1a4a1a'},grid:{color:GRID}},
      y:{beginAtZero:true,grid:{color:GRID},ticks:{color:'#5a9a5a',callback:yFmt||undefined}}
    },
    plugins:{legend:{display:false}}
  });
  const donutOpts={
    responsive:true,maintainAspectRatio:false,
    plugins:{legend:{position:'bottom',labels:{boxWidth:10,padding:7,color:'#5a9a5a'}}}
  };
  const barOpts=(horiz=false)=>({
    animation:false,responsive:true,maintainAspectRatio:false,
    indexAxis:horiz?'y':'x',
    scales:{
      x:{beginAtZero:true,grid:{color:horiz?GRID:'transparent'},ticks:{color:'#5a9a5a'}},
      y:{grid:{color:horiz?'transparent':GRID},ticks:{color:'#5a9a5a'}}
    },
    plugins:{legend:{display:false}}
  });

  mk('cTp',{type:'line',data:{labels:[],datasets:[line('kbps',G1)]},
    options:{...lineOpts(v=>v+'k'),animation:false,responsive:true,maintainAspectRatio:false,
      scales:{x:{ticks:{maxTicksLimit:8,color:'#1a4a1a'},grid:{color:GRID}},
              y:{beginAtZero:true,grid:{color:GRID},ticks:{color:'#5a9a5a',callback:v=>v+'k'}}},
      plugins:{legend:{display:false}}}});

  mk('cRate',{type:'line',data:{labels:[],datasets:[line('pkt/s',G2)]},
    options:{...lineOpts(),animation:false,responsive:true,maintainAspectRatio:false,
      scales:{x:{ticks:{maxTicksLimit:8,color:'#1a4a1a'},grid:{color:GRID}},
              y:{beginAtZero:true,grid:{color:GRID},ticks:{color:'#5a9a5a'}}},
      plugins:{legend:{display:false}}}});

  mk('cProto',{type:'doughnut',
    data:{labels:[],datasets:[{data:[],backgroundColor:[G1,AMBER,BLUE,RED,'#cc44aa'],
      borderColor:'#000300',borderWidth:2}]},options:donutOpts});

  mk('cCat',{type:'doughnut',
    data:{labels:['Web','DNS','Streaming','General'],
      datasets:[{data:[0,0,0,0],backgroundColor:[G1,AMBER,BLUE,'#5a9a5a'],
        borderColor:'#000300',borderWidth:2}]},options:donutOpts});

  mk('cEnc',{type:'doughnut',
    data:{labels:['Encrypted','Plain'],
      datasets:[{data:[0,0],backgroundColor:[G2,RED],borderColor:'#000300',borderWidth:2}]},
    options:donutOpts});

  mk('cSrc',{type:'bar',
    data:{labels:[],datasets:[{label:'pkts',data:[],backgroundColor:G1+'55',borderColor:G1,borderWidth:1}]},
    options:{...barOpts(true),animation:false,responsive:true,maintainAspectRatio:false,
      indexAxis:'y',scales:{x:{beginAtZero:true,grid:{color:GRID},ticks:{color:'#5a9a5a'}},
      y:{grid:{display:false},ticks:{color:'#5a9a5a'}}},plugins:{legend:{display:false}}}});

  mk('cDst',{type:'bar',
    data:{labels:[],datasets:[{label:'pkts',data:[],backgroundColor:AMBER+'55',borderColor:AMBER,borderWidth:1}]},
    options:{animation:false,responsive:true,maintainAspectRatio:false,indexAxis:'y',
      scales:{x:{beginAtZero:true,grid:{color:GRID},ticks:{color:'#5a9a5a'}},
              y:{grid:{display:false},ticks:{color:'#5a9a5a'}}},plugins:{legend:{display:false}}}});

  mk('cPorts',{type:'bar',
    data:{labels:[],datasets:[{label:'pkts',data:[],backgroundColor:BLUE+'55',borderColor:BLUE,borderWidth:1}]},
    options:{animation:false,responsive:true,maintainAspectRatio:false,
      scales:{x:{ticks:{maxRotation:45,color:'#5a9a5a'},grid:{display:false}},
              y:{beginAtZero:true,grid:{color:GRID},ticks:{color:'#5a9a5a'}}},
      plugins:{legend:{display:false}}}});

  mk('cLat',{type:'line',
    data:{labels:[],datasets:[
      {...line('Edge MEC',G1),fill:false},
      {...line('Cloud DC',AMBER),fill:false}
    ]},
    options:{animation:false,responsive:true,maintainAspectRatio:false,
      scales:{x:{ticks:{maxTicksLimit:8,color:'#1a4a1a'},grid:{color:GRID}},
              y:{beginAtZero:true,grid:{color:GRID},ticks:{color:'#5a9a5a',callback:v=>v+'ms'}}},
      plugins:{legend:{position:'top',labels:{boxWidth:10,padding:7,color:'#5a9a5a'}}}}});

  mk('cAnm',{type:'bar',
    data:{labels:['HIGH','MEDIUM'],
      datasets:[{data:[0,0],backgroundColor:[RED+'88',AMBER+'88'],borderColor:[RED,AMBER],borderWidth:1}]},
    options:{responsive:true,maintainAspectRatio:false,
      scales:{y:{beginAtZero:true,grid:{color:GRID},ticks:{color:'#5a9a5a'}}},
      plugins:{legend:{display:false}}}});

  mk('cSlice',{type:'doughnut',
    data:{labels:['eMBB','URLLC','mMTC'],
      datasets:[{data:[0,0,0],backgroundColor:[G1,AMBER,BLUE],borderColor:'#000300',borderWidth:2}]},
    options:donutOpts});

  mk('cMEC',{type:'line',
    data:{labels:[],datasets:[
      {...line('Edge MEC',G1)},{...line('Cloud DC',AMBER)}
    ]},
    options:{animation:false,responsive:true,maintainAspectRatio:false,
      scales:{x:{ticks:{maxTicksLimit:8,color:'#1a4a1a'},grid:{color:GRID}},
              y:{beginAtZero:true,grid:{color:GRID},ticks:{color:'#5a9a5a',callback:v=>v+'ms'}}},
      plugins:{legend:{position:'top',labels:{boxWidth:10,padding:7,color:'#5a9a5a'}}}}});
}

/* ── Tab switching ── */
function tab(name,btn){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.tc').forEach(t=>t.classList.remove('active'));
  btn.classList.add('active');
  document.getElementById('tab-'+name).classList.add('active');
  Object.values(C).forEach(c=>c&&c.resize&&c.resize());
}

/* ── Interface load ── */
async function loadIfaces(){
  try{
    const d=await(await fetch('/api/interfaces')).json();
    const s=document.getElementById('iface'); s.innerHTML='';
    d.interfaces.forEach(i=>{const o=document.createElement('option');o.value=o.text=i;s.append(o);});
  }catch(e){}
}

/* ── Capture controls ── */
async function startCap(){
  const iface=document.getElementById('iface').value;
  await fetch('/api/start',{method:'POST',headers:{'Content-Type':'application/json'},
    body:JSON.stringify({interface:iface})});
  document.getElementById('startBtn').disabled=true;
  document.getElementById('stopBtn').disabled=false;
}
async function stopCap(){
  await fetch('/api/stop',{method:'POST'});
  document.getElementById('startBtn').disabled=false;
  document.getElementById('stopBtn').disabled=true;
  document.getElementById('dot').classList.remove('on');
  document.getElementById('stxt').textContent='OFFLINE';
}

/* ── Helpers ── */
function fmt(s){const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sec=Math.floor(s%60);
  return[h,m,sec].map(v=>String(v).padStart(2,'0')).join(':');}
function fmtBytes(b){if(b<1024)return b+' B';if(b<1048576)return(b/1024).toFixed(1)+' KB';return(b/1048576).toFixed(2)+' MB';}

/* ── All packets ── */
let allPkts=[];

/* ── Status poll ── */
async function pollStatus(){
  try{
    const d=await(await fetch('/api/status')).json();
    // Header
    const dot=document.getElementById('dot');
    dot.classList.toggle('on',d.active);
    document.getElementById('stxt').textContent=d.active?'LIVE_CAPTURE':'OFFLINE';
    document.getElementById('iflbl').textContent='IFACE: '+d.interface;
    document.getElementById('elbl').textContent=fmt(d.elapsed);
    // KPIs
    document.getElementById('kPkts').textContent=d.total_packets.toLocaleString();
    document.getElementById('kTp').innerHTML=d.avg_tp+' <span class="kpi-u">kbps</span>';
    document.getElementById('kRate').innerHTML=d.avg_rate+' <span class="kpi-u">p/s</span>';
    document.getElementById('kBytes').textContent=fmtBytes(d.total_bytes);
    const tot=d.encrypted+d.unencrypted||1;
    const pct=Math.round(d.encrypted/tot*100);
    document.getElementById('kEnc').innerHTML=pct+'<span class="kpi-u">%</span>';
    document.getElementById('kEncD').textContent=d.encrypted+' enc / '+d.unencrypted+' plain';
    document.getElementById('kAnm').textContent=d.anomaly_count;
    // Badge
    const badge=document.getElementById('abadge');
    d.anomaly_count>0?(badge.textContent=d.anomaly_count,badge.classList.remove('h')):badge.classList.add('h');
    // Timeline charts
    if(d.timeline&&d.timeline.length){
      const last=d.timeline[d.timeline.length-1];
      if(C.cTp&&last)push(C.cTp,last.t,last.k);
      if(C.cRate&&last)push(C.cRate,last.t,last.r);
    }
    // Protocol
    if(C.cProto&&d.protocols){const e=Object.entries(d.protocols);doughnut(C.cProto,e.map(x=>x[0]),e.map(x=>x[1]));}
    // Category
    if(C.cCat&&d.traffic_types){
      const cats=['Web','DNS','Streaming','General'];
      C.cCat.data.datasets[0].data=cats.map(c=>d.traffic_types[c]||0);C.cCat.update('none');
    }
    // Encryption
    if(C.cEnc){C.cEnc.data.datasets[0].data=[d.encrypted,d.unencrypted];C.cEnc.update('none');}
    // Top src/dst
    if(C.cSrc&&d.top_src)barH(C.cSrc,d.top_src.map(x=>x[0]),d.top_src.map(x=>x[1]));
    if(C.cDst&&d.top_dst)barH(C.cDst,d.top_dst.map(x=>x[0]),d.top_dst.map(x=>x[1]));
    // Ports
    if(C.cPorts&&d.top_ports){
      C.cPorts.data.labels=d.top_ports.map(x=>':'+x[0]);
      C.cPorts.data.datasets[0].data=d.top_ports.map(x=>x[1]);
      C.cPorts.update('none');
    }
    // Latency
    if(C.cLat){
      const ts=new Date().toLocaleTimeString('en',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});
      C.cLat.data.labels.push(ts);
      C.cLat.data.datasets[0].data.push(d.avg_edge);
      C.cLat.data.datasets[1].data.push(d.avg_cloud);
      if(C.cLat.data.labels.length>40){C.cLat.data.labels.shift();C.cLat.data.datasets.forEach(ds=>ds.data.shift());}
      C.cLat.update('none');
    }
    // 5G slices
    const sc=d.slice_counts||{};
    const embb=sc.eMBB||0,urllc=sc.URLLC||0,mmtc=sc.mMTC||0,tot2=embb+urllc+mmtc||1;
    document.getElementById('sE').textContent=embb.toLocaleString()+' packets';
    document.getElementById('sU').textContent=urllc.toLocaleString()+' packets';
    document.getElementById('sM').textContent=mmtc.toLocaleString()+' packets';
    document.getElementById('sEb').style.width=(embb/tot2*100).toFixed(1)+'%';
    document.getElementById('sUb').style.width=(urllc/tot2*100).toFixed(1)+'%';
    document.getElementById('sMb').style.width=(mmtc/tot2*100).toFixed(1)+'%';
    if(C.cSlice){C.cSlice.data.datasets[0].data=[embb,urllc,mmtc];C.cSlice.update('none');}
    // MEC
    if(C.cMEC){
      const ts2=new Date().toLocaleTimeString('en',{hour12:false,hour:'2-digit',minute:'2-digit',second:'2-digit'});
      C.cMEC.data.labels.push(ts2);
      C.cMEC.data.datasets[0].data.push(d.avg_edge);
      C.cMEC.data.datasets[1].data.push(d.avg_cloud);
      if(C.cMEC.data.labels.length>40){C.cMEC.data.labels.shift();C.cMEC.data.datasets.forEach(ds=>ds.data.shift());}
      C.cMEC.update('none');
    }
    if(d.avg_edge>0){
      document.getElementById('mEdge').textContent=d.avg_edge+' ms';
      document.getElementById('mCloud').textContent=d.avg_cloud+' ms';
      document.getElementById('mAdv').textContent=Math.round((1-d.avg_edge/d.avg_cloud)*100)+'%';
    }
  }catch(e){}
}

/* ── Packets poll ── */
async function pollPkts(){
  try{
    const d=await(await fetch('/api/packets?limit=200')).json();
    allPkts=d.packets||[]; filt();
  }catch(e){}
}
function filt(){
  const q=(document.getElementById('fi')?.value||'').toLowerCase();
  const pr=document.getElementById('fp')?.value||'';
  const cat=document.getElementById('fc')?.value||'';
  const rows=allPkts.filter(p=>{
    if(pr&&p.protocol!==pr)return false;
    if(cat&&p.category!==cat)return false;
    if(q&&!`${p.src_ip} ${p.dst_ip} ${p.protocol} ${p.src_port} ${p.dst_port} ${p.service}`.toLowerCase().includes(q))return false;
    return true;
  }).slice(0,100).map(p=>{
    const ecls=p.encrypted?'ey':'en';
    const elbl=p.encrypted?'[ENC]':'[CLR]';
    const ccls='c'+p.category[0].toLowerCase()+(p.category.slice(1)||'');
    const protcls=p.protocol==='TCP'?'pt':'pu';
    return`<tr>
      <td>${p.time}</td><td>${p.src_ip}</td><td>${p.dst_ip}</td>
      <td class="${protcls}">${p.protocol}</td>
      <td>${p.src_port}</td><td>${p.dst_port}</td>
      <td>${p.service}</td><td class="${ccls}">${p.category}</td>
      <td>${p.size}B</td><td class="${ecls}">${elbl}</td>
    </tr>`;
  }).join('');
  const tb=document.getElementById('ptbody');
  tb.innerHTML=rows||'<tr><td colspan="10" class="empty">&gt;&gt; AWAITING PACKETS...</td></tr>';
}

/* ── Anomalies poll ── */
async function pollAnm(){
  try{
    const d=await(await fetch('/api/anomalies')).json();
    const list=document.getElementById('alist');
    const anms=d.anomalies||[];
    if(!anms.length){list.innerHTML='<div class="empty">::  SYSTEM NOMINAL — NO ANOMALIES DETECTED  ::</div>';return;}
    list.innerHTML=anms.map(a=>{
      const cls=a.severity==='HIGH'?'':'  med';
      const scls=a.severity==='HIGH'?'sh':'sm';
      return`<div class="ai${cls}">
        <span class="at">${a.time}</span>
        <span class="asev ${scls}">${a.severity}</span>
        <div><div class="atype">&gt; ${a.type}</div><div class="adet">${a.detail}</div></div>
      </div>`;
    }).join('');
    const h=anms.filter(a=>a.severity==='HIGH').length;
    const m=anms.filter(a=>a.severity==='MEDIUM').length;
    if(C.cAnm){C.cAnm.data.datasets[0].data=[h,m];C.cAnm.update('none');}
  }catch(e){}
}

/* ── Boot ── */
window.addEventListener('DOMContentLoaded',()=>{
  loadIfaces(); initCharts();
  setInterval(pollStatus,1500);
  setInterval(pollPkts,2000);
  setInterval(pollAnm,3000);
  setTimeout(pollStatus,600);
  setTimeout(pollPkts,900);
});
</script>
</body>
</html>"""


if __name__=="__main__":
    print("\n" + "="*60)
    print("  5G NETWORK TRAFFIC ANALYZER  ")
    print("  http://127.0.0.1:5000")
    print("="*60 + "\n")
    app.run(host="0.0.0.0", port=5000, debug=False, threaded=True)
