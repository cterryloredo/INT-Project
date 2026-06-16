# INT-Project — Data Plane Programming with INT-XD

This project extends the [GÉANT int-platforms](https://github.com/GEANT-DataPlaneProgramming/int-platforms) repository with **INT-XD (Export Data)** support on the BMv2/Mininet platform.

## What This Project Does

The base GÉANT repository implements **INT-MD (Embed Data)** — telemetry data is embedded into packets as they traverse the network and stripped at the sink node.

This project adds **INT-XD (Export Data)** — each switch independently clones matching packets and exports telemetry reports directly to the collector, without modifying the original packet.

Both modes write to InfluxDB v2 and are visualized in Grafana, tagged with `int_mode=MD` or `int_mode=XD`.

---

## Architecture

```
Mininet (inside Docker p4app container)
    H1 (10.0.1.1) --- S1 --- S2 --- S3 --- H2 (10.0.2.2)
                       |      |      |
                   XD clone  XD clone  XD clone
                       |      |      |
                    veth_dp_0  veth_dp_1  veth_dp_2
                       |      |      |
                    int_collection bridge (ns_int namespace)
                              |
                        INT Collector (port 6000 MD, port 6001 XD)
                              |
                         socat (18086 -> 172.17.0.1:8086)
                              |
                         InfluxDB v2 (host machine)
                              |
                           Grafana
```

---

## Requirements

- Docker and docker-compose
- The p4app Docker image (pulled automatically by `start_int1.0.sh`)
- Grafana and InfluxDB v2 (started via docker-compose)

---

## Setup

### 1 — Clone the repository

```bash
git clone https://github.com/cterryloredo/INT-Project.git
cd INT-Project
```

### 2 — Start the analytics stack

```bash
cd analytics
docker-compose up -d
```

This starts:
- **InfluxDB v2** on port `8086`
- **Grafana** on port `3000`

Default credentials:
- InfluxDB: org=`int-project`, bucket=`int_telemetry`, token=`my-super-secret-token`
- Grafana: `admin / admin`

### 3 — Start Mininet

```bash
cd platforms/bmv2-mininet
./start_int1.0.sh
```

This will:
- Compile the P4 program inside Docker
- Start the Mininet topology (3 switches, 3 hosts)
- Configure all INT tables automatically
- Start the INT collector

### 4 — Generate traffic

From the Mininet CLI:

```
mininet> h1 python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('10.0.1.1', 4000)); s.sendto(b'test', ('10.0.2.2', 5000))"
```

Any UDP or TCP packet from `10.0.1.1` to `10.0.2.2` triggers XD reporting on all three switches.

### Seeing both INT modes (MD + XD) at the same time

The data plane gives **INT-XD precedence per flow**: `int.p4` runs `Int_xd_config` before the MD source (`if (xd_clone == 0) Int_source.apply()`), so any flow matching the XD watchlist is exported by XD and is **never** MD-sourced. The two modes therefore run on **different flows**, not the same packets:

| Mode | Flow | Mechanism |
|---|---|---|
| INT-XD | H1 → H2 (`10.0.1.1 → 10.0.2.2`) | XD watchlist on every switch; each switch exports its own per-hop report |
| INT-MD | H2 → H1 (`10.0.2.2 → 10.0.1.1`) | MD source on S2 (`commands2.txt`); sink at S1 emits one end-to-end report |

Generate traffic in **both directions** from the Mininet CLI using `sender.py`
(`int.p4app/utils/sender.py`, available inside the container at `/tmp/utils/sender.py`;
args: `<dst> <count> [src]`, paced at ~125 pps):

```
# INT-XD: H1 -> H2
mininet> h1 python3 /tmp/utils/sender.py 10.0.2.2 500 10.0.1.1

# INT-MD: H2 -> H1
mininet> h2 python3 /tmp/utils/sender.py 10.0.1.1 500 10.0.2.2
```

In Grafana, the **"Reports received by mode"** panel then shows both `int_mode=MD` and `int_mode=XD` together; the XD panels populate per-switch and the MD panel shows the end-to-end path delay.

> Traffic in only one direction shows only one mode. Keep the rate under ~500 pps (collector ceiling).

### 5 — View data in Grafana

Open `http://localhost:3000` in your browser.

Add InfluxDB v2 as a data source:
- Query Language: **Flux**
- URL: `http://[HOST_MACHINE_DOCKER_BRIDGE_IP usually: 172.17.0.1]:8086`
- Organisation: `int-project`
- Token: `my-super-secret-token`
- Default Bucket: `int_telemetry`

---

## Project Structure

```
INT-Project/
├── analytics/
│   └── docker-compose.yml          # InfluxDB v2 + Grafana
├── p4src/
│   └── int_v1.0/
│       ├── int.p4                  # Main P4 program (modified)
│       └── include/
│           ├── headers.p4          # Modified: added xd_clone flag
│           ├── int_source.p4       # Modified: moved ingress metadata capture
│           ├── int_sink.p4         # Unchanged
│           └── int_xd.p4           # New: INT-XD ingress + egress controls
└── platforms/
    └── bmv2-mininet/
        └── int.p4app/
            ├── commands/
            │   ├── commands1.txt   # S1 table entries (modified: XD entries added)
            │   ├── commands2.txt   # S2 table entries (modified: XD entries added)
            │   └── commands3.txt   # S3 table entries (modified: XD entries added)
            ├── src/
            │   └── networking.py   # Modified: socat to local InfluxDB, XD port
            └── utils/
                └── int_collector_influx.py  # Modified: InfluxDB v2, XD parser
```

---

## INT-XD Flow

1. UDP/TCP packet from H1 (`10.0.1.1`) to H2 (`10.0.2.2`) enters S1 ingress
2. `tb_int_xd_watchlist` matches — `clone3` creates an I2E clone (mirror session 2)
3. Clone goes through egress — `Int_xd_report` builds a telemetry report
4. Report sent via `veth_dp_0` to the INT collector on port `6001`
5. Same happens independently on S2 and S3
6. Collector parses each report and writes to InfluxDB v2 with `int_mode=XD`

---

## Key Differences from GÉANT Base

| | GÉANT Base | This Project |
|---|---|---|
| INT mode | INT-MD only | INT-MD + INT-XD |
| Packet modification | Yes (INT headers embedded) | XD: No modification |
| Reports per packet | 1 (from sink) | XD: 3 (one per switch) |
| Analytics backend | InfluxDB v1 | InfluxDB v2 |
| Query language | InfluxQL | Flux |
| Collector | Single UDP listener | Two threaded listeners (MD+XD) |

---

## Troubleshooting

**Collector not starting:**
```bash
docker exec int python3 /tmp/utils/int_collector_influx.py -i 6000 -x 6001 -H 192.168.0.1:18086 -d 1
```

**No data in InfluxDB:**
```bash
docker exec influxdb influx query 'from(bucket:"int_telemetry") |> range(start: -5m) |> limit(n:5)'
```

**Check XD tables loaded:**
```
mininet> sh echo "table_dump tb_int_xd_watchlist" | simple_switch_CLI --thrift-port 22222
```

**Check mirror sessions:**
```
mininet> sh echo "mirroring_get 2" | simple_switch_CLI --thrift-port 22222
```

**Verify XD packets on collection interface:**
```
mininet> sh tcpdump -i veth_dp_0 -nn &
mininet> h1 python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(('10.0.1.1', 4000)); s.sendto(b'test', ('10.0.2.2', 5000))"
```

---

## Collaborative Workflow

```bash
# Before starting work
git checkout master
git pull origin master

# Create a branch for your work
git checkout -b feature/your-feature

# Make changes, commit, push
git add .
git commit -m "description of change"
git push origin feature/your-feature
```

Then open a Pull Request on GitHub to merge into master.
