"""E1 ARP Spoofing / MITM runner: P0 feasibility gate + full experiment.

Spec sections 2.1, 5, 7-13, 22, 35. Orchestrates the isolated e1_net lab
(victim / gateway / attacker) via docker exec. All activity is confined to the
private Docker network (scope section 0); targets are fixed by the topology.

Flow: prepare -> baseline -> feasibility gate -> controlled MITM -> HTTP/HTTPS
payload observation -> certificate validation -> regression -> evidence -> verdict.
"""

from __future__ import annotations

import subprocess
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from labs.common.evidence import start_run  # noqa: E402
from labs.common.result_schema import ExperimentReport, ScenarioResult, Verdict  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
COMPOSE = REPO / "labs" / "e1_arp" / "docker" / "docker-compose.e1.yml"
GATEWAY_IP = "10.77.0.2"
VICTIM_IP = "10.77.0.10"
ATTACKER_IP = "10.77.0.66"
TOKEN = "SECRET_TELEMETRY_TOKEN_12345"
ATTACKER_MODEL = "on same L2 network; can send crafted ARP; can enable IP forwarding"
TB = "TB-A (network trust)"


def run(cmd: list[str], timeout: int = 90) -> subprocess.CompletedProcess:
    # Force UTF-8 decoding: docker emits UTF-8 that the Windows locale codec
    # (cp950) cannot decode. errors='replace' keeps capture robust.
    return subprocess.run(
        cmd, capture_output=True, text=True, timeout=timeout,
        encoding="utf-8", errors="replace",
    )


def dexec(container: str, args: list[str], timeout: int = 60) -> subprocess.CompletedProcess:
    return run(["docker", "exec", container, *args], timeout=timeout)


def dexec_d(container: str, args: list[str]) -> None:
    run(["docker", "exec", "-d", container, *args], timeout=30)


def compose(*args: str, timeout: int = 600) -> subprocess.CompletedProcess:
    return run(["docker", "compose", "-f", str(COMPOSE), *args], timeout=timeout)


def mk(sid, expected, actual, control, ok, ev, detail) -> ScenarioResult:
    return ScenarioResult(
        experiment_id="e1", scenario_id=sid, attacker_model=ATTACKER_MODEL,
        trust_boundary=TB, expected_result=expected, actual_result=actual,
        security_control=control, evidence_location=ev,
        verdict=Verdict.PASS if ok else Verdict.FAIL, detail=detail,
    )


def arp_line(container: str, ip: str) -> str:
    out = dexec(container, ["arp", "-n", ip]).stdout
    for line in out.splitlines():
        if ip in line:
            return line.strip()
    return out.strip()


def main() -> int:
    run_ev = start_run("e1")
    ev = str(run_ev.dir)
    results: list[ScenarioResult] = []
    feasibility_ok = True

    print("[e1] building + starting isolated lab ...", flush=True)
    b = compose("up", "-d", "--build")
    run_ev.write_text("compose_up.log", b.stdout + "\n" + b.stderr)
    if b.returncode != 0:
        print(b.stderr[-1500:])
        results.append(mk("E1-ENV", "lab starts", "compose up failed",
                          "docker", False, ev, {"stderr": b.stderr[-1000:]}))
        ExperimentReport("e1", run_ev.run_id, tuple(results)).write(
            run_ev.path("result.json"))
        return 1

    # Wait for gateway HTTP to answer from the victim.
    deadline = time.time() + 60
    gw_up = False
    while time.time() < deadline:
        r = dexec("e1_victim", ["curl", "-s", "-m", "3", f"http://{GATEWAY_IP}/"])
        if TOKEN in r.stdout:
            gw_up = True
            break
        time.sleep(2)
    if not gw_up:
        results.append(mk("E1-ENV", "gateway reachable", "gateway not reachable",
                          "docker", False, ev, {}))
        ExperimentReport("e1", run_ev.run_id, tuple(results)).write(
            run_ev.path("result.json"))
        return 1

    # ---------------- Baseline (pre-attack) ----------------
    dexec("e1_victim", ["ping", "-c", "2", GATEWAY_IP])
    baseline_arp = arp_line("e1_victim", GATEWAY_IP)
    run_ev.write_text("E1-01_baseline_arp.txt", baseline_arp + "\n")

    base_resp = dexec("e1_victim", ["curl", "-s", f"http://{GATEWAY_IP}/"]).stdout
    run_ev.write_text("E1-03_baseline_http_response.txt", base_resp)

    # Attacker MAC + IP forwarding (provisioned at creation via compose sysctl).
    att_mac = dexec("e1_attacker", ["cat", "/sys/class/net/eth0/address"]).stdout.strip()
    ipf = dexec("e1_attacker", ["cat", "/proc/sys/net/ipv4/ip_forward"]).stdout.strip()

    # ---------------- Start ARP poisoning ----------------
    dexec_d("e1_attacker", ["sh", "-c",
            "python /lab/arp_spoof.py >/lab/arp_spoof.log 2>&1"])
    time.sleep(6)  # let poisoning take effect

    poisoned_arp = arp_line("e1_victim", GATEWAY_IP)
    run_ev.write_text("E1-02_poisoned_arp.txt", poisoned_arp + "\n")

    # ---------------- DoS contrast: poisoned BUT not forwarding (spec 7.2) ----
    # Drop forwarded victim packets -> traffic breaks -> disruption/DoS, which
    # must NOT be claimed as MITM success.
    dexec("e1_attacker", ["iptables", "-I", "FORWARD", "1", "-s", VICTIM_IP, "-j", "DROP"])
    dos_resp = dexec("e1_victim", ["curl", "-s", "-m", "4",
                                   f"http://{GATEWAY_IP}/telemetry"]).stdout
    run_ev.write_text("E1-DOS_http_response.txt",
                      f"(empty = disruption/DoS)\n{dos_resp}\n")
    dexec("e1_attacker", ["iptables", "-F", "FORWARD"])  # restore forwarding
    time.sleep(1)

    # ---------------- True MITM: poisoned AND forwarding ----------------
    dexec_d("e1_attacker", ["sh", "-c",
            f"tcpdump -i eth0 -w /lab/mitm_http.pcap host {VICTIM_IP} and port 80 "
            f">/lab/tcpdump_http.log 2>&1"])
    time.sleep(1)
    mitm_resp = dexec("e1_victim", ["curl", "-s", "-m", "5",
                                    f"http://{GATEWAY_IP}/telemetry"]).stdout
    run_ev.write_text("E1-05_mitm_http_response.txt", mitm_resp)
    time.sleep(2)
    dexec("e1_attacker", ["pkill", "tcpdump"])
    time.sleep(1)

    pcap_read = dexec("e1_attacker", ["sh", "-c",
                      "tcpdump -r /lab/mitm_http.pcap -nn -c 50 -A 2>/dev/null"]).stdout
    run_ev.write_text("E1-04_mitm_http_pcap.txt", pcap_read)

    # ---------------- Feasibility gate conditions ----------------
    victim_net = dexec("e1_victim", ["sh", "-c", "ip -o -4 addr show eth0"]).stdout.strip()
    same_l2 = all(ip.rsplit(".", 1)[0] == "10.77.0"
                  for ip in (GATEWAY_IP, VICTIM_IP, ATTACKER_IP))
    arp_visible = GATEWAY_IP in baseline_arp and ":" in baseline_arp
    mapping_changed = (att_mac and att_mac in poisoned_arp
                       and poisoned_arp != baseline_arp)
    ip_fwd = ipf == "1"
    traffic_continues = TOKEN in mitm_resp
    pcap_available = (VICTIM_IP in pcap_read) and len(pcap_read.strip()) > 0

    gate = {
        "SAME_L2_DOMAIN": same_l2,
        "ARP_TABLE_VISIBLE": arp_visible,
        "ARP_MAPPING_CAN_CHANGE": bool(mapping_changed),
        "ATTACKER_IP_FORWARDING": ip_fwd,
        "TRAFFIC_CONTINUES_THROUGH_ATTACKER": traffic_continues,
        "PCAP_EVIDENCE_AVAILABLE": pcap_available,
    }
    run_ev.write_json("feasibility_gate.json", gate)
    feasibility_ok = all(gate.values())

    results.append(mk(
        "E1-FEASIBILITY-GATE",
        "all six feasibility conditions = YES",
        " ".join(f"{k}={'YES' if v else 'NO'}" for k, v in gate.items()),
        "isolated L2 lab", feasibility_ok, ev, gate,
    ))
    results.append(mk(
        "E1-MITM-PATH",
        "victim ARP(gateway) -> attacker MAC AND forwarding on",
        f"baseline[{baseline_arp}] poisoned[{poisoned_arp}] ip_forward={ipf}",
        "n/a (attack demonstration)",
        bool(mapping_changed) and ip_fwd and traffic_continues, ev,
        {"attacker_mac": att_mac},
    ))
    # DoS contrast (spec 7.2): poisoned but not forwarding => traffic broken.
    dos_broke = TOKEN not in dos_resp
    results.append(mk(
        "E1-DOS-WITHOUT-FORWARDING",
        "poisoned + forwarding dropped => traffic broken (DoS, not MITM)",
        f"traffic_broken={dos_broke} (response empty={dos_resp.strip()==''})",
        "n/a (demonstrates DoS vs MITM distinction)", dos_broke, ev, {},
    ))

    # ---------------- HTTP payload exposure (confidentiality) ----------------
    http_token_seen = TOKEN in pcap_read
    results.append(mk(
        "E1-HTTP-PAYLOAD-EXPOSED",
        "plaintext token visible in attacker PCAP over HTTP",
        f"token_in_http_pcap={http_token_seen}",
        "none (plaintext HTTP)", http_token_seen, ev,
        {"evidence": "E1-04_mitm_http_pcap.txt / E1-05"},
    ))

    # ---------------- HTTPS under MITM (TLS protects payload) ----------------
    # Copy gateway cert to victim for proper validation.
    cert_host = run_ev.path("server.crt")
    run(["docker", "cp", "e1_gateway:/lab/server.crt", str(cert_host)])
    run(["docker", "cp", str(cert_host), "e1_victim:/lab/server.crt"])

    dexec_d("e1_attacker", ["sh", "-c",
            f"tcpdump -i eth0 -w /lab/mitm_https.pcap host {VICTIM_IP} and port 443 "
            f">/lab/tcpdump_https.log 2>&1"])
    time.sleep(1)
    https_ok = dexec("e1_victim", ["sh", "-c",
                     f"curl -s -m 6 --cacert /lab/server.crt "
                     f"--resolve gateway:443:{GATEWAY_IP} https://gateway/telemetry"])
    run_ev.write_text("E1-06_https_response_validated.txt",
                      https_ok.stdout + "\nEXIT=" + str(https_ok.returncode))
    time.sleep(2)
    dexec("e1_attacker", ["pkill", "tcpdump"])
    time.sleep(1)
    https_pcap = dexec("e1_attacker", ["sh", "-c",
                       "tcpdump -r /lab/mitm_https.pcap -nn -c 80 -A 2>/dev/null"]).stdout
    run_ev.write_text("E1-06_mitm_https_pcap.txt", https_pcap)

    https_payload_protected = (TOKEN not in https_pcap) and (TOKEN in https_ok.stdout)
    results.append(mk(
        "E1-HTTPS-PAYLOAD-PROTECTED",
        "token NOT in HTTPS PCAP but valid response received (TLS protects payload)",
        f"token_in_https_pcap={TOKEN in https_pcap} "
        f"valid_response={TOKEN in https_ok.stdout}",
        "[I] TLS", https_payload_protected, ev, {},
    ))

    # ---------------- Certificate validation enforced ----------------
    # With correct CA -> success; with default trust (no CA) -> must FAIL
    # (proves validation is ON; verify=false is NOT used).
    noca = dexec("e1_victim", ["sh", "-c",
                 f"curl -s -o /dev/null -w '%{{http_code}}' -m 6 "
                 f"--resolve gateway:443:{GATEWAY_IP} https://gateway/ ; echo \" rc=$?\""])
    run_ev.write_text("E1-07_cert_validation.txt",
                      f"with_ca_exit={https_ok.returncode}\n"
                      f"without_ca_result={noca.stdout.strip()}\n")
    cert_validation = (https_ok.returncode == 0) and ("rc=0" not in noca.stdout)
    results.append(mk(
        "E1-TLS-CERT-VALIDATION",
        "valid CA connects; untrusted/self-signed rejected (no verify=false)",
        f"with_ca_exit={https_ok.returncode} without_ca='{noca.stdout.strip()}'",
        "[I] Certificate validation", cert_validation, ev, {},
    ))

    # ---------------- Stop attack + regression ----------------
    dexec("e1_attacker", ["pkill", "-f", "arp_spoof.py"])
    time.sleep(4)
    restored_arp = arp_line("e1_victim", GATEWAY_IP)
    run_ev.write_text("E1-08_restored_arp.txt", restored_arp + "\n")
    reg_http = dexec("e1_victim", ["curl", "-s", "-m", "5",
                                   f"http://{GATEWAY_IP}/"]).stdout
    reg_https = dexec("e1_victim", ["sh", "-c",
                      f"curl -s -m 6 --cacert /lab/server.crt "
                      f"--resolve gateway:443:{GATEWAY_IP} https://gateway/"])
    normal_ok = (TOKEN in reg_http) and (TOKEN in reg_https.stdout) \
        and (att_mac not in restored_arp)
    results.append(mk(
        "E1-REGRESSION",
        "normal device traffic + valid TLS pass after restore (not 'block everything')",
        f"http_ok={TOKEN in reg_http} tls_ok={TOKEN in reg_https.stdout} "
        f"arp_restored={att_mac not in restored_arp}",
        "[I] TLS + restored network", normal_ok, ev, {"restored_arp": restored_arp},
    ))

    report = ExperimentReport("e1", run_ev.run_id, tuple(results))
    report.write(run_ev.path("result.json"))

    print(f"=== E1 ARP/MITM | run {run_ev.run_id} | "
          f"feasibility={'PASS' if feasibility_ok else 'FAIL'} | "
          f"verdict {report.verdict.value} ===")
    for s in results:
        print(f"  [{s.verdict.value:4}] {s.scenario_id}: {s.actual_result}")
    print(f"Evidence: {run_ev.dir}")

    if "--down" in sys.argv:
        compose("down")
    return 0 if report.verdict == Verdict.PASS else 1


if __name__ == "__main__":
    raise SystemExit(main())
