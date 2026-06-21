# int_xd_setup.py
#
# 3-hop loopback chain on one Tofino. Xena still only touches 7/0 (in) and
# 8/0 (out) - the chain lives entirely on spare front-panel ports cabled
# back-to-back: 10/0 <-> 11/0 and 12/0 <-> 13/0.
#
# FILL IN: P_XENA_IN, P_LOOP1_OUT, P_LOOP1_IN, P_LOOP2_OUT, P_LOOP2_IN, P_XENA_OUT with what 'pm show' shows for your cabling. The loopback ports can be any spare front-panel ports.
# FILL IN: The collector_mac and collector_ip in the tb_int_xd_reporting entries with the MAC and IP of your collector server.

# Fill in the following ports with what this shows bfshell -> ucli -> pm -> show
P_XENA_IN   = None   # 7/0  - Xena Port0 -> switch (hop 1 in) [known]
P_LOOP1_OUT = None  # 10/0 - hop 1 out  -> DAC loopback -> P_LOOP1_IN
P_LOOP1_IN  = None  # 11/0 - hop 2 in
P_LOOP2_OUT = None  # 12/0 - hop 2 out  -> DAC loopback -> P_LOOP2_IN
P_LOOP2_IN  = None  # 13/0 - hop 3 in
P_XENA_OUT  = None   # 8/0  - hop 3 out  -> Xena Port1 [known, unchanged]

assert None not in (P_LOOP1_OUT, P_LOOP1_IN, P_LOOP2_OUT, P_LOOP2_IN), \
    "fill in the loopback dev_port numbers from `pm show` before running this"

# --- hop forwarding: ingress_port -> egress_port, fixed by cabling ---------
bfrt.int_xd_tofino.pipe.SwitchIngress.tb_hop_fwd.add_with_forward(
    ingress_port=P_XENA_IN, port=P_LOOP1_OUT)        # hop 1: Xena -> loop
bfrt.int_xd_tofino.pipe.SwitchIngress.tb_hop_fwd.add_with_forward(
    ingress_port=P_LOOP1_IN, port=P_LOOP2_OUT)        # hop 2: loop -> loop
bfrt.int_xd_tofino.pipe.SwitchIngress.tb_hop_fwd.add_with_forward(
    ingress_port=P_LOOP2_IN, port=P_XENA_OUT)         # hop 3: loop -> Xena

# --- XD watchlist: ONE entry, fires identically on all 3 passes since the --
# --- flow's IP header is never rewritten between hops ----------------------
bfrt.int_xd_tofino.pipe.SwitchIngress.tb_int_xd_watchlist.add_with_set_xd_clone(
    src_addr=0x0A000001, src_addr_mask=0xFFFFFFFF,
    dst_addr=0x0A000002, dst_addr_mask=0xFFFFFFFF,
    l4_src=0, l4_src_mask=0,
    l4_dst=0, l4_dst_mask=0,
    MATCH_PRIORITY=1, session_id=2)

# --- mirror session -> collector port, unchanged ---------------------------
bfrt.mirror.cfg.add_with_normal(sid=2, session_enable=True, direction="BOTH",
    ucast_egress_port=60, ucast_egress_port_valid=1, max_pkt_len=200)

# --- XD reporting: one entry PER HOP, keyed on which port the packet -------
# --- ingressed on for that pass. Distinct switch_id/dp_mac/dp_ip per hop. --
bfrt.int_xd_tofino.pipe.SwitchEgress.tb_int_xd_reporting.add_with_send_xd_report(
    ingress_port=P_XENA_IN,
    dp_mac=0xF661C06A0001, dp_ip=0x0A000001,
    collector_mac=0x54EE75A550F8, collector_ip=0x0A0000FE,
    collector_port=6001, switch_id=1)

bfrt.int_xd_tofino.pipe.SwitchEgress.tb_int_xd_reporting.add_with_send_xd_report(
    ingress_port=P_LOOP1_IN,
    dp_mac=0xF661C06A0002, dp_ip=0x0A000002,
    collector_mac=0x54EE75A550F8, collector_ip=0x0A0000FE,
    collector_port=6001, switch_id=2)

bfrt.int_xd_tofino.pipe.SwitchEgress.tb_int_xd_reporting.add_with_send_xd_report(
    ingress_port=P_LOOP2_IN,
    dp_mac=0xF661C06A0003, dp_ip=0x0A000003,
    collector_mac=0x54EE75A550F8, collector_ip=0x0A0000FE,
    collector_port=6001, switch_id=3)

bfrt.int_xd_tofino.pipe.SwitchIngress.tb_hop_fwd.dump(table=True)
bfrt.int_xd_tofino.pipe.SwitchIngress.tb_int_xd_watchlist.dump(table=True)
bfrt.mirror.cfg.dump(table=True)
bfrt.int_xd_tofino.pipe.SwitchEgress.tb_int_xd_reporting.dump(table=True)

print("INT-XD 3-hop setup complete.")
