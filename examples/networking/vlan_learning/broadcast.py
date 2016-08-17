#!/usr/bin/env python
# Copyright (c) PLUMgrid, Inc.
# Licensed under the Apache License, Version 2.0 (the "License")

from bcc import BPF
from builtins import input
from pyroute2 import IPRoute, NetNS, IPDB, NSPopen
from time import sleep
from simulation import Simulation
from pyroute2.netlink.rtnl import TC_H_CLSACT
from ctypes import c_int
import sys

num_clients = 2

ipr = IPRoute()
ipdb = IPDB(nl=ipr)
parent = TC_H_CLSACT

broadcast  = BPF(src_file="broadcast.c", debug = 0)
egress     = broadcast.load_func("egress_replication", BPF.SCHED_CLS)
ingress    = broadcast.load_func("incr_counter",BPF.SCHED_CLS)
response   = broadcast.load_func("ingress_response",BPF.SCHED_CLS)
ports      = broadcast.get_table("ports")

class DavideSimulation(Simulation):
    def __init__(self, ipdb):
        super(DavideSimulation, self).__init__(ipdb)

    def start(self):

        in_interface = self.ipdb.create(ifname="clientA", kind="veth", peer="clientB").up().commit()
        self.ipdb.interfaces.clientB.up().commit()

        v_bpf = self.ipdb.interfaces["clientB"]

        ipr.tc("add", "clsact", v_bpf["index"])

        # add ingress/egress clsact
        ipr.tc("add-filter", "bpf", v_bpf["index"], ":1", fd=ingress.fd, name=ingress.name, parent="ffff:fff2", classid=1, direct_action = True)
        ipr.tc("add-filter", "bpf", v_bpf["index"], ":1", fd=egress.fd, name=egress.name, parent="ffff:fff3", classid=1, direct_action= True)
        mac = "02:00:00:00:00:01"
        self._create_ns("client0", in_ifc = in_interface, ipaddr="172.16.1.100/24", macaddr=mac)

        ports[c_int(0)] = c_int(v_bpf["index"])
        receivers = []
        for i in range(0, num_clients):
            receivers.append(self._create_ns("worker%d" % i, ipaddr="172.16.1.%d/24" % (i+1)))

        port_count = 1
        for receiver in receivers:
            ipr.tc("add", "clsact", receiver[1].index)
            ipr.tc("add-filter", "bpf", receiver[1].index, ":1", fd=response.fd, name=response.name, parent="ffff:fff2", classid=1, direct_action = True)
            print(receiver[1].index)
            ports[c_int(port_count)] = c_int(receiver[1].index)
            port_count = port_count + 1

        #with self.ipdb.create(ifname="bridge", kind="bridge") as br:
            #br.add_port("worker0a")
            #br.add_port("worker1a")
            #br.add_port("clientB")
            #br.up()

try:
    sim = DavideSimulation(ipdb)
    sim.start()
    #sleep(10)
    input("Press enter to exit: ")
#    stats_collect = {}
#    for key, leaf in ingress.items():
#        stats_collect[key.value] = [leaf.tx_pkts, leaf.tx_bytes, 0, 0]
#    for key, leaf in egress.items():
#        x = stats_collect.get(key.value, [0, 0, 0, 0])
#        x[2] = leaf.tx_pkts
#        x[3] = leaf.tx_bytes
#    for k, v in stats_collect.items():
#        print("mac %.12x rx pkts = %u, rx bytes = %u" % (k, v[0], v[1]))
#        print("                 tx pkts = %u, tx bytes = %u" % (v[2], v[3]))
finally:
    #for i in ipr.link_lookup(ifname="bridge"):
        #ipr.link('set', index=i, state='down')
        #ipr.link("delete", index=i)     
    if "sim" in locals():
        sim.release()
    ipdb.release()
