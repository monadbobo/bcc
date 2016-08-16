// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

#include <bcc/proto.h>

#define NUM_PORTS 2

struct config {
  int ifindex;
};

BPF_TABLE("hash", int, struct config, conf, NUM_PORTS);

struct ifindex_leaf_t {
  int out_ifindex;
  u64 tx_pkts;
  u64 tx_bytes;
};

// replicate packets based on number of ports
BPF_TABLE("hash", int, struct ifindex_leaf_t, egress, 4096);

int egress_replication(struct __sk_buff *skb) {
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  //bpf_trace_printk("Packet egress ifindex=%d\n", skb->ifindex);
  bpf_trace_printk("\n");
  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
  switch (ip->nextp) {
    
    case 0x01:
      bpf_trace_printk("Egress Dropping ICMP packets\n");
      return 2;
  }
  return 0;
}

int incr_counter(struct __sk_buff *skb) {
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));
  bpf_trace_printk("\n");
  switch (ip->nextp) {

    case 0x01:
      bpf_trace_printk("Ingress ICMP packets\n");
      return 0;
  }

  return 0;
}

