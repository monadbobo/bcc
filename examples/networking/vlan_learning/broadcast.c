// Copyright (c) PLUMgrid, Inc.
// Licensed under the Apache License, Version 2.0 (the "License")

#include <bcc/proto.h>

#define NUM_PORTS 3

struct port {
  int ifindex;
};

BPF_TABLE("hash", int, struct port, ports, NUM_PORTS);

struct mac_key {
  u64 mac;
};

struct ifindex_info {
  u32 ifindex;
};

BPF_TABLE("hash", struct mac_key, struct ifindex_info, bridge, 4096);

int ingress_response(struct __sk_buff *skb) {
  int dst_index = 0;
  struct port *pport = 0;
  u8 *cursor = 0;
  struct ifindex_info src_ifindex;
  struct ifindex_info *dst_ifindex = 0;
  struct mac_key src_mac;

  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  bpf_trace_printk("\n");
  bpf_trace_printk("RECEIVER: GOT packet on port = %d\n", skb->ifindex);

  src_mac.mac = ethernet->src;
  src_ifindex.ifindex = skb->ifindex;

  dst_ifindex = bridge.lookup_or_init(&src_mac, &src_ifindex);
  pport = ports.lookup(&dst_index);
  if (pport) {
      bpf_trace_printk("RECEIVER: SEND packet to dst_port = %d\n", pport->ifindex);
      bpf_clone_redirect(skb, pport->ifindex, 0);
      return 2;
  }
  return 2;
}


int egress_replication(struct __sk_buff *skb) {
  u8 *cursor = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  //bpf_trace_printk("SENDER Packet egress ifindex=%d\n", skb->ifindex);
  return 0;
}

int incr_counter(struct __sk_buff *skb) {
  u8 *cursor = 0;
  int dst_index = 1;
  struct port *pport = 0;
  struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));
  struct mac_key dst_mac;
  struct ifindex_info *dst_ifindex = 0;

  dst_mac.mac = ethernet->dst;
  dst_ifindex = bridge.lookup(&dst_mac);


  if (dst_ifindex) {
      bpf_trace_printk("SENDER ingress: FOUND HOST send to port %d\n",dst_ifindex->ifindex);
      bpf_clone_redirect(skb, dst_ifindex->ifindex, 0);
      return 2;
  } else {
      bpf_trace_printk("SENDER ingress: START replication\n");
      pport = ports.lookup(&dst_index);
      if (!pport) 
          goto exit;
      bpf_trace_printk("SENDER ingress: sending to dst_port = %d\n", pport->ifindex);
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      pport = ports.lookup(&dst_index);
      if (!pport) 
          goto exit;
      bpf_trace_printk("SENDER ingress: sending to dst_port = %d\n", pport->ifindex);
      bpf_clone_redirect(skb, pport->ifindex, 0);
      dst_index++;
      pport = ports.lookup(&dst_index);
      if (pport)
          bpf_trace_printk("SHOULD NOT COME HERE\n");
exit:
      bpf_trace_printk("\n");
      return 2;
  }
}
