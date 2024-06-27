#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAX_MAP_ENTRIES 4096

char __license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32);   // source IPv4 address
	__type(value, __u64); // no of bytes
} ingress_ip4_usage_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u32);   // destination IPv4 address
	__type(value, __u64); // no of bytes
} egress_ip4_usage_map SEC(".maps");

typedef enum {
	UPDATE_USAGE_INGRESS,
	UPDATE_USAGE_EGRESS,
} update_usage_t;

static __always_inline int update_usage(void *map, struct __sk_buff *skb,
					update_usage_t traffic)
{
	__u32 ip4;
	__u64 len, *usage;

	void *data_end = (void *)(long)skb->data_end;
	void *data = (void *)(long)skb->data;
	struct iphdr *ip = data + sizeof(struct ethhdr);

	if (skb->protocol != bpf_htons(ETH_P_IP))
		return TCX_PASS;
	else if ((void *)(ip + 1) > data_end)
		return TCX_PASS;

	if (traffic == UPDATE_USAGE_INGRESS)
		ip4 = ip->saddr;
	else
		ip4 = ip->daddr;
	len = skb->len - sizeof(struct ethhdr);

	usage = bpf_map_lookup_elem(map, &ip4);
	if (!usage) {
		/* no entry in the map for this IP address yet. */
		bpf_map_update_elem(map, &ip4, &len, BPF_ANY);
	} else {
		__sync_fetch_and_add(usage, len);
	}

	return TCX_PASS;
}

SEC("tc")
int ingress_func(struct __sk_buff *skb)
{
	return update_usage(&ingress_ip4_usage_map, skb, UPDATE_USAGE_INGRESS);
}

SEC("tc")
int egress__func(struct __sk_buff *skb)
{
	return update_usage(&egress_ip4_usage_map, skb, UPDATE_USAGE_EGRESS);
}
