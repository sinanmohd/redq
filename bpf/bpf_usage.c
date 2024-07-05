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
	__type(key, __u64);   // source mac address
	__type(value, __u64); // no of bytes
} ingress_ip4_usage_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u64);   // destination mac address
	__type(value, __u64); // no of bytes
} egress_ip4_usage_map SEC(".maps");

typedef enum {
	UPDATE_USAGE_INGRESS,
	UPDATE_USAGE_EGRESS,
} update_usage_t;

static __always_inline __u64 nchar6_to_u64(unsigned char bytes[6])
{
	union {
		char bytes[6];
		__u64 i;
	} ret;

	ret.i = 0;
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	ret.bytes[0] = bytes[5];
	ret.bytes[1] = bytes[4];
	ret.bytes[2] = bytes[3];
	ret.bytes[3] = bytes[2];
	ret.bytes[4] = bytes[1];
	ret.bytes[5] = bytes[0];
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	ret.bytes[0] = bytes[0];
	ret.bytes[1] = bytes[1];
	ret.bytes[2] = bytes[2];
	ret.bytes[3] = bytes[3];
	ret.bytes[4] = bytes[4];
	ret.bytes[5] = bytes[5];
#endif

	return ret.i;
}

static __always_inline int update_usage(void *map, struct __sk_buff *skb,
					update_usage_t traffic)
{
	__u64 mac, len, *usage;

	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = (void *)(long)skb->data;

	if ((void *) (eth + 1) > data_end)
		return TCX_PASS;

	if (skb->protocol != bpf_htons(ETH_P_IP) &&
	    skb->protocol != bpf_htons(ETH_P_IPV6)) {
		return TCX_PASS;
	}

	len = skb->len - sizeof(struct ethhdr);
	if (traffic == UPDATE_USAGE_INGRESS) {
		mac = nchar6_to_u64(eth->h_source);
	} else {
		mac = nchar6_to_u64(eth->h_dest);
	}

	usage = bpf_map_lookup_elem(map, &mac);
	if (!usage) {
		/* no entry in the map for this IP address yet. */
		bpf_map_update_elem(map, &mac, &len, BPF_ANY);
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
