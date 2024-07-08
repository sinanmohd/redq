#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#define MAX_MAP_ENTRIES 4096

char __license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_MAP_ENTRIES);
	__type(key, __u64);  // blocked mac address
	// i just like her for the o(1) key lookup
	// we don't care about the value
	__type(value, __u16); 
} mac_blacklist_map SEC(".maps");

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

static __always_inline int mac_src_parse(struct xdp_md *ctx, __u64 *mac)
{
	__u64 len, *usage;

	void *data_end = (void *)(long)ctx->data_end;
	struct ethhdr *eth = (void *)(long)ctx->data;

	if ((void *) (eth + 1) > data_end)
		return -1;

	if (eth->h_proto != bpf_htons(ETH_P_IP) &&
	    eth->h_proto != bpf_htons(ETH_P_IPV6)) {
		return -1;
	}

	*mac = nchar6_to_u64(eth->h_source);
	return 0;
}

SEC("xdp")
int mac_filter(struct xdp_md *ctx)
{
	__u64 mac;
	int ret, *blocked;

	ret = mac_src_parse(ctx, &mac);
	if (ret < 0)
		return XDP_PASS;

	blocked = bpf_map_lookup_elem(&mac_blacklist_map, &mac);
	if (blocked)
		return XDP_DROP;

	return XDP_PASS;
}
