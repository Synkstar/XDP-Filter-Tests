#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/icmpv6.h>
#include <linux/in.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>
#include <linux/bpf.h>
#include <linux/bpf_common.h>
#include <linux/types.h>

#include <bpf_helpers.h>
#include "csum.h"

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#ifndef htons
#define htons(x) ((__be16)___constant_swab16((x)))
#endif

#ifndef ntohs
#define ntohs(x) ((__be16)___constant_swab16((x)))
#endif

#ifndef htonl
#define htonl(x) ((__be32)___constant_swab32((x)))
#endif

#ifndef ntohl
#define ntohl(x) ((__be32)___constant_swab32((x)))
#endif
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#ifndef htons
#define htons(x) (x)
#endif

#ifndef ntohs
#define ntohs(X) (x)
#endif

#ifndef htonl
#define htonl(x) (x)
#endif

#ifndef ntohl
#define ntohl(x) (x)
#endif
#endif

// Rate limit struct
struct ratelimit_val
{
    __u8 counts;
    __u64 next_reset;
};

// NTP return message struct with flags, auth, implementation, request code, error code, and clock
struct ntp_response
{
    __u8 flags;
    __u8 auth;
    __u8 implementation;
    __u8 request_code;
    __u8 error_code;
    __u8 clock;
};

// DNS qyery response struct with id, flags, questions, answers, authority, and additional
struct dns_response
{
    __u16 id;
    __u16 flags;
    __u16 questions;
    __u16 answers;
    __u16 authority;
    __u16 additional;
};

// SIP response struct
struct sip_response
{
    __u8 method[8];
    __u8 uri[64];
    __u8 version[8];
    __u8 host[64];
};

// ldap response struct
struct ldap_response
{
    __u8 version;
    __u8 type;
    __u16 length;
};

// Rtp response struct
struct rtp_response
{
    __u8 version;
    __u8 padding;
    __u8 extension;
    __u8 csrc_count;
    __u8 marker;
    __u8 payload_type;
    __u16 sequence_number;
    __u32 timestamp;
    __u32 ssrc;
};


// Blocked clients map
struct bpf_map_def SEC("maps") blocked_nerds =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__be32),
    .value_size = sizeof(__u64),
    .max_entries = 1000000
};

// Blocked tcp signatures map
struct bpf_map_def SEC("maps") blocked_tcp_signatures =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1000000
};

// Blocked udp signatures map
struct bpf_map_def SEC("maps") blocked_udp_signatures =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 1000000
};

// Client ratelimit map
struct bpf_map_def SEC("maps") client_ratelimit =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__be32),
    .value_size = sizeof(struct ratelimit_val),
    .max_entries = 1000000
};

// UDP Signature map
struct bpf_map_def SEC("maps") udp_signatures =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct ratelimit_val),
    .max_entries = 1000000
};

// TCP Signature map
struct bpf_map_def SEC("maps") tcp_signatures =
{
    .type = BPF_MAP_TYPE_LRU_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct ratelimit_val),
    .max_entries = 1000000
};

// Block client function
static inline void block_client(__be32 ip,__u64 now,__u16 time){
    __u64 block_time = now + (time * 1000000000);

    bpf_map_update_elem(&blocked_nerds, &ip, &block_time, BPF_ANY);
}

// Block tcp signature function
static inline void block_tcp_signature(__u32 sig,__u64 now,__u16 time){
    __u64 block_time = now + (time * 1000000000);

    bpf_map_update_elem(&blocked_tcp_signatures,&sig,&block_time,BPF_ANY);
}

// Block udp signature function
static inline void block_udp_signature(__u32 sig,__u64 now,__u16 time){
    __u64 block_time = now + (time * 1000000000);

    bpf_map_update_elem(&blocked_udp_signatures,&sig,&block_time,BPF_ANY);

}

// Rate limit ip function
static inline int ratelimit_client(__be32 ip,__u64 now,__u16 block_time,__u64 pps){
    struct ratelimit_val *val = bpf_map_lookup_elem(&client_ratelimit, &ip);
    if(!val)
    {
       struct ratelimit_val new_val = {0};
       new_val.counts = 1;
       new_val.next_reset = now + 1000000000;
       bpf_map_update_elem(&client_ratelimit,&ip,&new_val,BPF_ANY);
       return 0;
    }
    if (val->next_reset <= now)
    {
        val->counts = 1;
        val->next_reset = now + 1000000000;
        return 0;
    }
    val->counts++;
    if(pps > 0 && val->counts > pps) {
        block_client(ip, now, block_time);
    }
    return 0;
}

// Rate limit udp signature function
static inline int ratelimit_udp_signature(__u32 sig,__u64 now,__u16 block_time,__u64 pps){
    struct ratelimit_val *val = bpf_map_lookup_elem(&udp_signatures, &sig);
    if(!val)
    {
       struct ratelimit_val new_val = {0};
       new_val.counts = 1;
       new_val.next_reset = now + 1000000000;
       bpf_map_update_elem(&udp_signatures,&sig,&new_val,BPF_ANY);
       return 0;
    }
    if (val->next_reset <= now)
    {
        val->counts = 1;
        val->next_reset = now + 1000000000;
        return 0;
    }
    val->counts++;
    if(pps > 0 && val->counts > pps) {
        block_udp_signature(sig, now, block_time);
    }
    return 0;
}

// Rate limit tcp signature function
static inline int ratelimit_tcp_signature(__u32 sig,__u64 now,__u16 block_time,__u64 pps){
    struct ratelimit_val *val = bpf_map_lookup_elem(&tcp_signatures, &sig);
    if(!val)
    {
       struct ratelimit_val new_val = {0};
       new_val.counts = 1;
       new_val.next_reset = now + 1000000000;
       bpf_map_update_elem(&tcp_signatures,&sig,&new_val,BPF_ANY);
       return 0;
    }
    if (val->next_reset <= now)
    {
        val->counts = 1;
        val->next_reset = now + 1000000000;
        return 0;
    }
    val->counts++;
    if(pps > 0 && val->counts > pps) {
        block_tcp_signature(sig, now, block_time);
    }
    return 0;
}

// function to swap ip headers
static inline void swap_ip(struct iphdr *iph)
{
    __be32 tmp = iph->saddr;
    iph->saddr = iph->daddr;
    iph->daddr = tmp;
}

// Function that swaps the ethernet headers
static inline void swap_eth(struct ethhdr *eth)
{
    __u8 tmp[ETH_ALEN];
    memcpy(tmp, eth->h_source, ETH_ALEN);
    memcpy(eth->h_source, eth->h_dest, ETH_ALEN);
    memcpy(eth->h_dest, tmp, ETH_ALEN);
}

// Main xdp function
SEC("udpfilters")
int xdp_filter(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    __u16 len = (data_end - data);
    struct ethhdr *eth = data;
    if (eth + 1 > data_end) {
        return XDP_DROP;
    }

    __u64 now = bpf_ktime_get_ns();

    if(eth->h_proto == htons(ETH_P_IP)) {
        struct iphdr *iph = data + sizeof(struct ethhdr);
        if (iph + 1 > data_end) {
            return XDP_DROP;
        }

        __u64 *block_time = bpf_map_lookup_elem(&blocked_nerds, &iph->saddr);
        // Check if the client is blocked
        if (block_time)
        {
            ratelimit_client(iph->saddr,now,60,100);
            if (*block_time < now)
            {
                bpf_map_delete_elem(&blocked_nerds, &iph->saddr);
            }
            return XDP_DROP;
        }

        if(iph->protocol == IPPROTO_UDP) {
            struct udphdr *udph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (udph + 1 > data_end) {
                return XDP_DROP;
            }

            // Block dns responses with a * questions type
            if(udph->dest == htons(53)) {
                struct dns_response *dns = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
                if (dns + 1 > data_end) {
                    return XDP_DROP;
                }
                if(dns->questions == 0x00ff) {
                    block_client(iph->saddr, now, 60);
                    return XDP_DROP;
                }
            }

            // Block traffic coming from a ntp monlist amplification response
            if(udph->source == htons(123)) {
                struct ntp_response *ntp = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
                if (ntp + 1 > data_end) {
                    return XDP_DROP;
                }
                if(ntp->request_code == 0x2a) {
                    block_client(iph->saddr, now, 60);
                    return XDP_DROP;
                }
            }

            // Block traffic from a ldap amplification response
            if(udph->source == htons(389)) {
                struct ldap_response *ldap = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
                if (ldap + 1 > data_end) {
                    return XDP_DROP;
                }
                if(ldap->version == 0x30) {
                    return XDP_DROP;
                }
            }

            // Block traffic from a sip amplification response
            if(udph->source == htons(5060)) {
                struct sip_response *sip = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
                if (sip + 1 > data_end) {
                    return XDP_DROP;
                }
                if(*sip->version == 0x53) {
                    return XDP_DROP;
                }
            }

            // Block traffic from a rtp amplification response
            if(udph->source == htons(16384)) {
                struct rtp_response *rtp = data + sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct udphdr);
                if (rtp + 1 > data_end) {
                    return XDP_DROP;
                }
                if(rtp->version == 0x80) {
                    return XDP_DROP;
                }
            }

            // Block traffic coming from the source port of ssdp, portmap, snmp, netbios, and memcached services which should not be exposed to the internet
            if(udph->source == htons(1900) || udph->source == htons(111) || udph->source == htons(161) || udph->source == htons(137) || udph->source == htons(138) || udph->source == htons(11211)) {
                return XDP_DROP;
            }
            
            // Block udp traffic with invalid checksums
            if(udph->check == 0) {
                return XDP_DROP;
            }

            // Block udp traffic with invalid lengths
            __u16 udplen = len - sizeof(struct ethhdr) - (iph->ihl * 4);
            if(htons(udph->len) != udplen)
            {
                return XDP_DROP;
            }

            // Strict rate limit from ports of services commonly used for reflections
            if(udph->source == htons(17) || udph->source == htons(19) || udph->source == htons(53) || udph->source == htons(123) || udph->source == htons(161) || udph->source == htons(389) || udph->source == htons(1900) || udph->source == htons(9987) || udph->source == htons(111) || udph->source == htons(80) || udph->source == htons(443)) {
                ratelimit_client(iph->saddr,now,60,100);
            } else if(len < 400) {
                ratelimit_client(iph->saddr,now,60,10000);
            } else {
                ratelimit_client(iph->saddr,now,60,100000);
            }

            // Generate signature from udp header data
            __u32 sig = 0;
            sig = udph->source;
            sig = sig << 16;
            sig = sig | udph->dest;
            sig = sig << 16;
            sig = sig | udph->len;
            sig = sig << 16;
            sig = sig | udph->check;
            
            // Rate limit traffic using the Rate limit udp signature function
            ratelimit_udp_signature(sig,now,60,1000);

            // Check if the signature is blocked
            __u64 *block_time = bpf_map_lookup_elem(&blocked_udp_signatures, &sig);
            if (block_time)
            {
                if (*block_time < now)
                {
                    bpf_map_delete_elem(&blocked_udp_signatures, &sig);
                }
                return XDP_DROP;
            }
            return XDP_PASS;
        }
        // Ratelimit TCP
        if(iph->protocol == IPPROTO_TCP) {
            struct tcphdr *tcph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (tcph + 1 > data_end) {
                return XDP_DROP;
            }

            // TCP SYN rate limit
            if(tcph->syn && !tcph->ack) {
                ratelimit_client(iph->saddr,now,60,1000);
            }

            // Block tcp traffic with invalid flags
            if(tcph->syn && tcph->ack && tcph->fin && tcph->rst && tcph->psh && tcph->urg) {
                return XDP_DROP;
            }

            // Block tcp traffic with invalid checksums
            if(tcph->check == 0) {
                return XDP_DROP;
            }

            // Block tcp traffic with invalid length
            if(tcph->doff == 0) {
                return XDP_DROP;
            }

            // Block XMAS packets
            if(tcph->fin && tcph->psh && tcph->urg) {
                return XDP_DROP;
            }

            // Ratelimit traffic depending on the size of the packet and RST flag
            if(tcph->rst) {
                ratelimit_client(iph->saddr,now,10,100);
            }
            else if(len < 400) {
                ratelimit_client(iph->saddr,now,10,10000);
            }
            else {
                ratelimit_client(iph->saddr,now,10,100000);
            }

            // Generate signature from the tcp header
            __u32 sig = tcph->source + tcph->dest + tcph->doff + tcph->seq + tcph->ack_seq + tcph->window + tcph->urg_ptr + tcph->syn + tcph->ack + tcph->fin + tcph->rst + tcph->psh + tcph->urg;

            // Rate limit traffic using the Rate limit tcp signature function
            ratelimit_tcp_signature(sig,now,60,1000);

            // Check if the signature is blocked
            __u64 *block_time = bpf_map_lookup_elem(&blocked_tcp_signatures, &sig);
            if (block_time)
            {
                if (*block_time < now)
                {
                    bpf_map_delete_elem(&blocked_tcp_signatures, &sig);
                }
                return XDP_DROP;
            }
            return XDP_PASS;
        }
        // Respond to ICMP using XDP_TX
        if(iph->protocol == IPPROTO_ICMP) {
            // Get ICMP header
            struct icmphdr *icmph = data + sizeof(struct ethhdr) + sizeof(struct iphdr);
            if (icmph + 1 > data_end) {
                return XDP_DROP;
            }
            // Check for ICMP echo
            if (icmph->type == ICMP_ECHO) 
            {
                swap_eth(eth);
                swap_ip(iph);
        
                __u8 old_ttl = iph->ttl;
                iph->ttl = 64;
                iph->check = csum_diff4(old_ttl, 64, iph->check);

                icmph->type = ICMP_ECHOREPLY;
                icmph->checksum = csum_diff4(ICMP_ECHO, ICMP_ECHOREPLY, icmph->checksum);

                return XDP_TX;
            }
            return XDP_DROP;
        }
        // Drop all other ipv4 protocols
        return XDP_DROP;
    }
    // Pass other traffic
    return XDP_PASS;
}
