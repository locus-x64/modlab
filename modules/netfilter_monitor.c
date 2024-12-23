#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <linux/string.h>
#include <linux/byteorder/generic.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Your Name");
MODULE_DESCRIPTION("Netfilter Hook to Detect '../' Sequence in TCP Packets");

// Netfilter hook operation struct
static struct nf_hook_ops nfho_tcp;



// Check if payload contains traversal sequences
static bool contains_traversal_sequence(char *payload, size_t payload_len) {
    if (!payload || payload_len == 0)
        return false;

    const char *patterns[] = {
        "\\.\\./", "\\\\.\\\\",
        "%2E%2E%2F", "%2E%2E%5C",
        "%252E%252E%252F", "%252E%252E%255C",
        "%2e%2e%2f", "%2e%2e%5c",
        "%252e%252e%252f", "%252e%252e%255c"
    };

    for (int i = 0; i < ARRAY_SIZE(patterns); i++) {
        if (strnstr(payload, patterns[i], payload_len))
            return true;
    }

    return false;
}

// Hook function
unsigned int hook_func_tcp(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    unsigned char *payload;
    unsigned int ip_header_len, tcp_header_len, payload_len;

    if (!skb)
        return NF_ACCEPT;

    // Ensure skb is linearized
    if (skb_linearize(skb) != 0) {
        printk(KERN_WARNING "Failed to linearize skb\n");
        return NF_ACCEPT;
    }

    ip_header = ip_hdr(skb);
    if (!ip_header || ip_header->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    tcp_header = tcp_hdr(skb);
    if (!tcp_header)
        return NF_ACCEPT;

    // Calculate header lengths
    ip_header_len = ip_header->ihl * 4;
    tcp_header_len = tcp_header->doff * 4;

    // Ensure skb has enough data for headers
    if (skb->len < (ip_header_len + tcp_header_len))
        return NF_ACCEPT;

    // Calculate payload pointer
    payload = (unsigned char *)((unsigned char *)ip_header + ip_header_len + tcp_header_len);
    payload_len = skb->len - (ip_header_len + tcp_header_len);

    // Ensure payload is within skb's data range
    if (payload_len > 0 && payload_len <= skb_tail_pointer(skb) - skb->data) {
        // pr_info("Payload: %s\n",payload);
        if (contains_traversal_sequence(payload, payload_len)) {
            printk(KERN_WARNING "Path Traversal Detected in TCP Packet: Src IP: %pI4, Dst IP: %pI4, Src Port: %u, Dst Port: %u\n",
                   &ip_header->saddr, &ip_header->daddr,
                   ntohs(tcp_header->source), ntohs(tcp_header->dest));
        }
    }

    return NF_ACCEPT;
}

// Module initialization
static int __init monitor_init(void) {
    printk(KERN_INFO "Initializing Netfilter TCP Packet Monitor for '../' Detection\n");

    nfho_tcp.hook = hook_func_tcp;
    nfho_tcp.hooknum = NF_INET_LOCAL_IN;
    nfho_tcp.pf = PF_INET;
    nfho_tcp.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho_tcp);

    return 0;
}

// Module cleanup
static void __exit monitor_exit(void) {
    printk(KERN_INFO "Cleaning up Netfilter TCP Packet Monitor\n");
    nf_unregister_net_hook(&init_net, &nfho_tcp);
}

module_init(monitor_init);
module_exit(monitor_exit);
