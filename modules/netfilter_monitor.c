#include <linux/ip.h>
#include <net/sock.h>
#include <linux/fs.h>
#include <linux/tcp.h>
#include <linux/ctype.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/kernel.h>
#include <linux/socket.h>
#include <linux/fdtable.h>
#include <linux/rcupdate.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/sched/signal.h>

static struct nf_hook_ops nfho_tcp;

#include <linux/ctype.h>

static bool contains_traversal_sequence(char *payload, size_t payload_len) {
    if (!payload || payload_len == 0)
        return false;

    const char *patterns[] = {
        // Basic patterns
        "../", "..\\", "..%2F", "..%5C", "%2e%2e%2f", "%2e%2e%5c", 
        "%252e%252e%252f", "%252e%252e%255c",
        "..%c0%af", "..%c1%9c", "..%c0%9v", "..%c1%pc",
        "..%e0%80%af", "..%f0%80%80%af", "..%u2215", "..%u2216",
        
        // Mixed encodings
        ".%2e/", ".%2e\\", ".%252e/", ".%252e\\",
        "..;/", "..;\\", "..::", "..%00/", "..%00\\",

        // Double encoding
        "%2e%2e%2f", "%2e%2e%5c", "%252e%252e%252f", "%252e%252e%255c",
        "%2e%2e/", "%2e%2e\\", "..%2f", "..%5c",

        // Unicode encodings
        "%u002e%u002e%u002f", "%u002e%u002e%u005c", "%uff0e%uff0e%u2215",
        "%uff0e%uff0e%u2216", "%u2024%u2024%u2215", "%u2024%u2024%u2216",

        // Obfuscated variations
        "..~1/", "..~1\\", "..`/", "..`\\", "..^/",
        
        // Null-byte injection
        "../%00", "..\\%00", "..%00/", "..%00\\"
    };

    char lower_payload[payload_len + 1];
    size_t i;

    // Convert payload to lowercase
    for (i = 0; i < payload_len; i++) {
        lower_payload[i] = tolower(payload[i]);
    }
    lower_payload[payload_len] = '\0';

    for (i = 0; i < ARRAY_SIZE(patterns); i++) {
        if (strnstr(lower_payload, patterns[i], payload_len))
            return true;
    }

    return false;
}

unsigned int hook_func_tcp(void *priv, struct sk_buff *skb, const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;
    unsigned char *payload;
    unsigned int ip_header_len, tcp_header_len, payload_len;

    if (!skb)
        return NF_ACCEPT;

    if (skb_linearize(skb) != 0) {
        pr_err("Failed to linearize skb\n");
        return NF_ACCEPT;
    }

    ip_header = ip_hdr(skb);
    if (!ip_header || ip_header->protocol != IPPROTO_TCP)
        return NF_ACCEPT;

    tcp_header = tcp_hdr(skb);
    if (!tcp_header)
        return NF_ACCEPT;

    ip_header_len = ip_header->ihl * 4;
    tcp_header_len = tcp_header->doff * 4;

    if (skb->len < (ip_header_len + tcp_header_len))
        return NF_ACCEPT;

    payload = (unsigned char *)((unsigned char *)ip_header + ip_header_len + tcp_header_len);
    payload_len = skb->len - (ip_header_len + tcp_header_len);

    if (payload_len > 0 && payload_len <= skb_tail_pointer(skb) - skb->data) {
        // pr_info("--- Payload ---:\n%s---------------",payload);
        if (contains_traversal_sequence(payload, payload_len)) {
            pr_info("--- Payload ---:\n%s---------------",payload);
            pr_warn("[bluerock.io] Path Traversal Detected: Src IP: %pI4, Src Port: %u\n",
                   &ip_header->saddr, ntohs(tcp_header->source));
        }
    }

    return NF_ACCEPT;
}

static int __init monitor_init(void) {
    pr_info("[bluerock.io] Initializing path traversal guard\n");

    nfho_tcp.hook = hook_func_tcp;
    nfho_tcp.hooknum = NF_INET_PRE_ROUTING;
    nfho_tcp.pf = PF_INET;
    nfho_tcp.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho_tcp);

    return 0;
}

static void __exit monitor_exit(void) {
    pr_info("[bluerock.io] Cleaning up path traversal guard\n");
    nf_unregister_net_hook(&init_net, &nfho_tcp);
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("raza.mumtaz@ebryx.com");
MODULE_DESCRIPTION("Path Traversal Guard");

module_init(monitor_init);
module_exit(monitor_exit);