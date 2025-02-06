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
#include <linux/list.h>
#include <linux/spinlock.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("raza.mumtaz@ebryx.com");
MODULE_DESCRIPTION("Packet Inspection Module");

static struct nf_hook_ops nfho_tcp;

// Shared Data Structure
struct port_entry {
    u16 port;
    atomic_t refcount;
    struct list_head list;
};
struct list_head captured_ports = LIST_HEAD_INIT(captured_ports);
spinlock_t ports_lock;
EXPORT_SYMBOL(captured_ports);
EXPORT_SYMBOL(ports_lock);

static void cleanup_captured_ports(void) {
    struct port_entry *entry, *tmp;
    
    spin_lock(&ports_lock);
    list_for_each_entry_safe(entry, tmp, &captured_ports, list) {
        list_del(&entry->list);
        kfree(entry);
    }
    spin_unlock(&ports_lock);
}

#define MAX_PAYLOAD_SIZE 1024

static bool contains_traversal_sequence(char *payload, size_t payload_len) {
    if (!payload || payload_len == 0)
        return false;

    // Impose an upper limit on payload length
    if (payload_len > MAX_PAYLOAD_SIZE)
        payload_len = MAX_PAYLOAD_SIZE;

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
    
    char *lower_payload;
    size_t i;

    // Allocate memory from the heap
    lower_payload = kmalloc(payload_len + 1, GFP_KERNEL);
    if (!lower_payload)
        return false;  // Allocation failed

    // Convert payload to lowercase safely
    for (i = 0; i < payload_len; i++) {
        lower_payload[i] = tolower(payload[i]);
    }
    lower_payload[payload_len] = '\0';

    // Search for traversal patterns
    for (i = 0; i < ARRAY_SIZE(patterns); i++) {
        if (strnstr(lower_payload, patterns[i], payload_len)) {
            kfree(lower_payload);
            return true;
        }
    }

    kfree(lower_payload);
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
        pr_err("[bluerock.io netfilter_monitor] Failed to linearize skb\n");
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
        // pr_info("[bluerock.io netfilter_monitor] --- Payload ---:\n%s---------------",payload);
        if (contains_traversal_sequence(payload, payload_len)) {
            pr_info("[bluerock.io netfilter_monitor] --- Payload ---:\n%s---------------",payload);
            pr_warn("[bluerock.io netfilter_monitor] Path Traversal Detected from IP: %pI4, Src Port: %u\n",
                   &ip_header->saddr, ntohs(tcp_header->source));
            
            struct port_entry *entry = kmalloc(sizeof(*entry), GFP_ATOMIC);
            entry->port = ntohs(tcp_header->dest);
            atomic_set(&entry->refcount, 1);

            spin_lock(&ports_lock);
            list_add_tail(&entry->list, &captured_ports);
            spin_unlock(&ports_lock);
        }
    }

    return NF_ACCEPT;
}

static int __init monitor_init(void) {
    pr_info("[bluerock.io netfilter_monitor] [bluerock.io] Initializing Packet Inspection Module\n");

    nfho_tcp.hook = hook_func_tcp;
    nfho_tcp.hooknum = NF_INET_PRE_ROUTING;
    nfho_tcp.pf = PF_INET;
    nfho_tcp.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho_tcp);

    return 0;
}

static void __exit monitor_exit(void) {
    pr_info("[bluerock.io netfilter_monitor] [bluerock.io] Cleaning up Packet Inspection Module\n");
    nf_unregister_net_hook(&init_net, &nfho_tcp);
    cleanup_captured_ports();
}

module_init(monitor_init);
module_exit(monitor_exit);