#include <linux/version.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include <net/ip.h>
#include <net/tcp.h>
#include <net/udp.h>

#define MAGIC 0xdeadbeef
#define MAGIC1_OFFSET 22
#define MAGIC2_OFFSET 26
#define IP1_OFFSET 30
#define IP2_OFFSET 34

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

static struct nf_hook_ops nfho_pre, nfho_post;

uint32_t orig_ip = 0;
uint32_t new_ip = 0;


void fix_packet_checksum(struct sk_buff *skb, struct iphdr *iph) {

    struct sk_buff* sock_buff = skb;
    struct tcphdr *tcph;
    struct udphdr *udph;
    unsigned int tcplen = 0, udplen = 0;

    // fix IP header checksum
    sock_buff->ip_summed = CHECKSUM_NONE; //stop offloading
    sock_buff->csum_valid = 0;
    iph->check = 0;
    iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
    
    if ((iph->protocol == IPPROTO_TCP) || (iph->protocol == IPPROTO_UDP)) {
        
        // convert paged skb to linear one
        if (skb_is_nonlinear(sock_buff)) {
            skb_linearize(sock_buff); 
        }

        sock_buff->csum = 0;

        // fix TCP header checksum
        if (iph->protocol==IPPROTO_TCP) {
            tcph = tcp_hdr(sock_buff);
            printk(KERN_INFO "tcp old checksum: %d\n", tcph->check);
            tcplen = ntohs(iph->tot_len) - iph->ihl*4;
            tcph->check = 0;
            tcph->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial((char *)tcph, tcplen, 0));
            printk(KERN_INFO "tcp new checksum: %d\n", tcph->check);
        }

        // fix UDP header checksum
        else if (iph->protocol==IPPROTO_UDP) {
            udph = udp_hdr(sock_buff);
            printk(KERN_INFO "udp old checksum: %d\n", udph->check);
            udplen = ntohs(iph->tot_len) - iph->ihl*4;
            udph->check = 0;
            udph->check = udp_v4_check(udplen,iph->saddr, iph->daddr, csum_partial((char *)udph, udplen, 0));
            printk(KERN_INFO "udp new checksum: %d\n", udph->check);
        }
    }
}

unsigned int hook_func_pre(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct sk_buff* sock_buff = skb;
    struct iphdr *iph;
    
    if (!sock_buff) {
        return NF_ACCEPT;
    }

    iph = (struct iphdr *)skb_network_header(sock_buff);

    if (!iph) {
        // no ip header
        return NF_ACCEPT;
    }

    // check if the ip is hooked
    if (orig_ip && new_ip && iph->saddr == new_ip) {
        printk(KERN_INFO "%d.%d.%d.%d->%d.%d.%d.%d\n", NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
        iph->saddr = orig_ip;
        fix_packet_checksum(sock_buff, iph);
    }
    return NF_ACCEPT;        
}

unsigned int hook_func_post(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct sk_buff* sock_buff = skb;
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned int magic1 = 0, magic2 = 0;
    unsigned char * ptcph = 0;

    if (!sock_buff) {
        return NF_ACCEPT;
    }

    iph = (struct iphdr *)skb_network_header(sock_buff);

    if (!iph) {
        // no ip header
        return NF_ACCEPT;
    }

    // check if the ip is hooked
    if (orig_ip && new_ip && iph->daddr == orig_ip) {
        printk(KERN_INFO "%d.%d.%d.%d->%d.%d.%d.%d\n", NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
        iph->daddr = new_ip;
        fix_packet_checksum(sock_buff, iph);
    }
  
    if (iph->protocol==IPPROTO_TCP) {
        // check for magic packet from the client
        tcph = tcp_hdr(sock_buff);
        ptcph = (unsigned char *)tcph;
        magic1 = *(uint32_t *)(ptcph + MAGIC1_OFFSET);
        magic2 = *(uint32_t *)(ptcph + MAGIC2_OFFSET);

        if ((magic1 ^ magic2) == 0xdeadbeef) {
            printk(KERN_INFO "magic1: %x\n", magic1);
            printk(KERN_INFO "magic2: %x\n", magic2);
            printk(KERN_INFO "xored: %x\n", (magic1 ^ magic2));
            printk(KERN_INFO "found! installing ip hook\n");
            orig_ip = *(uint32_t *)(ptcph + IP1_OFFSET);
            new_ip = *(uint32_t *)(ptcph + IP2_OFFSET);
            printk(KERN_INFO "origin ip: %d.%d.%d.%d\n", NIPQUAD(orig_ip));
            printk(KERN_INFO "new ip: %d.%d.%d.%d\n", NIPQUAD(new_ip));
            //drop the packet
            return NF_DROP;
        }
    }
    return NF_ACCEPT;        
}

static int __init initialize(void) {
    printk(KERN_INFO "installing netfilter\n");
    // we must hook pre_route and post_route to capture all packets

    // hook PRE_ROUTING
    nfho_pre.hook = hook_func_pre;
    nfho_pre.hooknum = NF_INET_PRE_ROUTING;
    nfho_pre.pf = PF_INET;
    nfho_pre.priority = NF_IP_PRI_FIRST;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_register_net_hook(&init_net, &nfho_pre);
#else
    nf_register_hook(&nfho_pre);
#endif

    // hook POST_ROUTING
    nfho_post.hook = hook_func_post;
    nfho_post.hooknum = NF_INET_POST_ROUTING;
    nfho_post.pf = PF_INET;
    nfho_post.priority = NF_IP_PRI_FIRST;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_register_net_hook(&init_net, &nfho_post);
#else
    nf_register_hook(&nfho_post);
#endif

    return 0;    
}

static void __exit teardown(void) {
    printk(KERN_INFO "removing netfilter\n");

    // unhook PRE_ROUTING
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_unregister_net_hook(&init_net, &nfho_pre);
#else
    nf_unregister_hook(&nfho_pre);
#endif

    // unhook POST_ROUTING
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_unregister_net_hook(&init_net, &nfho_post);
#else
    nf_unregister_hook(&nfho_post);
#endif
}

module_init(initialize);
module_exit(teardown);
