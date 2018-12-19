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

#define MAGIC 0xdeadbeef

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

static struct nf_hook_ops nfho;
struct iphdr *iph;
struct tcphdr *tcp_header;
struct udphdr *udp_header;
struct sk_buff *sock_buff;
uint16_t sport, dport;

uint32_t orig_ip = 0;
uint32_t new_ip = 0;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
unsigned int hook_func(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
#else
unsigned int hook_func(unsigned int hooknum,
                       struct sk_buff **skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn)(struct sk_buff *))
#endif
{
    unsigned int magic1 = 0;
    unsigned int magic2 = 0;
    unsigned char * ptr_tcp_header = 0;
    int fix_checksum_flag = 0;
    int tcplen = 0;
    //printk(KERN_INFO "=== BEGIN HOOK ===\n");

    sock_buff = skb;

    if (!sock_buff) {
        return NF_ACCEPT;
    }

    iph = (struct iphdr *)skb_network_header(sock_buff);

    if (!iph) {
        //printk(KERN_INFO "no ip header\n");
        return NF_ACCEPT;
    }
    //printk(KERN_INFO "=== IP ===\n");

    // check for hooked ip
    if (orig_ip && new_ip) {
	if (iph->saddr == new_ip) {
            printk(KERN_INFO "%d.%d.%d.%d->%d.%d.%d.%d\n", NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
            iph->saddr = orig_ip;
            fix_checksum_flag = 1;
	}
	else if (iph->daddr == orig_ip) {
            printk(KERN_INFO "%d.%d.%d.%d->%d.%d.%d.%d\n", NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));
            iph->daddr = new_ip;
            fix_checksum_flag = 1;
	}
        if (fix_checksum_flag) {
            // fix IP header checksum
            sock_buff->ip_summed = CHECKSUM_NONE; //stop offloading
            sock_buff->csum_valid = 0;
            iph->check = 0;
            iph->check = ip_fast_csum((u8 *)iph, iph->ihl);
            
            if(skb_is_nonlinear(sock_buff))
                skb_linearize(sock_buff); 

            // fix TCP header checksum
            if (iph->protocol==IPPROTO_TCP) {
                printk(KERN_INFO "old checksum: %d\n", tcp_header->check);
                tcp_header = tcp_hdr(sock_buff);
                sock_buff->csum =0;
                tcplen = ntohs(iph->tot_len) - iph->ihl*4;
                tcp_header->check = 0;
                tcp_header->check = tcp_v4_check(tcplen, iph->saddr, iph->daddr, csum_partial((char *)tcp_header, tcplen, 0));
                printk(KERN_INFO "new checksum: %d\n", tcp_header->check);
            }
        }

    }
  
    if (iph->protocol==IPPROTO_TCP) {
        //printk(KERN_INFO "=== TCP ===\n");
        tcp_header = tcp_hdr(sock_buff);
        sport = ntohs((uint16_t) tcp_header->source);
        dport = ntohs((uint16_t) tcp_header->dest);
        //printk(KERN_INFO "TCP ports: source: %d, dest: %d\n", sport, dport);
        //printk(KERN_INFO "SKBuffer: len %d, data_len %d\n", sock_buff->len, sock_buff->data_len);
	ptr_tcp_header = (unsigned char *)tcp_header;
	magic1 = *(uint32_t *)(ptr_tcp_header+22);
	magic2 = *(uint32_t *)(ptr_tcp_header+26);
	if ((magic1 ^ magic2) == 0xdeadbeef) {
	    printk(KERN_INFO "magic1: %x\n", magic1);
	    printk(KERN_INFO "magic2: %x\n", magic2);
	    printk(KERN_INFO "xored: %x\n", (magic1 ^ magic2));
            printk(KERN_INFO "Found! installing ip hook\n");
            orig_ip = *(uint32_t *)(ptr_tcp_header+30);
	    new_ip = *(uint32_t *)(ptr_tcp_header+34);
            printk(KERN_INFO "origin ip: %d.%d.%d.%d\n", NIPQUAD(orig_ip));
            printk(KERN_INFO "new ip: %d.%d.%d.%d\n", NIPQUAD(new_ip));
	}
    }
    else if(iph->protocol==IPPROTO_UDP) {
        //printk(KERN_INFO "=== UDP ===\n");
        //udp_header = udp_hdr(sock_buff);
        //sport = ntohs((unsigned short int) udp_header->source);
        //dport = ntohs((unsigned short int) udp_header->dest);
        //printk(KERN_INFO "UDP ports: source: %d, dest: %d \n", sport, dport);
        //printk(KERN_INFO "SKBuffer: len %d, data_len %d\n", sock_buff->len, sock_buff->data_len);
    }
    else if(iph->protocol==IPPROTO_ICMP) {
        //printk(KERN_INFO "=== ICMP ===\n");
        //printk(KERN_INFO "IP header: original source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
        //iph->saddr = iph->saddr ^ 0x10000000;
        //printk(KERN_INFO "IP header: modified source: %d.%d.%d.%d\n", NIPQUAD(iph->saddr));
        //printk(KERN_INFO "IP header: original destin: %d.%d.%d.%d\n", NIPQUAD(iph->daddr));
    }

    //printk(KERN_INFO "=== END HOOK ===\n");
    return NF_ACCEPT;        

}

static int __init initialize(void) {
    // we must hook before and after routing to capture all packets
    printk(KERN_INFO "installing netfilter\n");
    // hook POST_ROUTING
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_POST_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_register_net_hook(&init_net, &nfho);
#else
    nf_register_hook(&nfho);
#endif

    // hook PRE_ROUTING
    nfho.hooknum = NF_INET_PRE_ROUTING;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_register_net_hook(&init_net, &nfho);
#else
    nf_register_hook(&nfho);
#endif

    return 0;    
}

static void __exit teardown(void) {
    printk(KERN_INFO "removing netfilter\n");
    // unhook PRE_ROUTING
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_unregister_net_hook(&init_net, &nfho);
#else
    nf_unregister_hook(&nfho);
#endif

    // unhook POST_ROUTING
    nfho.hooknum = NF_INET_POST_ROUTING;
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,13,0)
    nf_unregister_net_hook(&init_net, &nfho);
#else
    nf_unregister_hook(&nfho);
#endif
}

module_init(initialize);
module_exit(teardown);
