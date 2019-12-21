#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <uapi/linux/netfilter.h>
#include <uapi/linux/netfilter_ipv4.h>

static unsigned int hook_pre(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *IP = ip_hdr(skb);
	struct tcphdr *TCP = tcp_hdr(skb);
}

static struct nf_hook_ops ops_pre;

static int __init NF_init(void)
{	
	ops_pre.hook = hook_pre;
	ops_pre.pf = PF_INET;
	ops_pre.hooknum = NF_INET_PRE_ROUTING;
	ops_pre.priority = NF_IP_PRI_FIRST;
	/* 
	Add Proc
	*/
	nf_register_hook(&ops_pre);
	return 0;
}

static void __exit NF_exit(void)
{
	/* 
	Remove Proc
	*/
	nf_unregister_hook(&ops_pre);
}

module_init(NF_init);
module_exit(NF_exit);

MODULE_AUTHOR("7");
MODULE_DESCRIPTION("Netfilter");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0");
