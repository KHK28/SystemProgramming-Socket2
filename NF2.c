#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/skbuff.h>
#include <uapi/linux/netfilter.h>
#include <uapi/linux/netfilter_ipv4.h>
#include <linux/kernel.h>

#define IP_TO_FORWARD 0x0400a8c0	//Host which added manually by route command

static unsigned int hook_pre(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *IP = ip_hdr(skb);
	struct tcphdr *TCP = tcp_hdr(skb);
	if (IP != NULL && TCP != NULL)
	{
		printk("PRE_ROUTING[%d, %u, %u, %pI4, %pI4]\n", (IP->protocol), ntohs(TCP->source), ntohs(TCP->dest), &(IP->saddr), &(IP->daddr));
	}
	if (ntohs(TCP->source) == (unsigned)33333)
	{
		TCP->source = htons((unsigned)7777);
		TCP->dest = htons((unsigned)7777);
		IP->daddr = ((unsigned long)IP_TO_FORWARD);
		printk("FORWARD[%d, %u, %u, %pI4, %pI4]\n", IP->protocol, ntohs(TCP->source), ntohs(TCP->dest), &(IP->saddr), &(IP->daddr));
	}
	return NF_ACCEPT;
}

static unsigned int hook_post(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
	struct iphdr *IP = ip_hdr(skb);
	struct tcphdr *TCP = tcp_hdr(skb);
	if (IP != NULL && TCP != NULL)
	{
		printk("POST_ROUTING[%d, %u, %u, %pI4, %pI4]\n", (IP->protocol), ntohs(TCP->source), ntohs(TCP->dest), &(IP->saddr), &(IP->daddr));
	}
	return NF_ACCEPT;
}

static struct nf_hook_ops ops_pre, ops_post;

static int NF_init(void)
{	
	// Setting PRE hook
	ops_pre.hook = hook_pre;
	ops_pre.pf = PF_INET;
	ops_pre.hooknum = NF_INET_PRE_ROUTING;
	ops_pre.priority = NF_IP_PRI_FIRST;
	// Setting POST hook
	ops_post.hook = hook_post;
	ops_post.pf = PF_INET;
	ops_post.hooknum = NF_INET_POST_ROUTING;
	ops_post.priority = NF_IP_PRI_FIRST;
	/* 
	Add Proc
	*/
	nf_register_hook(&ops_pre);
	nf_register_hook(&ops_post);
	return 0;
}

static void NF_exit(void)
{
	/* 
	Remove Proc
	*/
	nf_unregister_hook(&ops_pre);
	nf_unregister_hook(&ops_post);
}

module_init(NF_init);
module_exit(NF_exit);

MODULE_AUTHOR("7");
MODULE_DESCRIPTION("Netfilter");
MODULE_LICENSE("GPL");
MODULE_VERSION("0.0");
