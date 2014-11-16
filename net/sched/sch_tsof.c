/*
 * net/sched/sch_tsof.c	Take Small Ones First "scheduler".
 *
 *		This program is free software; you can redistribute it and/or
 *		modify it under the terms of the GNU General Public License
 *		as published by the Free Software Foundation; either version
 *		2 of the License, or (at your option) any later version.
 *
 * Authors:	Radek Podgorny, <radek@podgorny.cz>
 */

#include <linux/module.h>
#include <linux/slab.h>
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/errno.h>
#include <linux/skbuff.h>
#include <net/netlink.h>
#include <net/pkt_sched.h>


struct tsof_sched_data {
	int bands;
	struct tcf_proto __rcu *filter_list;
	u8 borders[TCQ_TSOF_BANDS-1];
	struct Qdisc *queues[TCQ_TSOF_BANDS];
};

static int size2band(struct tsof_sched_data *q, int size)
{
	int i = 0;
	for (i = 0; i < q->bands-1; i++) {
		if (size < q->borders[i])
			return i;
	}
	return q->bands-1;
}

static struct Qdisc *
tsof_classify(struct sk_buff *skb, struct Qdisc *sch, int *qerr)
{
	struct tsof_sched_data *q = qdisc_priv(sch);

	return q->queues[size2band(q, skb->len)];
}

static int
tsof_enqueue(struct sk_buff *skb, struct Qdisc *sch)
{
	struct Qdisc *qdisc;
	int ret;

	qdisc = tsof_classify(skb, sch, &ret);
#ifdef CONFIG_NET_CLS_ACT
	if (qdisc == NULL) {

		if (ret & __NET_XMIT_BYPASS)
			qdisc_qstats_drop(sch);
		kfree_skb(skb);
		return ret;
	}
#endif

	ret = qdisc_enqueue(skb, qdisc);
	if (ret == NET_XMIT_SUCCESS) {
		sch->q.qlen++;
		return NET_XMIT_SUCCESS;
	}
	if (net_xmit_drop_count(ret))
		qdisc_qstats_drop(sch);
	return ret;
}


static struct sk_buff *tsof_peek(struct Qdisc* sch)
{
	struct tsof_sched_data *q = qdisc_priv(sch);
	int i;

	for (i = 0; i < q->bands; i++) {
		struct Qdisc *qdisc = q->queues[i];
		struct sk_buff *skb = qdisc->ops->peek(qdisc);
		if (skb)
			return skb;
	}
	return NULL;
}

static struct sk_buff *tsof_dequeue(struct Qdisc *sch)
{
	struct tsof_sched_data *q = qdisc_priv(sch);
	int i;

	for (i = 0; i < q->bands; i++) {
		struct Qdisc *qdisc = q->queues[i];
		struct sk_buff *skb = qdisc_dequeue_peeked(qdisc);
		if (skb) {
			qdisc_bstats_update(sch, skb);
			sch->q.qlen--;
			return skb;
		}
	}
	return NULL;

}

static unsigned int tsof_drop(struct Qdisc *sch)
{
	struct tsof_sched_data *q = qdisc_priv(sch);
	int i;
	unsigned int len;
	struct Qdisc *qdisc;

	for (i=q->bands-1; i >= 0; i--) {
		qdisc = q->queues[i];
		if (qdisc->ops->drop && (len = qdisc->ops->drop(qdisc)) != 0) {
			sch->q.qlen--;
			return len;
		}
	}
	return 0;
}


static void
tsof_reset(struct Qdisc *sch)
{
	int i;
	struct tsof_sched_data *q = qdisc_priv(sch);

	for (i = 0; i < q->bands; i++)
		qdisc_reset(q->queues[i]);
	sch->q.qlen = 0;
}

static void
tsof_destroy(struct Qdisc *sch)
{
	int i;
	struct tsof_sched_data *q = qdisc_priv(sch);

	tcf_destroy_chain(&q->filter_list);
	for (i = 0; i < q->bands; i++)
		qdisc_destroy(q->queues[i]);
}

static int tsof_tune(struct Qdisc *sch, struct nlattr *opt)
{
	struct tsof_sched_data *q = qdisc_priv(sch);
	struct tc_tsof_qopt *qopt;
	int i;

	if (nla_len(opt) < sizeof(*qopt))
		return -EINVAL;
	qopt = nla_data(opt);

	if (qopt->bands > TCQ_TSOF_BANDS || qopt->bands < 2)
		return -EINVAL;

	// check if borders are sorted (ascending)
	for (i = 1; i < qopt->bands; i++) {
		if (qopt->borders[i-1] >= qopt->borders[i])
			return -EINVAL;
	}

	sch_tree_lock(sch);
	q->bands = qopt->bands;
	memcpy(q->borders, qopt->borders, sizeof(q->borders));

	for (i = q->bands; i < TCQ_TSOF_BANDS; i++) {
		struct Qdisc *child = q->queues[i];
		q->queues[i] = &noop_qdisc;
		if (child != &noop_qdisc) {
			qdisc_tree_decrease_qlen(child, child->q.qlen);
			qdisc_destroy(child);
		}
	}
	sch_tree_unlock(sch);

	for (i = 0; i < q->bands; i++) {
		if (q->queues[i] == &noop_qdisc) {
			struct Qdisc *child, *old;

			child = qdisc_create_dflt(sch->dev_queue,
						  &pfifo_qdisc_ops,
						  TC_H_MAKE(sch->handle, i + 1));
			if (child) {
				sch_tree_lock(sch);
				old = q->queues[i];
				q->queues[i] = child;

				if (old != &noop_qdisc) {
					qdisc_tree_decrease_qlen(old,
								 old->q.qlen);
					qdisc_destroy(old);
				}
				sch_tree_unlock(sch);
			}
		}
	}
	return 0;
}

static int tsof_init(struct Qdisc *sch, struct nlattr *opt)
{
	struct tsof_sched_data *q = qdisc_priv(sch);
	int i;

	for (i = 0; i < TCQ_TSOF_BANDS; i++)
		q->queues[i] = &noop_qdisc;

	if (opt == NULL) {
		return -EINVAL;
	} else {
		int err;

		if ((err = tsof_tune(sch, opt)) != 0)
			return err;
	}
	return 0;
}

static int tsof_dump(struct Qdisc *sch, struct sk_buff *skb)
{
	struct tsof_sched_data *q = qdisc_priv(sch);
	unsigned char *b = skb_tail_pointer(skb);
	struct tc_tsof_qopt opt;

	opt.bands = q->bands;
	memcpy(&opt.borders, q->borders, sizeof(q->borders));

	if (nla_put(skb, TCA_OPTIONS, sizeof(opt), &opt))
		goto nla_put_failure;

	return skb->len;

nla_put_failure:
	nlmsg_trim(skb, b);
	return -1;
}

static int tsof_graft(struct Qdisc *sch, unsigned long arg, struct Qdisc *new,
		      struct Qdisc **old)
{
	struct tsof_sched_data *q = qdisc_priv(sch);
	unsigned long band = arg - 1;

	if (new == NULL)
		new = &noop_qdisc;

	sch_tree_lock(sch);
	*old = q->queues[band];
	q->queues[band] = new;
	qdisc_tree_decrease_qlen(*old, (*old)->q.qlen);
	qdisc_reset(*old);
	sch_tree_unlock(sch);

	return 0;
}

static struct Qdisc *
tsof_leaf(struct Qdisc *sch, unsigned long arg)
{
	struct tsof_sched_data *q = qdisc_priv(sch);
	unsigned long band = arg - 1;

	return q->queues[band];
}

static unsigned long tsof_get(struct Qdisc *sch, u32 classid)
{
	struct tsof_sched_data *q = qdisc_priv(sch);
	unsigned long band = TC_H_MIN(classid);

	if (band - 1 >= q->bands)
		return 0;
	return band;
}

static unsigned long tsof_bind(struct Qdisc *sch, unsigned long parent, u32 classid)
{
	return tsof_get(sch, classid);
}


static void tsof_put(struct Qdisc *q, unsigned long cl)
{
}

static int tsof_dump_class(struct Qdisc *sch, unsigned long cl, struct sk_buff *skb,
			   struct tcmsg *tcm)
{
	struct tsof_sched_data *q = qdisc_priv(sch);

	tcm->tcm_handle |= TC_H_MIN(cl);
	tcm->tcm_info = q->queues[cl-1]->handle;
	return 0;
}

static int tsof_dump_class_stats(struct Qdisc *sch, unsigned long cl,
				 struct gnet_dump *d)
{
	struct tsof_sched_data *q = qdisc_priv(sch);
	struct Qdisc *cl_q;

	cl_q = q->queues[cl - 1];
	if (gnet_stats_copy_basic(d, NULL, &cl_q->bstats) < 0 ||
	    gnet_stats_copy_queue(d, NULL, &cl_q->qstats, cl_q->q.qlen) < 0)
		return -1;

	return 0;
}

static void tsof_walk(struct Qdisc *sch, struct qdisc_walker *arg)
{
	struct tsof_sched_data *q = qdisc_priv(sch);
	int i;

	if (arg->stop)
		return;

	for (i = 0; i < q->bands; i++) {
		if (arg->count < arg->skip) {
			arg->count++;
			continue;
		}
		if (arg->fn(sch, i+1, arg) < 0) {
			arg->stop = 1;
			break;
		}
		arg->count++;
	}
}

static struct tcf_proto __rcu **tsof_find_tcf(struct Qdisc *sch,
					      unsigned long cl)
{
	struct tsof_sched_data *q = qdisc_priv(sch);

	if (cl)
		return NULL;
	return &q->filter_list;
}

static const struct Qdisc_class_ops tsof_class_ops = {
	.graft		=	tsof_graft,
	.leaf		=	tsof_leaf,
	.get		=	tsof_get,
	.put		=	tsof_put,
	.walk		=	tsof_walk,
	.tcf_chain	=	tsof_find_tcf,
	.bind_tcf	=	tsof_bind,
	.unbind_tcf	=	tsof_put,
	.dump		=	tsof_dump_class,
	.dump_stats	=	tsof_dump_class_stats,
};

static struct Qdisc_ops tsof_qdisc_ops __read_mostly = {
	.next		=	NULL,
	.cl_ops		=	&tsof_class_ops,
	.id		=	"tsof",
	.priv_size	=	sizeof(struct tsof_sched_data),
	.enqueue	=	tsof_enqueue,
	.dequeue	=	tsof_dequeue,
	.peek		=	tsof_peek,
	.drop		=	tsof_drop,
	.init		=	tsof_init,
	.reset		=	tsof_reset,
	.destroy	=	tsof_destroy,
	.change		=	tsof_tune,
	.dump		=	tsof_dump,
	.owner		=	THIS_MODULE,
};

static int __init tsof_module_init(void)
{
	return register_qdisc(&tsof_qdisc_ops);
}

static void __exit tsof_module_exit(void)
{
	unregister_qdisc(&tsof_qdisc_ops);
}

module_init(tsof_module_init)
module_exit(tsof_module_exit)

MODULE_LICENSE("GPL");
