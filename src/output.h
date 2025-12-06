#ifndef _H_PKT_UTILS
#define _H_PKT_UTILS

#include <net_utils.h>
#include "progs/skb_shared.h"

#define MAX_ADDR_LENGTH		48
#define PARAM_SET(name, value)			\
	obj->rodata->enable_##name = true;	\
	obj->rodata->arg_##name = value

#define BUF_FMT_INIT(fmt, args...)			\
	do {						\
		pos = sprintf(buf, fmt, ##args);	\
	} while (0)

#define BUF_FMT(fmt, args...) pos += sprintf(buf + pos, fmt, ##args)

enum {
	TIME_MODE_RAW = 0,
	TIME_MODE_TIME,
	TIME_MODE_DATE,
};

void ts_print_packet(char *buf, packet_t *pkt, char *minfo,
		     int time_mode);
void ts_print_sock(char *buf, sock_t *ske, char *minfo, int time_mode);
int  ts_print_ts(char *buf, u64 ts, int time_mode);

#endif
