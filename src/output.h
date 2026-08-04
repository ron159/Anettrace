#ifndef _H_PKT_UTILS
#define _H_PKT_UTILS

#include "utils/net_utils.h"
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

enum time_mode {
	TIME_MODE_LOCAL,
	TIME_MODE_DATE,
	TIME_MODE_MONOTONIC,
};

void output_time_init(void);
void ts_print_packet(char *buf, packet_t *pkt, char *minfo,
		     enum time_mode time_mode);
void ts_print_sock(char *buf, sock_t *ske, char *minfo,
		   enum time_mode time_mode);
int  ts_print_ts(char *buf, u64 ts, enum time_mode time_mode);

#endif
