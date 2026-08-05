// SPDX-License-Identifier: MulanPSL-2.0

#ifndef _H_TRAFFIC_SHARED
#define _H_TRAFFIC_SHARED

#define TRAFFIC_COMM_LEN 16
#define TRAFFIC_MAX_FLOWS 16384
#define TRAFFIC_STALE_NS (300ULL * 1000000000ULL)

enum traffic_operation {
	TRAFFIC_OP_TCP_TX = 1,
	TRAFFIC_OP_TCP_RX,
	TRAFFIC_OP_UDP4_TX,
	TRAFFIC_OP_UDP4_RX,
	TRAFFIC_OP_UDP6_TX,
	TRAFFIC_OP_UDP6_RX,
};

enum traffic_stat_index {
	TRAFFIC_STAT_INFLIGHT_DROP,
	TRAFFIC_STAT_FLOW_DROP,
	TRAFFIC_STAT_MAX,
};

typedef union {
	u32 v4;
	u8 v6[16];
} traffic_addr_t;

typedef struct {
	u32 tgid;
	u32 tid;
	u16 family;
	u16 lport;
	u16 rport;
	u8 protocol;
	u8 pad;
	traffic_addr_t laddr;
	traffic_addr_t raddr;
	char comm[TRAFFIC_COMM_LEN];
} traffic_flow_key_t;

typedef struct {
	u64 tx_bytes;
	u64 rx_bytes;
	u64 last_seen_ns;
} traffic_flow_value_t;

typedef struct {
	u64 pid_tgid;
	u32 operation;
	u32 pad;
} traffic_inflight_key_t;

typedef struct {
	u32 tid;
	u32 uid;
	u8 protocol;
	u8 uid_enabled;
	u16 pad;
} traffic_config_t;

#endif
