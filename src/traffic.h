// SPDX-License-Identifier: MulanPSL-2.0

#ifndef _H_TRAFFIC
#define _H_TRAFFIC

#include "trace.h"

int traffic_start(trace_args_t *args, bpf_args_t *bpf_args);
bool traffic_poll(void);
void traffic_stop(bool final_report);
int traffic_run(trace_args_t *args, bpf_args_t *bpf_args);

#endif
