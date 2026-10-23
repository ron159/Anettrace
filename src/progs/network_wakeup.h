// SPDX-License-Identifier: MulanPSL-2.0
#ifndef _H_NETWORK_WAKEUP
#define _H_NETWORK_WAKEUP

/* Standard tracepoint prefixes. sched_wakeup's optional success/target_cpu
 * suffix varies between kernels and is intentionally not consumed. */
typedef struct {
	u16 type;
	u8 flags;
	u8 preempt_count;
	s32 common_pid;
	char comm[16];
	s32 pid;
	s32 prio;
} network_sched_wakeup_ctx_t;

typedef struct {
	u16 type;
	u8 flags;
	u8 preempt_count;
	s32 common_pid;
	char prev_comm[16];
	s32 prev_pid;
	s32 prev_prio;
	long prev_state;
	char next_comm[16];
	s32 next_pid;
} network_sched_switch_ctx_t;

typedef struct {
	u64 task_start_time;
	u32 tgid;
	u64 waking_ts;
	u64 wakeup_ts;
	u64 run_start_ts;
	u64 waker_start_time;
	u32 waker_tid;
	u32 waker_tgid;
	u32 waking_cpu;
	u32 run_cpu;
	u8 waking_context;
	u8 waking_flags;
	char waker_task[16];
} network_wakeup_state_t;

/* Scope-filtered and bounded. Eviction makes evidence unknown rather than
 * borrowing another task's history. No global scheduling stream is exported. */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 16384);
	__type(key, u32);
	__type(value, network_wakeup_state_t);
} m_network_wakeups SEC(".maps");

static __always_inline network_wakeup_state_t *
network_wakeup_current(bpf_args_t *args)
{
	u64 task_id = bpf_get_current_pid_tgid();
	u32 tid = task_id, tgid = task_id >> 32;
	u32 uid = bpf_get_current_uid_gid();
	struct task_struct *task = (void *)bpf_get_current_task();
	network_wakeup_state_t *state;
	u64 birth;

	if (!perfetto_current_matches(args, tid, uid))
		return NULL;
	birth = _C(task, start_time);
	if (!tid || !birth)
		return NULL;
	state = bpf_map_lookup_elem(&m_network_wakeups, &tid);
	if (!state || state->task_start_time != birth || state->tgid != tgid) {
		network_wakeup_state_t fresh = {
			.task_start_time = birth,
			.tgid = tgid,
		};
		if (bpf_map_update_elem(&m_network_wakeups, &tid, &fresh, BPF_ANY))
			return NULL;
		state = bpf_map_lookup_elem(&m_network_wakeups, &tid);
	}
	return state;
}

/* End every running segment, including preemption. A later resumption with
 * no fresh successful wake is not represented as a new wake edge. */
static __always_inline void network_wakeup_clear(network_wakeup_state_t *state)
{
	state->waking_ts = 0;
	state->wakeup_ts = 0;
	state->run_start_ts = 0;
	state->waker_start_time = 0;
	state->waker_tid = 0;
	state->waker_tgid = 0;
	state->waking_cpu = 0;
	state->run_cpu = 0;
	state->waking_context = 0;
	state->waking_flags = 0;
	__builtin_memset(state->waker_task, 0, sizeof(state->waker_task));
}

SEC("tp/sched/sched_waking")
int TRACE_NAME(network_sched_waking)(network_sched_wakeup_ctx_t *ctx)
{
	bpf_args_t *args = (void *)CONFIG();
	u32 target = _(ctx->pid);
	network_wakeup_state_t *state;
	u8 flags;

	if (!args->ready || !args->perfetto || !args->wakeup_chain)
		return 0;
	state = bpf_map_lookup_elem(&m_network_wakeups, &target);
	if (!state)
		return 0;
	network_wakeup_clear(state);
	state->waking_ts = bpf_ktime_get_ns();
	state->waking_cpu = bpf_get_smp_processor_id();
	flags = _(ctx->flags);
	state->waking_flags = flags;
	/* Linux trace_entry flags: NMI 0x40, HARDIRQ 0x08, SOFTIRQ 0x10.
	 * IRQ-disabled alone does not mean interrupt context. */
	if (flags & 0x40)
		state->waking_context = 4;
	else if (flags & 0x08)
		state->waking_context = 2;
	else if (flags & 0x10)
		state->waking_context = 3;
	else {
		struct task_struct *task = (void *)bpf_get_current_task();
		u64 task_id = bpf_get_current_pid_tgid();
		u64 birth = _C(task, start_time);
		if ((u32)task_id && birth) {
			state->waking_context = 1;
			state->waker_tid = task_id;
			state->waker_tgid = task_id >> 32;
			state->waker_start_time = birth;
			bpf_get_current_comm(state->waker_task, sizeof(state->waker_task));
		}
	}
	return 0;
}

SEC("tp/sched/sched_wakeup")
int TRACE_NAME(network_sched_wakeup)(network_sched_wakeup_ctx_t *ctx)
{
	bpf_args_t *args = (void *)CONFIG();
	u32 target = _(ctx->pid);
	network_wakeup_state_t *state;

	if (!args->ready || !args->perfetto || !args->wakeup_chain)
		return 0;
	state = bpf_map_lookup_elem(&m_network_wakeups, &target);
	/* sched_wakeup means TASK_RUNNING, but may execute on a remote CPU:
	 * its current task must never replace the sched_waking context. */
	if (state && state->waking_ts && !state->run_start_ts)
		state->wakeup_ts = bpf_ktime_get_ns();
	return 0;
}

SEC("tp/sched/sched_switch")
int TRACE_NAME(network_sched_switch)(network_sched_switch_ctx_t *ctx)
{
	bpf_args_t *args = (void *)CONFIG();
	u32 prev = _(ctx->prev_pid), next = _(ctx->next_pid);
	network_wakeup_state_t *state;

	if (!args->ready || !args->perfetto || !args->wakeup_chain)
		return 0;
	/* At this tracepoint current is prev, so only prev's task generation
	 * can be established reliably. First-seen next tasks stay unknown. */
	if (prev == (u32)bpf_get_current_pid_tgid()) {
		state = network_wakeup_current(args);
		if (state)
			network_wakeup_clear(state);
	}
	state = bpf_map_lookup_elem(&m_network_wakeups, &next);
	if (state) {
		state->run_start_ts = bpf_ktime_get_ns();
		state->run_cpu = bpf_get_smp_processor_id();
	}
	return 0;
}

static __always_inline int network_wakeup_snapshot(network_syscall_event_t *event)
{
	bpf_args_t *args = (void *)CONFIG();
	network_wakeup_state_t *state;

	if (!args->ready || !args->perfetto || !args->wakeup_chain)
		return 0;
	event->wakeup_status = 1;
	state = network_wakeup_current(args);
	if (!state || !state->run_start_ts || state->run_start_ts > event->start_ts)
		return 0;
	event->wakeup_status = 3;
	event->run_start_ts = state->run_start_ts;
	event->run_cpu = state->run_cpu;
	if (!state->waking_ts || state->wakeup_ts < state->waking_ts ||
	    state->run_start_ts < state->wakeup_ts)
		return 0;
	event->wakeup_status = 2;
	event->waking_ts = state->waking_ts;
	event->wakeup_ts = state->wakeup_ts;
	event->waker_start_time = state->waker_start_time;
	event->waker_tid = state->waker_tid;
	event->waker_tgid = state->waker_tgid;
	event->waking_cpu = state->waking_cpu;
	event->waking_context = state->waking_context;
	event->waking_flags = state->waking_flags;
	__builtin_memcpy(event->waker_task, state->waker_task, sizeof(event->waker_task));
	return 0;
}

#endif
