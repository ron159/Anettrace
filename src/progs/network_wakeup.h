// SPDX-License-Identifier: MulanPSL-2.0
#ifndef _H_NETWORK_WAKEUP
#define _H_NETWORK_WAKEUP

/* Standard tracepoint payloads. The first eight bytes are reserved: perf
 * replaces trace_entry with a pt_regs pointer before calling BPF programs.
 * sched_wakeup's optional success/target_cpu suffix is not consumed. */
typedef struct {
	u64 reserved;
	char comm[16];
	s32 pid;
	s32 prio;
} network_sched_wakeup_ctx_t;

typedef struct {
	u64 reserved;
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
	u32 waking_preempt_count;
	u8 waking_context;
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

#ifndef NO_BTF
extern int LINUX_KERNEL_VERSION __kconfig;

struct task_struct___wakeup_rt {
	int softirq_disable_cnt;
} __attribute__((preserve_access_index));

#if defined(__TARGET_ARCH_x86)
extern const int __preempt_count __ksym __weak;
struct pcpu_hot___wakeup {
	int preempt_count;
} __attribute__((preserve_access_index));
extern struct pcpu_hot___wakeup pcpu_hot __ksym __weak;
#endif
#endif

/* Follow the kernel's in_task()/in_serving_softirq() semantics. Merely having
 * IRQs or BHs disabled is still task context. Unknown layouts/read failures
 * must not attribute an interrupt to the task it interrupted.
 * See Linux tools/testing/selftests/bpf/bpf_experimental.h:get_preempt_count.
 */
static __always_inline u8 network_wakeup_context(u32 *raw_count)
{
#ifndef NO_BTF
	struct task_struct *task = (void *)bpf_get_current_task();
	struct task_struct___wakeup_rt *rt_task = (void *)task;
	u32 count = 0, softirq_count;

	/* Verified through Linux 6.18. Newer kernels move the hardirq/NMI
	 * bits to make room for hardirq-disable nesting. Do not guess. */
	if (LINUX_KERNEL_VERSION >= (7 << 16))
		return 0;
#if defined(__TARGET_ARCH_x86)
	if (!bpf_core_enum_value_exists(enum bpf_func_id, BPF_FUNC_this_cpu_ptr))
		return 0;
	if (bpf_ksym_exists(&__preempt_count)) {
		const void *ptr = bpf_this_cpu_ptr(&__preempt_count);
		if (bpf_probe_read_kernel(&count, sizeof(count), ptr))
			return 0;
	} else if (bpf_ksym_exists(&pcpu_hot) &&
		   bpf_core_field_exists(pcpu_hot.preempt_count)) {
		struct pcpu_hot___wakeup *hot = bpf_this_cpu_ptr(&pcpu_hot);
		if (_LC(&count, hot, preempt_count))
			return 0;
	} else {
		return 0;
	}
#elif defined(__TARGET_ARCH_arm64)
	if (!bpf_core_field_exists(task->thread_info.preempt.count) ||
	    _LC(&count, task, thread_info.preempt.count))
		return 0;
#elif defined(__TARGET_ARCH_loongarch)
	if (!bpf_core_field_exists(task->thread_info.preempt_count) ||
	    _LC(&count, task, thread_info.preempt_count))
		return 0;
#else
	return 0;
#endif
	/* Exclude PREEMPT_NEED_RESCHED, but reject unfamiliar high bits. */
	if (count & 0x7f000000U)
		return 0;
	softirq_count = count;
	if (bpf_core_field_exists(rt_task->softirq_disable_cnt) &&
	    _LC(&softirq_count, rt_task, softirq_disable_cnt))
		return 0;
	*raw_count = count;
	if (count & 0x00f00000U)
		return 4;
	if (count & 0x000f0000U)
		return 2;
	if (softirq_count & 0x00000100U)
		return 3;
	return 1;
#else
	(void)raw_count;
	return 0;
#endif
}

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
	state->waking_preempt_count = 0;
	__builtin_memset(state->waker_task, 0, sizeof(state->waker_task));
}

SEC("tp/sched/sched_waking")
int TRACE_NAME(network_sched_waking)(network_sched_wakeup_ctx_t *ctx)
{
	bpf_args_t *args = (void *)CONFIG();
	u32 target = _(ctx->pid);
	network_wakeup_state_t *state;

	if (!args->ready || !args->perfetto || !args->wakeup_chain)
		return 0;
	state = bpf_map_lookup_elem(&m_network_wakeups, &target);
	if (!state)
		return 0;
	network_wakeup_clear(state);
	state->waking_ts = bpf_ktime_get_ns();
	state->waking_cpu = bpf_get_smp_processor_id();
	state->waking_context = network_wakeup_context(&state->waking_preempt_count);
	if (state->waking_context == 1) {
		struct task_struct *task = (void *)bpf_get_current_task();
		u64 task_id = bpf_get_current_pid_tgid();
		u64 birth = _C(task, start_time);
		if ((u32)task_id && birth) {
			state->waking_context = 1;
			state->waker_tid = task_id;
			state->waker_tgid = task_id >> 32;
			state->waker_start_time = birth;
			bpf_get_current_comm(state->waker_task, sizeof(state->waker_task));
		} else {
			state->waking_context = 0;
			state->waking_preempt_count = 0;
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
	event->waking_preempt_count = state->waking_preempt_count;
	__builtin_memcpy(event->waker_task, state->waker_task, sizeof(event->waker_task));
	return 0;
}

#endif
