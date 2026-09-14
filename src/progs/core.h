#ifndef _H_PROG_CORE
#define _H_PROG_CORE

typedef struct {
	u16 func1;
	u16 func2;
	u32 ts1;
	u32 ts2;
} match_val_t;

typedef struct {
	/* the bpf context args */
	void *ctx;
	struct sk_buff *skb;
	struct sock *sk;
	event_t *e;
	/* the filter condition stored in map */
	bpf_args_t *args;
	union {
		/* used by fexit to pass the retval to event */
		u64 retval;
		/* match only used in context mode, no conflict with retval */
		match_val_t match_val;
		u32 matched;
	};
	u16 func;
	u8  func_status;
	/* don't output the event for this skb */
	u8  no_event:1;
	/* fexit events use the same payload but a distinct userspace type. */
	u8  is_return:1;
} context_info_t;

/* init the skb by the index of func args */
#define DEFINE_KPROBE_SKB(name, skb_index, arg_count)		\
	DEFINE_KPROBE_INIT(name, name, arg_count,		\
			   .skb = ctx_get_arg(ctx, skb_index))

/* Keep both ordinary and extended event payloads off the 512-byte BPF
 * call-chain stack. Initialize the whole record to avoid stale map bytes. */
#define DECLARE_EVENT(type, name) \
	pure_##type __attribute__((__unused__)) *name; \
	int name##_size; \
	const int name##_full_size __attribute__((__unused__)) = sizeof(detail_##type); \
	_Static_assert(sizeof(detail_##type) <= MAX_EVENT_SIZE, "event buffer too small"); \
	info->e = trace_event_buffer(); \
	if (!info->e) \
		return -1; \
	__builtin_memset(info->e, 0, sizeof(detail_##type)); \
	if (info->args->detail) { \
		name##_size = sizeof(detail_##type); \
		name = (void *)info->e + offsetof(detail_##type, __event_filed); \
	} else { \
		name##_size = sizeof(type); \
		name = (void *)info->e + offsetof(type, __event_filed); \
	}

#if (defined(BPF_NO_GLOBAL_DATA) || defined(__F_INIT_EVENT)) && defined(__F_OUTPUT_WHOLE)
#define handle_event_output(info, e) do_event_output(info, e##_full_size)
#else
#define handle_event_output(info, e) do_event_output(info, e##_size)
#endif

#define handle_entry_output(info, e)		\
({						\
	int err = handle_entry(info);		\
	if (!err)				\
		handle_event_output(info, e);	\
	err;					\
})

#endif
