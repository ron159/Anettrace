"""Resolve actual trace selections without silently choosing duplicate symbols."""
import errno
import unittest

from tests import test_flow_identity as helpers

function = helpers.function
ROOT = helpers.ROOT


class ProbeSelectionTests(unittest.TestCase):
    run_source = helpers.FlowIdentityTests.run_source

    def helpers(self):
        source = (ROOT / 'src/trace.c').read_text()
        prelude = r'''
#include <errno.h>
#define TRACE_ENABLE (1U << 1)
#define TRACE_INVALID (1U << 2)
#define TRACE_ATTACH_MANUAL (1U << 5)
#define TRACE_EXPLICIT (1U << 8)
#define TRACE_SYMBOL_AMBIGUOUS (1U << 9)
#define TRACE_MODE_BPF_CTX_MASK 0
enum { SYM_NOT_EXIST, SYM_MODULE, SYM_KERNEL, SYM_AMBIGUOUS };
typedef struct { char name[64]; const char *tp, *prog, *desc;
    unsigned status; bool is_func; } trace_t;
static trace_t traces[2];
static unsigned warnings, errors, prepared;
static void prepare(void) { prepared++; }
static struct { void (*prepare_traces)(void); } ops = {prepare};
static struct { int mode; typeof(ops) *ops; } trace_ctx = {.ops=&ops};
#define trace_for_each(t) for (t=traces; t<traces+2; t++)
#define pr_debug(...) ((void)0)
#define pr_verb(...) ((void)0)
#define pr_warn(...) ((void)warnings++)
#define pr_err(...) ((void)errors++)
static const char *get_tracing_path(void) { return "/sys/kernel/tracing"; }
static bool file_exist(const char *path) { return true; }
static bool trace_is_invalid(trace_t *t) { return t->status & TRACE_INVALID; }
static bool trace_is_enable(trace_t *t) { return t->status & TRACE_ENABLE; }
static bool trace_is_func(trace_t *t) { return t->is_func; }
static void trace_set_invalid_reason(trace_t *t, const char *reason) {
    t->status |= TRACE_INVALID;
}
static void trace_set_invalid(trace_t *t) { t->status |= TRACE_INVALID; }
static void trace_group_enable(const char *name, int target) {}
static void trace_exec_cond(void) {}
static void trace_prepare_status(void) {}
/* The symbol service has its own fixture-backed parser tests. Here it
 * supplies controlled uniqueness results to the real trace selection. */
static int sym_search_unique(const char *name, char *out, size_t size, bool partial) {
    const char *resolved = name;
    if (!strcmp(name, "missing") || !strcmp(name, "missing.")) return SYM_NOT_EXIST;
    if (!strcmp(name, "cloned") || !strcmp(name, "many")) return SYM_NOT_EXIST;
    if (!strcmp(name, "ambiguous") || !strcmp(name, "many.")) return SYM_AMBIGUOUS;
    if (!strcmp(name, "cloned.")) resolved = "cloned.isra.0";
    snprintf(out, size, "%s", resolved);
    return SYM_KERNEL;
}
static int sym_get_type(const char *name) {
    char out[64];
    int result=sym_search_unique(name,out,sizeof(out),false);
    return result==SYM_AMBIGUOUS ? SYM_KERNEL : result;
}
static int sym_search_pattern(const char *name, char *out, bool partial) {
    int result=sym_search_unique(name,out,64,partial);
    if (result==SYM_AMBIGUOUS) { strcpy(out,"many.isra.0"); return SYM_KERNEL; }
    return result;
}
static int trace_set_target(trace_t *t, int target) {
    if (target==1) t->status |= TRACE_ENABLE;
    return 0;
}
'''
        if 'static int trace_resolve_symbol(' in source:
            prelude += function(source, 'trace_resolve_symbol')
        return prelude + function(source, 'trace_prepare_traces')

    def selected(self, name, explicit=False):
        body = r'''
traces[0]=(trace_t){.name="ip_output",.status=TRACE_ENABLE,.is_func=true};
traces[1]=(trace_t){.status=TRACE_ENABLE,.is_func=true};
''' + f'strcpy(traces[1].name,"{name}");\n'
        if explicit:
            body += 'traces[1].status |= TRACE_EXPLICIT;\n'
        body += r'''
int result=trace_prepare_traces();
printf("%d %u %u %u %d %d %s", result,warnings,errors,prepared,
       !!(traces[0].status & TRACE_INVALID),
       !!(traces[1].status & TRACE_INVALID),traces[1].name);
printf(" %d %d", !!(traces[1].status & TRACE_SYMBOL_AMBIGUOUS),
       !!(traces[1].status & TRACE_ATTACH_MANUAL));
'''
        return self.run_source(self.helpers(), body)

    def test_optional_duplicate_is_skipped_and_other_probes_remain_usable(self):
        self.assertEqual(self.selected('ambiguous'),
                         ['0','1','0','1','0','1','ambiguous','1','0'])

    def test_unique_symbol_keeps_existing_selection(self):
        self.assertEqual(self.selected('unique'),
                         ['0','0','0','1','0','0','unique','0','0'])

    def test_unique_compiler_suffix_uses_manual_attach(self):
        self.assertEqual(self.selected('cloned'),
                         ['0','0','0','1','0','0','cloned.isra.0','0','1'])

    def test_multiple_compiler_suffixes_are_not_arbitrarily_selected(self):
        self.assertEqual(self.selected('many'),
                         ['0','1','0','1','0','1','many','1','0'])

    def test_explicit_duplicate_fails_before_backend_preparation(self):
        self.assertEqual(self.selected('ambiguous', True),
                         [str(-errno.EADDRNOTAVAIL),'0','1','0','0','1','ambiguous','1','0'])

    def test_explicit_missing_symbol_fails(self):
        self.assertEqual(self.selected('missing', True),
                         [str(-2),'0','1','0','0','1','missing','0','0'])

    def test_optional_missing_symbol_preserves_legacy_skip(self):
        self.assertEqual(self.selected('missing'),
                         ['0','0','0','1','0','1','missing','0','0'])

    def test_named_user_selection_is_marked_explicit(self):
        source=(ROOT/'src/trace.c').read_text()
        result=self.run_source(self.helpers()+function(source,'trace_enable'), r'''
traces[0]=(trace_t){.name="ambiguous",.is_func=true};
printf("%d ",trace_enable("ambiguous",1));
printf("%d",!!(traces[0].status & TRACE_EXPLICIT));
''')
        self.assertEqual(result,['0','1'])


if __name__ == '__main__':
    unittest.main()
