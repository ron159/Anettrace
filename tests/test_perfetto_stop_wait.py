"""Exercise Perfetto shutdown grace and file progress with a virtual clock."""
import errno
import unittest

from tests import test_flow_identity as helpers


PRELUDE = r'''
#include <assert.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#define PERFETTO_STOP_TIMEOUT_MS 30000
#define PERFETTO_STOP_IDLE_MS 3000
#define pr_info(...) ((void)0)
#define pr_warn(...) ((void)0)
#define pr_err(...) ((void)0)
#define pr_debug(...) ((void)0)

enum scenario {
    SILENT_EXIT, GROWING_EXIT, GROWING_THEN_IDLE, IDLE,
    INTERRUPTED_EXIT, WAIT_ERROR, STAT_ERROR, STAT_MISSING, STAT_TIMEOUT
};
static enum scenario scenario;
static unsigned long long elapsed_ms;
static unsigned interrupts;
static struct { pid_t perfetto_pid; char system_trace[64]; } capture = {
    .perfetto_pid = 4242, .system_trace = "/fake/system.pftrace"
};

static int fake_clock_gettime(clockid_t clock, struct timespec *value)
{
    assert(clock == CLOCK_MONOTONIC);
    /* A nonzero origin catches accidental comparisons with absolute uptime. */
    value->tv_sec = 100 + elapsed_ms / 1000;
    value->tv_nsec = (elapsed_ms % 1000) * 1000000;
    return 0;
}

static int fake_usleep(useconds_t usec)
{
    assert(usec == 100000);
    elapsed_ms += usec / 1000;
    /* A failed timeout must not hang the host test runner. */
    assert(elapsed_ms <= 60000);
    return 0;
}

static pid_t fake_waitpid(pid_t pid, int *status, int flags)
{
    assert(pid == capture.perfetto_pid && flags == WNOHANG);
    if (scenario == INTERRUPTED_EXIT && !interrupts) {
        interrupts++;
        errno = EINTR;
        return -1;
    }
    if (scenario == WAIT_ERROR && elapsed_ms >= 700) {
        errno = ECHILD;
        return -1;
    }
    if (((scenario == SILENT_EXIT || scenario == INTERRUPTED_EXIT) && elapsed_ms >= 20000) ||
        (scenario == GROWING_EXIT && elapsed_ms >= 45000)) {
        *status = 42 << 8;
        return pid;
    }
    return 0;
}

static int fake_stat(const char *path, struct stat *result)
{
    assert(!strcmp(path, capture.system_trace));
    if ((scenario == STAT_ERROR || scenario == STAT_MISSING || scenario == STAT_TIMEOUT) &&
        elapsed_ms >= 500) {
        errno = scenario == STAT_MISSING ? ENOENT :
                scenario == STAT_TIMEOUT ? ETIMEDOUT : EACCES;
        return -1;
    }
    memset(result, 0, sizeof(*result));
    result->st_size = 1024;
    if (scenario == GROWING_EXIT)
        result->st_size += elapsed_ms / 100;
    else if (scenario == GROWING_THEN_IDLE)
        result->st_size += (elapsed_ms < 35500 ? elapsed_ms : 35500) / 100;
    return 0;
}

#define clock_gettime(clock, value) fake_clock_gettime(clock, value)
#define usleep(usec) fake_usleep(usec)
#define waitpid(pid, status, flags) fake_waitpid(pid, status, flags)
#define stat(path, result) fake_stat(path, result)
'''


WRAPPER_PRELUDE = r'''
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/wait.h>
#define pr_info(...) ((void)0)
#define pr_warn(...) ((void)0)
#define pr_err(...) ((void)0)

static struct { pid_t perfetto_pid; bool child_reaped; int child_status; } capture = {
    .perfetto_pid = 4242, .child_status = -777
};
static int wait_result, wait_status = 42 << 8;
static bool wait_stalled;
static int reap_result, reap_status = SIGKILL;
static int kill_result, kill_errno;
static unsigned stop_requests, wait_requests, kill_requests, reap_requests;

static void trace_capture_stop(void) { stop_requests++; }
static int wait_perfetto_stop(int *status, bool *stalled)
{
    wait_requests++;
    *stalled = wait_stalled;
    if (!wait_result)
        *status = wait_status;
    return wait_result;
}

static int fake_kill(pid_t pid, int signal)
{
    assert(pid == capture.perfetto_pid && signal == SIGKILL);
    kill_requests++;
    errno = kill_errno;
    return kill_result;
}

static int wait_child(pid_t pid, unsigned timeout_ms, int *status)
{
    assert(pid == capture.perfetto_pid && timeout_ms == 2000);
    reap_requests++;
    if (!reap_result)
        *status = reap_status;
    return reap_result;
}

static pid_t unexpected_waitpid(pid_t pid, int *status, int flags)
{
    (void)pid; (void)status; (void)flags;
    assert(!"stop wrapper must not introduce an unbounded waitpid");
    return -1;
}
#define kill(pid, signal) fake_kill(pid, signal)
#define waitpid(pid, status, flags) unexpected_waitpid(pid, status, flags)
'''


class PerfettoStopWaitTests(unittest.TestCase):
    run_source = helpers.FlowIdentityTests.run_source

    def run_scenario(self, scenario):
        source = (helpers.ROOT / "src/trace_capture.c").read_text()
        code = PRELUDE + helpers.function(source, "wait_perfetto_stop")
        result = self.run_source(code, """
scenario = %s;
int status = -123;
bool stalled = true;
int result = wait_perfetto_stop(&status, &stalled);
printf("%%d %%llu %%d %%u %%d", result, elapsed_ms, status, interrupts, stalled);
""" % scenario)
        return tuple(map(int, result))

    def test_silent_flush_can_take_twenty_seconds_before_exit(self):
        self.assertEqual(self.run_scenario("SILENT_EXIT"),
                         (0, 20000, 42 << 8, 0, 0))

    def test_trace_still_growing_after_thirty_seconds_can_finish_at_forty_five(self):
        self.assertEqual(self.run_scenario("GROWING_EXIT"),
                         (0, 45000, 42 << 8, 0, 0))

    def test_timeout_waits_three_seconds_after_the_last_growth(self):
        self.assertEqual(self.run_scenario("GROWING_THEN_IDLE"),
                         (-errno.ETIMEDOUT, 38500, -123, 0, 1))

    def test_no_file_progress_still_gets_the_full_thirty_second_grace(self):
        self.assertEqual(self.run_scenario("IDLE"),
                         (-errno.ETIMEDOUT, 30000, -123, 0, 1))

    def test_interrupted_waitpid_retries_without_losing_child_status(self):
        self.assertEqual(self.run_scenario("INTERRUPTED_EXIT"),
                         (0, 20000, 42 << 8, 1, 0))

    def test_waitpid_error_is_reported_instead_of_becoming_a_timeout(self):
        self.assertEqual(self.run_scenario("WAIT_ERROR"),
                         (-errno.ECHILD, 700, -123, 0, 0))

    def test_failed_stat_is_reported_instead_of_counting_as_no_growth(self):
        self.assertEqual(self.run_scenario("STAT_ERROR"),
                         (-errno.EACCES, 500, -123, 0, 0))

    def test_missing_trace_path_is_an_error_instead_of_stalled_write_evidence(self):
        self.assertEqual(self.run_scenario("STAT_MISSING"),
                         (-errno.ENOENT, 500, -123, 0, 0))

    def test_stat_timeout_error_does_not_claim_the_writer_is_stalled(self):
        self.assertEqual(self.run_scenario("STAT_TIMEOUT"),
                         (-errno.ETIMEDOUT, 500, -123, 0, 0))


class PerfettoStopWrapperTests(unittest.TestCase):
    run_source = helpers.FlowIdentityTests.run_source

    def run_wrapper(self, setup):
        source = (helpers.ROOT / "src/trace_capture.c").read_text()
        code = WRAPPER_PRELUDE + helpers.function(source, "stop_perfetto")
        result = self.run_source(code, setup + r'''
int status = -123;
int result = stop_perfetto(&status);
printf("%d %d %d %d %u %u %u %u", result, status, capture.child_reaped,
       capture.child_status, stop_requests, wait_requests, kill_requests, reap_requests);
''')
        return tuple(map(int, result))

    def test_normal_exit_marks_reaped_and_preserves_the_raw_child_status(self):
        self.assertEqual(self.run_wrapper(""),
                         (0, 42 << 8, 1, 42 << 8, 1, 1, 0, 0))

    def test_stat_and_wait_errors_do_not_trigger_sigkill(self):
        for error in (errno.EACCES, errno.ECHILD, errno.ENOENT):
            with self.subTest(error=error):
                self.assertEqual(self.run_wrapper(f"wait_result = -{error};"),
                                 (-error, -123, 0, -777, 1, 1, 0, 0))

    def test_only_stalled_timeout_triggers_kill_and_a_bounded_reap(self):
        self.assertEqual(self.run_wrapper("wait_result = -ETIMEDOUT; wait_stalled = true;"),
                         (-errno.ETIMEDOUT, 9, 1, 9, 1, 1, 1, 1))

    def test_stat_timeout_error_does_not_trigger_sigkill(self):
        self.assertEqual(self.run_wrapper("wait_result = -ETIMEDOUT;"),
                         (-errno.ETIMEDOUT, -123, 0, -777, 1, 1, 0, 0))

    def test_normal_exit_racing_with_kill_can_succeed(self):
        self.assertEqual(self.run_wrapper(
            "wait_result = -ETIMEDOUT; wait_stalled = true; reap_status = 0;"),
            (0, 0, 1, 0, 1, 1, 1, 1))

    def test_already_exited_process_is_reaped_after_esrch(self):
        self.assertEqual(self.run_wrapper(
            "wait_result = -ETIMEDOUT; wait_stalled = true; reap_status = 0; "
            "kill_result = -1; kill_errno = ESRCH;"),
            (0, 0, 1, 0, 1, 1, 1, 1))

    def test_child_not_reaped_in_two_seconds_returns_without_waitpid_fallback(self):
        self.assertEqual(self.run_wrapper(
            "wait_result = -ETIMEDOUT; wait_stalled = true; reap_result = -ETIMEDOUT;"),
            (-errno.ETIMEDOUT, -123, 0, -777, 1, 1, 1, 1))


if __name__ == "__main__":
    unittest.main()
