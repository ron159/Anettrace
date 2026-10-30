"""Exercise the real capture queue with a deliberately blocked exporter."""
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

SOURCE = r'''
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "capture_queue.h"

static pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t changed = PTHREAD_COND_INITIALIZER;
static int blocked, entered, released, producer_done;
static unsigned delivered, expected, ticks;
static unsigned long long kernel_lost, queue_lost;

static void wait_for(int *flag)
{
    struct timespec deadline;
    assert(!clock_gettime(CLOCK_REALTIME, &deadline));
    deadline.tv_sec += 3;
    while (!*flag)
        assert(!pthread_cond_timedwait(&changed, &lock, &deadline));
}

static void fill(unsigned char *data, unsigned size, unsigned id)
{
    memset(data, (unsigned char)(id + 17), size);
    memcpy(data, &id, sizeof(id));
}

void perfetto_export_event(const void *data, int cpu, __u32 size)
{
    unsigned id;
    const unsigned char *bytes = data;

    assert(!pthread_mutex_lock(&lock));
    if (blocked && !entered) {
        entered = 1;
        assert(!pthread_cond_broadcast(&changed));
        wait_for(&released);
    }
    assert(size >= sizeof(id));
    memcpy(&id, data, sizeof(id));
    assert(id == expected++);
    assert(cpu == (int)(id % 8));
    for (unsigned i = sizeof(id); i < size; i++)
        assert(bytes[i] == (unsigned char)(id + 17));
    delivered++;
    assert(!pthread_cond_broadcast(&changed));
    assert(!pthread_mutex_unlock(&lock));
}

void perfetto_export_lost(int cpu, __u64 count)
{
    (void)cpu;
    assert(!pthread_mutex_lock(&lock));
    kernel_lost += count;
    assert(!pthread_mutex_unlock(&lock));
}

void perfetto_export_queue_lost(__u64 count)
{
    assert(!pthread_mutex_lock(&lock));
    queue_lost += count;
    assert(!pthread_mutex_unlock(&lock));
}

void perfetto_export_tick(void)
{
    assert(!pthread_mutex_lock(&lock));
    ticks++;
    assert(!pthread_cond_broadcast(&changed));
    assert(!pthread_mutex_unlock(&lock));
}

static void *produce(void *unused)
{
    unsigned char sample[128];
    (void)unused;
    for (unsigned id = 1; id <= 100; id++) {
        fill(sample, sizeof(sample), id);
        capture_queue_event(sample, id % 8, sizeof(sample));
        /* Each call must retain its own bytes before returning. */
        memset(sample, 0xff, sizeof(sample));
    }
    /* Report kernel losses even when the queue is already full. */
    capture_queue_lost(2, 7);
    capture_queue_lost(5, 11);
    capture_queue_tick();
    assert(!pthread_mutex_lock(&lock));
    producer_done = 1;
    assert(!pthread_cond_broadcast(&changed));
    assert(!pthread_mutex_unlock(&lock));
    return NULL;
}

static void slow_exporter(void)
{
    pthread_t producer;
    unsigned char sample[128];

    assert(!capture_queue_start(512));
    blocked = 1;
    fill(sample, sizeof(sample), 0);
    capture_queue_event(sample, 0, sizeof(sample));
    assert(!pthread_mutex_lock(&lock));
    wait_for(&entered);
    assert(!pthread_mutex_unlock(&lock));
    memset(sample, 0xff, sizeof(sample));
    assert(!pthread_create(&producer, NULL, produce, NULL));
    assert(!pthread_mutex_lock(&lock));
    /* A producer that waits for export or for space deadlocks here. */
    wait_for(&producer_done);
    released = 1;
    assert(!pthread_cond_broadcast(&changed));
    assert(!pthread_mutex_unlock(&lock));
    assert(!pthread_join(producer, NULL));
    capture_queue_stop();
    assert(delivered > 1 && delivered < 101);
    assert(delivered + queue_lost == 101);
    assert(kernel_lost == 18);
}

static void immediate_stop(void)
{
    unsigned char sample[128];
    assert(!capture_queue_start(32768));
    for (unsigned id = 0; id < 100; id++) {
        fill(sample, sizeof(sample), id);
        capture_queue_event(sample, id % 8, sizeof(sample));
        memset(sample, 0xff, sizeof(sample));
    }
    capture_queue_lost(3, 23);
    capture_queue_stop();
    assert(delivered == 100 && !queue_lost && kernel_lost == 23);
}

static void wrap_and_reuse(void)
{
    unsigned char sample[257];
    for (unsigned session = 0; session < 3; session++) {
        assert(!capture_queue_start(512));
        for (unsigned n = 0; n < 40; n++) {
            unsigned id = session * 40 + n;
            unsigned size = n % 2 ? 257 : 31;
            fill(sample, size, id);
            capture_queue_event(sample, id % 8, size);
            memset(sample, 0xff, sizeof(sample));
            assert(!pthread_mutex_lock(&lock));
            struct timespec deadline;
            assert(!clock_gettime(CLOCK_REALTIME, &deadline));
            deadline.tv_sec += 3;
            while (delivered <= id)
                assert(!pthread_cond_timedwait(&changed, &lock, &deadline));
            assert(!pthread_mutex_unlock(&lock));
        }
        capture_queue_tick();
        capture_queue_stop();
    }
    assert(delivered == 120 && !queue_lost && !kernel_lost);
    assert(ticks >= 3);
    capture_queue_stop();
}

int main(int argc, char **argv)
{
    assert(argc == 2);
    if (!strcmp(argv[1], "slow"))
        slow_exporter();
    else if (!strcmp(argv[1], "stop"))
        immediate_stop();
    else if (!strcmp(argv[1], "wrap"))
        wrap_and_reuse();
    else
        abort();
    puts("ok");
    return 0;
}
'''


class CaptureQueueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        root = Path(cls.tmp.name)
        # The queue uses only fixed-width Linux ABI types on macOS hosts.
        (root / "linux").mkdir()
        (root / "linux/types.h").write_text(
            "#pragma once\n#include <stdint.h>\n"
            "typedef uint32_t __u32;\ntypedef uint64_t __u64;\n")
        cfile = root / "capture_queue_test.c"
        cls.binary = root / "capture_queue_test"
        cfile.write_text(SOURCE)
        compiled = subprocess.run(
            ["cc", "-std=gnu11", "-Wall", "-Wextra", "-Werror", "-pthread",
             "-I", str(root), "-I", str(ROOT / "src"), str(cfile),
             str(ROOT / "src/capture_queue.c"), "-o", str(cls.binary)],
            text=True, capture_output=True)
        if compiled.returncode:
            raise AssertionError(compiled.stderr)

    def run_case(self, case):
        result = subprocess.run([str(self.binary), case], capture_output=True,
                                text=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "ok\n")

    def test_slow_exporter_does_not_block_capture_and_loss_is_counted(self):
        self.run_case("slow")

    def test_stop_drains_queued_samples_and_kernel_loss(self):
        self.run_case("stop")

    def test_ring_wrap_preserves_bytes_and_sessions_can_restart(self):
        self.run_case("wrap")


if __name__ == "__main__":
    unittest.main()
