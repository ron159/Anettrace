"""Validate both supported attribution and the existing unknown-layout contract."""
import unittest

from tests.wakeup_trace_integration import validate_wakeup_calls

IDENTITY = {'waker_tid': 8, 'tgid': 7}


def calls(context='task'):
    call = dict(wakeup_status='observed', waking_context=context,
                waking_ts_ns=10, wakeup_ts_ns=11, run_start_ts_ns=15, start_ts_ns=20)
    if context == 'task':
        call.update(waker_tid=8, waker_tgid=7, waker_start_time_ns=1,
                    waking_preempt_count=2, waker_task='waker')
    return [call.copy() for _ in range(24)]


class WakeupIntegrationValidationTest(unittest.TestCase):
    def test_supported_kernel_still_requires_observed_task_identity(self):
        validate_wakeup_calls(calls(), IDENTITY, True, 6)
        with self.assertRaises(AssertionError):
            validate_wakeup_calls(calls('unknown'), IDENTITY, True, 6)

    def test_new_kernel_preserves_real_timestamps_without_attribution(self):
        validate_wakeup_calls(calls('unknown'), IDENTITY, True, 7)

    def test_new_kernel_rejects_fabricated_identity_or_raw_count(self):
        for field, value in [('waker_tid', 8), ('waker_tgid', 7),
                             ('waker_start_time_ns', 1), ('waker_task', 'waker'),
                             ('waking_preempt_count', 0)]:
            with self.subTest(field=field):
                records = calls('unknown')
                records[0][field] = value
                with self.assertRaises(AssertionError):
                    validate_wakeup_calls(records, IDENTITY, True, 7)

    def test_new_kernel_rejects_missing_wake_evidence(self):
        records = calls('unknown')
        for call in records:
            call['wakeup_status'] = 'unknown'
            del call['waking_ts_ns']
        with self.assertRaises(AssertionError):
            validate_wakeup_calls(records, IDENTITY, True, 7)

    def test_new_kernel_rejects_inconsistent_timestamp_order(self):
        records = calls('unknown')
        records[0]['wakeup_ts_ns'] = 30
        with self.assertRaises(AssertionError):
            validate_wakeup_calls(records, IDENTITY, True, 7)

    def test_disabled_capture_still_rejects_scheduler_annotations(self):
        validate_wakeup_calls([{} for _ in range(24)], IDENTITY, False, 7)
        with self.assertRaises(AssertionError):
            validate_wakeup_calls(calls('unknown'), IDENTITY, False, 7)
