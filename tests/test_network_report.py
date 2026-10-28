"""Report contracts exercised against real protobuf traces and Trace Processor."""
import json
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen

from perfetto.protos.perfetto.trace.perfetto_trace_pb2 import Trace, TrackEvent
from perfetto.trace_processor import TraceProcessor
from jsonschema import Draft202012Validator

from tools import network_report as report

BASE = 9007199254740993
MS = 1_000_000


def fixture(path, *, states=True, ended=True, lifecycle=True):
    trace = Trace()
    tree = trace.packet.add().process_tree
    tree.processes.add(pid=44, ppid=1, cmdline=['app'])
    tree.threads.add(tid=45, tgid=44, name='worker')
    descriptor = trace.packet.add().track_descriptor
    descriptor.uuid = 1
    descriptor.thread.pid = 44
    descriptor.thread.tid = 45
    descriptor.thread.thread_name = 'worker'

    def event(ts, dur, category, name, **args):
        packet = trace.packet.add(timestamp=BASE + ts * MS,
                                  timestamp_clock_id=6, trusted_packet_sequence_id=1)
        event = packet.track_event
        event.track_uuid = 1
        event.type = TrackEvent.TYPE_SLICE_BEGIN if dur else TrackEvent.TYPE_INSTANT
        event.categories.append(category)
        event.name = name
        for key, value in args.items():
            annotation = event.debug_annotations.add(name=key)
            if isinstance(value, bool):
                annotation.bool_value = value
            elif isinstance(value, int):
                annotation.int_value = value
            else:
                annotation.string_value = value
        if dur:
            end = trace.packet.add(timestamp=BASE + (ts + dur) * MS,
                                   timestamp_clock_id=6, trusted_packet_sequence_id=1)
            end.track_event.track_uuid = 1
            end.track_event.type = TrackEvent.TYPE_SLICE_END

    event(100, 140, 'anettrace.syscall', 'recvmsg', call_id='call-a',
          flow_id='f1', socket_id='s1', tid=45, tgid=44, result=64,
          result_unit='bytes', incomplete=False, start_clipped=False)
    event(240, 0, 'anettrace.syscall.complete', 'complete', call_id='call-a')
    event(250, 10, 'anettrace.syscall', 'sendmmsg', call_id='call-b',
          flow_id='f2', socket_id='s1', result=2, result_unit='messages')
    event(270, 20, 'anettrace.syscall', 'recvmsg', call_id='partial',
          socket_id='s2', incomplete=True)
    event(291, 2, 'anettrace.syscall', 'sendto', call_id='clipped', flow_id='0000', start_clipped=True)
    for ts, category in [(110, 'anettrace.packet'), (120, 'anettrace.packet'),
                         (110, 'anettrace.socket.packet')]:
        event(ts, 0, category, 'TCP send', flow_id='f1', socket_id='s1',
              packet_id='p1', ip_id=4660, direction='tx')
    if lifecycle:
        event(90, 205, 'anettrace.flow', 'TCP connection', flow_id='f1', socket_id='s1')
    if ended:
        event(300, 0, 'anettrace.metadata', 'trace_end', lost_events=3)
    if states:
        bundle = trace.packet.add().ftrace_events
        bundle.cpu = 0
        for ts, prev, state, nxt in [(100, 0, 0, 45), (120, 45, 0, 99),
                                      (150, 99, 1, 45), (170, 45, 1, 99),
                                      (220, 99, 0, 45), (240, 45, 1, 99)]:
            e = bundle.event.add(timestamp=BASE + ts * MS, pid=prev)
            e.sched_switch.prev_pid = prev
            e.sched_switch.prev_state = state
            e.sched_switch.prev_comm = 'worker' if prev == 45 else 'other'
            e.sched_switch.next_pid = nxt
            e.sched_switch.next_comm = 'worker' if nxt == 45 else 'other'
        e = bundle.event.add(timestamp=BASE + 200 * MS, pid=99)
        e.sched_waking.pid = 45
        e.sched_waking.comm = 'worker'
        e.sched_waking.target_cpu = 0
        ordered = sorted(bundle.event, key=lambda e: e.timestamp)
        del bundle.event[:]
        bundle.event.extend(ordered)
    path.write_bytes(trace.SerializeToString())


class NetworkReportTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.path = Path(self.tmp.name) / 'capture.pftrace'

    def test_canonical_counts_units_and_evidence(self):
        fixture(self.path)
        result = report.analyze(self.path, limit=10)
        self.assertEqual(result['schema'], 'anettrace.network-performance.v1')
        schema = json.loads((Path(__file__).resolve().parents[1] /
                             'schemas/network-performance-v1.schema.json').read_text())
        Draft202012Validator(schema).validate(result)
        self.assertEqual(result['quality']['packet_events'], 2)
        self.assertEqual(result['quality']['observed_skbs'], 1)
        self.assertEqual(result['quality']['lost_events'], 3)
        self.assertEqual(result['quality']['excluded_calls'], 2)
        self.assertEqual(len(result['slow_calls']), 2)
        self.assertEqual(result['slow_calls'][0]['call_id'], 'call-a')
        self.assertEqual(result['slow_calls'][1]['result_unit'], 'messages')
        self.assertEqual(len(result['connections']), 3)
        f1 = next(c for c in result['connections'] if c['key'] == 'flow:f1')
        self.assertEqual(f1['application_bytes'], 64)
        self.assertEqual(f1['application_rx_bytes'], 64)
        f2 = next(c for c in result['connections'] if c['key'] == 'flow:f2')
        self.assertEqual(f2['application_bytes'], 0)
        self.assertEqual(f2['completed_messages'], 2)
        with TraceProcessor(trace=str(self.path)) as tp:
            for item in result['slow_calls'] + result['connections']:
                self.assertTrue(list(tp.query(item['evidence']['sql'])))
            self.assertEqual(len(list(tp.query(result['quality']['unassociated_evidence']['sql']))), 1)
            self.assertTrue(list(tp.query(result['slow_calls'][0]['schedule']['evidence']['sql'])))
        evidence = result['slow_calls'][0]['evidence']
        self.assertEqual(evidence['ts_ns'], str(BASE + 100 * MS))
        self.assertIn('query=', evidence['perfetto_url'])

    def test_schedule_uses_clipped_states(self):
        fixture(self.path)
        schedule = report.analyze(self.path)['slow_calls'][0]['schedule']
        self.assertEqual(schedule['running_ns'], str(60 * MS))
        self.assertEqual(schedule['runnable_ns'], str(50 * MS))
        self.assertEqual(schedule['other_ns'], str(30 * MS))
        self.assertEqual(schedule['uncovered_ns'], '0')

    def test_tags_and_missing_capture_state_remain_unknown(self):
        fixture(self.path, states=False, ended=False, lifecycle=False)
        result = report.analyze(self.path, limit=1)
        self.assertIsNone(result['quality']['lost_events'])
        self.assertEqual(result['quality']['status'], 'partial')
        self.assertEqual(result['calls']['ranked_total'], 2)
        self.assertTrue(result['calls']['truncated'])
        self.assertEqual(result['slow_calls'][0]['schedule']['uncovered_ns'], str(140 * MS))
        self.assertFalse(result['connections'][0]['lifecycle_observed'])

    def test_empty_trace_is_not_successful_capture(self):
        self.path.write_bytes(Trace().SerializeToString())
        with self.assertRaisesRegex(ValueError, 'Anettrace'):
            report.analyze(self.path)

    def test_metadata_gaps_endpoints_and_unassociated_events(self):
        fixture(self.path)
        result = report.analyze(self.path)
        self.assertEqual(result['quality']['unassociated_events'], 1)
        self.assertEqual(result['quality']['metadata'][0]['name'], 'trace_end')
        self.assertEqual(result['quality']['metadata'][0]['fields']['lost_events'], 3)
        self.assertTrue(result['quality']['issues'])
        self.assertEqual(result['connections'][0]['tx_events'], 2)

    def test_mismatched_thread_identity_does_not_borrow_schedule(self):
        fixture(self.path)
        trace = Trace.FromString(self.path.read_bytes())
        for packet in trace.packet:
            for arg in packet.track_event.debug_annotations:
                if arg.name == 'tid':
                    arg.int_value = 777
        self.path.write_bytes(trace.SerializeToString())
        schedule = report.analyze(self.path)['slow_calls'][0]['schedule']
        self.assertEqual(schedule['status'], 'unavailable')
        self.assertEqual(schedule['uncovered_ns'], str(140 * MS))

    def test_html_safe_embedding_and_verified_local_trace(self):
        fixture(self.path)
        result = report.analyze(self.path)
        result['trace']['name'] = '</script><img src=x onerror=alert(1)>'
        out = Path(self.tmp.name) / 'report'
        report.write_report(result, out)
        html = (out / 'report.html').read_text()
        self.assertNotIn('</script><img', html)
        self.assertIn('\\u003c/script', html)
        self.assertEqual(json.loads((out / 'report.json').read_text())['schema'], report.SCHEMA)
        server = report.make_server(out, port=0)
        self.addCleanup(server.server_close)
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        self.addCleanup(server.shutdown)
        url = f'http://127.0.0.1:{server.server_port}'
        with urlopen(url + '/trace.pftrace') as response:
            self.assertEqual(response.read(), self.path.read_bytes())
        for route in ('/../capture.pftrace', '/report.json'):
            request = Request(url + route, headers={'Host': 'attacker.example'})
            with self.assertRaises(HTTPError) as error:
                urlopen(request)
            self.assertEqual(error.exception.code, 403)
            error.exception.close()
        self.path.write_bytes(b'changed')
        with self.assertRaises(HTTPError) as error:
            urlopen(url + '/trace.pftrace')
        self.assertEqual(error.exception.code, 409)
        error.exception.close()

    def test_server_refuses_mismatched_relocated_trace(self):
        fixture(self.path)
        out = Path(self.tmp.name) / 'report'
        report.write_report(report.analyze(self.path), out)
        moved = Path(self.tmp.name) / 'wrong.pftrace'
        moved.write_bytes(b'wrong')
        with self.assertRaisesRegex(ValueError, 'SHA-256'):
            report.make_server(out, trace=moved)

    def test_native_string_annotations_match_typed_annotations(self):
        fixture(self.path)
        trace = Trace.FromString(self.path.read_bytes())
        for packet in trace.packet:
            for arg in packet.track_event.debug_annotations:
                field = arg.WhichOneof('value')
                if field in ('int_value', 'bool_value'):
                    value = getattr(arg, field)
                    arg.ClearField(field)
                    arg.string_value = str(value).lower()
        self.path.write_bytes(trace.SerializeToString())
        result = report.analyze(self.path)
        self.assertEqual(result['calls']['ranked_total'], 2)
        self.assertEqual(result['quality']['lost_events'], 3)
        self.assertEqual(result['slow_calls'][0]['result'], 64)

    def test_multiple_capture_ends_do_not_overwrite_earlier_loss(self):
        fixture(self.path)
        trace = Trace.FromString(self.path.read_bytes())
        end = next(p for p in trace.packet if p.track_event.name == 'trace_end')
        extra = trace.packet.add()
        extra.CopyFrom(end)
        extra.timestamp += MS
        extra.track_event.debug_annotations[0].int_value = 0
        self.path.write_bytes(trace.SerializeToString())
        quality = report.analyze(self.path)['quality']
        self.assertIsNone(quality['lost_events'])
        self.assertEqual(quality['status'], 'degraded')

    def test_interrupted_capture_preserves_observed_loss(self):
        fixture(self.path, ended=False)
        trace = Trace.FromString(self.path.read_bytes())
        packet = trace.packet.add(timestamp=BASE+300*MS, timestamp_clock_id=6,
                                  trusted_packet_sequence_id=1)
        packet.track_event.track_uuid = 1
        packet.track_event.type = TrackEvent.TYPE_INSTANT
        packet.track_event.name = 'lost_events'
        packet.track_event.categories.append('anettrace.metadata')
        packet.track_event.debug_annotations.add(name='count', string_value='7')
        self.path.write_bytes(trace.SerializeToString())
        quality = report.analyze(self.path)['quality']
        self.assertIsNone(quality['lost_events'])
        self.assertEqual(quality['observed_loss_notifications'], 7)
        self.assertEqual(quality['status'], 'degraded')
