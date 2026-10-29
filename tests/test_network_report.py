"""Report contracts exercised against real protobuf traces and Trace Processor."""
import json
import shutil
import subprocess
from pathlib import Path
import tempfile
import threading
import unittest
from urllib.error import HTTPError
from urllib.request import Request, urlopen
from urllib.parse import parse_qs, urlsplit

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


def filter_fixture(path):
    fixture(path)
    trace = Trace.FromString(path.read_bytes())
    for packet in trace.packet:
        event = packet.track_event
        category = event.categories[0] if event.categories else ''
        args = {a.name: a.string_value for a in event.debug_annotations}
        extra = {}
        if category == 'anettrace.syscall':
            extra['uid'] = 1002 if args.get('call_id') == 'call-b' else 1001
            if args.get('call_id') == 'call-b':
                extra.update(protocol='udp', remote_addr='203.0.113.2', remote_port=53)
        if category.startswith('anettrace.packet'):
            extra.update(uid=0, owner_uid=1001, owner_tid=45, owner_tgid=44,
                         owner_valid=True, proto_l4=6, saddr='192.0.2.1',
                         daddr='198.51.100.2', sport=12345, dport=443)
        if category == 'anettrace.flow':
            extra.update(protocol='tcp', owner_uid=1001, owner_tid=45, owner_tgid=44,
                         flow_tag='tcp-1')
        for name, value in extra.items():
            arg = event.debug_annotations.add(name=name)
            if isinstance(value, bool): arg.bool_value = value
            elif isinstance(value, int): arg.int_value = value
            else: arg.string_value = value
    path.write_bytes(trace.SerializeToString())


class NetworkReportTest(unittest.TestCase):
    def test_unavailable_probe_metadata_degrades_capture_quality(self):
        fixture(self.path)
        trace = Trace()
        trace.ParseFromString(self.path.read_bytes())
        for packet in trace.packet:
            if packet.HasField('track_event') and packet.track_event.name == 'trace_end':
                for arg in packet.track_event.debug_annotations:
                    if arg.name == 'lost_events':
                        arg.int_value = 0
        packet = trace.packet.add(timestamp=BASE + 299 * MS,
                                  timestamp_clock_id=6, trusted_packet_sequence_id=1)
        event = packet.track_event
        event.track_uuid = 1
        event.type = TrackEvent.TYPE_INSTANT
        event.categories.append('anettrace.metadata')
        event.name = 'probe_status'
        for key, value in dict(probe='xfrm4_policy_check', status='unavailable',
                               reason='ambiguous_symbol', coverage='degraded').items():
            event.debug_annotations.add(name=key, string_value=value)
        self.path.write_bytes(trace.SerializeToString())
        result = report.analyze(self.path)
        self.assertEqual(result['quality']['status'], 'degraded')
        self.assertTrue(any('xfrm4_policy_check' in issue and 'ambiguous_symbol' in issue
                            for issue in result['quality']['issues']))

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
        self.assertIn('ts=', evidence['perfetto_url'])

    def test_schedule_uses_clipped_states(self):
        fixture(self.path)
        schedule = report.analyze(self.path)['slow_calls'][0]['schedule']
        self.assertEqual(schedule['running_ns'], str(60 * MS))
        self.assertEqual(schedule['runnable_ns'], str(50 * MS))
        self.assertEqual(schedule['other_ns'], str(30 * MS))
        self.assertEqual(schedule['uncovered_ns'], '0')

    def test_uid_filters_before_ranking_limit_and_keeps_global_quality(self):
        filter_fixture(self.path)
        result = report.analyze(self.path, limit=1, filters={'uids': [1002]})
        self.assertEqual(result['slow_calls'][0]['call_id'], 'call-b')
        self.assertEqual(result['slow_calls'][0]['app_uid'], 1002)
        self.assertEqual(result['calls']['ranked_total'], 1)
        self.assertFalse(result['calls']['truncated'])
        self.assertEqual(result['quality']['calls'], 4)
        self.assertEqual(result['quality']['packet_events'], 2)
        self.assertEqual(result['scope']['packet_events'], 0)
        self.assertEqual({c['key'] for c in result['connections']}, {'flow:f2'})
        self.assertEqual({u['value'] for u in result['inventory']['uids']}, {1001, 1002})

    def test_protocol_and_endpoint_filters_follow_explicit_flow(self):
        filter_fixture(self.path)
        result = report.analyze(self.path, filters={'uids': [1001], 'protocols': ['tcp'],
                               'addresses': ['198.51.100.2'], 'ports': [443]})
        self.assertEqual([c['call_id'] for c in result['slow_calls']], ['call-a'])
        self.assertEqual(result['scope']['packet_events'], 2)
        self.assertEqual(result['connections'][0]['call_time']['max_ns'], str(140*MS))
        self.assertEqual(result['slow_calls'][0]['protocols'], ['tcp'])

    def test_packet_executor_uid_is_not_socket_owner_and_root_is_valid(self):
        filter_fixture(self.path)
        root = report.analyze(self.path, filters={'uids': [0]})
        self.assertEqual(root['scope']['packet_events'], 0)
        self.assertEqual(root['slow_calls'], [])
        trace = Trace.FromString(self.path.read_bytes())
        for packet in trace.packet:
            if packet.track_event.name == 'sendmmsg':
                next(a for a in packet.track_event.debug_annotations if a.name == 'uid').int_value = 0
        self.path.write_bytes(trace.SerializeToString())
        root = report.analyze(self.path, filters={'uids': [0]})
        self.assertEqual([c['call_id'] for c in root['slow_calls']], ['call-b'])

    def test_invalid_owner_and_context_creation_are_not_matching_statistics(self):
        filter_fixture(self.path)
        trace = Trace.FromString(self.path.read_bytes())
        for packet in trace.packet:
            if packet.track_event.name == 'TCP send' and packet.track_event.categories[0] == 'anettrace.packet':
                next(a for a in packet.track_event.debug_annotations if a.name == 'owner_valid').bool_value = False
        packet = trace.packet.add(timestamp=BASE+80*MS, timestamp_clock_id=6, trusted_packet_sequence_id=1)
        event = packet.track_event
        event.track_uuid = 1
        event.type = TrackEvent.TYPE_INSTANT
        event.name = 'socket allocation'
        event.categories.append('anettrace.socket')
        event.debug_annotations.add(name='socket_id', string_value='s1')
        event.debug_annotations.add(name='uid', int_value=1001)
        self.path.write_bytes(trace.SerializeToString())
        result = report.analyze(self.path, filters={'uids': [1002]})
        self.assertEqual({c['key'] for c in result['connections']}, {'flow:f2'})
        self.assertEqual(result['scope']['context_events'], 1)
        birth = result['sockets'][0]['events'][0]
        self.assertTrue(birth['context_only'])
        self.assertEqual(birth['kinds'], ['create'])
        self.assertEqual(birth['app_uid'], 1001)
        result = report.analyze(self.path, filters={'uids': [1001]})
        self.assertEqual(result['scope']['packet_events'], 0)

    def test_flow_tag_duration_and_time_window_do_not_clip_calls(self):
        filter_fixture(self.path)
        result = report.analyze(self.path, filters={'flows': ['tcp-1'], 'min_call_ms': '100',
                               'start_ms': '15', 'end_ms': '20'})
        call = result['slow_calls'][0]
        self.assertEqual(call['dur_ns'], str(140*MS))
        self.assertEqual(call['schedule']['running_ns'], str(60*MS))
        self.assertEqual(result['calls']['ranked_total'], 1)
        self.assertIn(f's.ts={BASE+100*MS}', call['evidence']['sql'])

    def test_invalid_filters_are_rejected(self):
        fixture(self.path)
        for filters in ({'uids': [-1]}, {'ports': [65536]}, {'min_call_ms': 'NaN'},
                        {'start_ms': 10, 'end_ms': 2}, {'start_ms': 2, 'end_ms': 2},
                        [], False, {'surprise': 'x'}):
            with self.subTest(filters=filters), self.assertRaises(ValueError):
                report.normalize_filters(filters)

    def test_process_uid_fallback_requires_consistent_event_identity(self):
        fixture(self.path)
        trace = Trace.FromString(self.path.read_bytes())
        trace.packet[0].process_tree.processes[0].uid = 0
        # A conflicting explicit PID must not borrow the track's process UID.
        for packet in trace.packet:
            if packet.track_event.name == 'sendmmsg':
                packet.track_event.debug_annotations.add(name='tgid', int_value=999)
        self.path.write_bytes(trace.SerializeToString())
        result = report.analyze(self.path, filters={'uids': [0]})
        self.assertEqual([c['call_id'] for c in result['slow_calls']], ['call-a'])
        self.assertEqual(result['slow_calls'][0]['identity_source'], 'thread_process')
        unknown = report.analyze(self.path, filters={'uids': ['unknown']})
        self.assertEqual([c['call_id'] for c in unknown['slow_calls']], ['call-b'])
        self.assertEqual(report.normalize_filters({'addresses': ['unknown']}), {'addresses': ['unknown']})

    def test_report_time_uses_clock_mapping_and_keeps_exact_evidence(self):
        fixture(self.path)
        trace = Trace.FromString(self.path.read_bytes())
        # UTC 16:00 rolls into the next UTC+8 calendar day.
        realtime = 1793289600123456789
        snapshot = Trace().packet.add().clock_snapshot
        snapshot.primary_trace_clock = 6
        snapshot.clocks.add(clock_id=6, timestamp=BASE)
        snapshot.clocks.add(clock_id=1, timestamp=realtime)
        packet = trace.packet.add()
        packet.clock_snapshot.CopyFrom(snapshot)
        self.path.write_bytes(trace.SerializeToString())
        result = report.analyze(self.path)
        time = result['time']
        self.assertEqual(time['timezone'], 'UTC+8')
        with TraceProcessor(trace=str(self.path)) as tp:
            start = list(tp.query('SELECT start_ts FROM trace_bounds'))[0].start_ts
            self.assertEqual(time['trace_start_ns'], str(start))
            for ts, utc in time['realtime_by_ts'].items():
                expected = list(tp.query(f'SELECT TO_REALTIME({ts}) AS t'))[0].t
                self.assertEqual(utc, str(expected))
        call = result['slow_calls'][0]
        self.assertEqual(time['realtime_by_ts'][call['ts_ns']], str(realtime+100*MS))
        self.assertIn(f"s.ts={BASE+100*MS}", call['evidence']['sql'])
        self.assertIn('ts='+str(BASE+100*MS), call['evidence']['perfetto_url'])

    def test_missing_wall_clock_stays_unknown(self):
        fixture(self.path)
        result = report.analyze(self.path)
        self.assertTrue(result['time']['realtime_by_ts'])
        self.assertTrue(all(t is None for t in result['time']['realtime_by_ts'].values()))

    def test_socket_timeline_retains_all_observations_and_ids(self):
        fixture(self.path)
        trace = Trace.FromString(self.path.read_bytes())
        def point(ts, category, name, **args):
            packet = trace.packet.add(timestamp=BASE+ts*MS, timestamp_clock_id=6,
                                      trusted_packet_sequence_id=1)
            event = packet.track_event
            event.track_uuid = 1
            event.type = TrackEvent.TYPE_INSTANT
            event.name = name
            event.categories.append(category)
            for key, value in args.items():
                event.debug_annotations.add(name=key, string_value=str(value))
        point(80, 'anettrace.socket', 'socket allocation', socket_id='s1')
        for ts, flags, direction, packet_id in [(85, 2, 'tx', 'syn1'),
                (86, 2, 'tx', 'syn1'), (87, 18, 'rx', 'syn2'),
                (290, 17, 'tx', 'fin1'), (291, 17, 'rx', 'fin2')]:
            point(ts, 'anettrace.packet', 'TCP packet', socket_id='s1',
                  flow_id='f1', tcp_flags=flags, proto_l4=6, direction=direction,
                  packet_id=packet_id, ip_id=4660, tcp_seq=123, tcp_ack=456)
        point(85, 'anettrace.socket.packet', 'mirror', socket_id='s1', tcp_flags=2)
        point(292, 'anettrace.packet.drop', 'TCP drop', owner_socket_id='s2', tcp_flags=4)
        point(293, 'anettrace.packet', 'UDP packet', socket_id='s2', proto_l4=17, tcp_flags=2)
        self.path.write_bytes(trace.SerializeToString())
        result = report.analyze(self.path, limit=1)
        schema = json.loads((Path(__file__).resolve().parents[1] /
                             'schemas/network-performance-v1.schema.json').read_text())
        Draft202012Validator(schema).validate(result)
        sockets = {s['socket_id']: s for s in result['sockets']}
        self.assertEqual(set(sockets), {'s1', 's2'})
        s1 = sockets['s1']
        self.assertEqual(len(s1['events']), 6)  # Preserve repeat probe observations.
        self.assertEqual(s1['first_syn_ns'], str(BASE+85*MS))
        self.assertEqual(s1['first_fin_ns'], str(BASE+290*MS))
        self.assertEqual(s1['created_ns'], str(BASE+80*MS))
        self.assertEqual(s1['events'][1]['packet_id'], 'syn1')
        self.assertEqual(s1['events'][1]['ip_id'], 4660)
        self.assertEqual(s1['events'][1]['tcp_seq'], 123)
        self.assertEqual(s1['events'][3]['kinds'], ['syn_ack'])
        self.assertIsNone(sockets['s2']['created_ns'])
        self.assertIsNone(sockets['s2']['first_syn_ns'])
        self.assertEqual(sockets['s2']['events'][0]['kinds'], ['rst'])
        with TraceProcessor(trace=str(self.path)) as tp:
            for socket in sockets.values():
                for event in socket['events']:
                    found = list(tp.query(event['evidence']['sql']))
                    self.assertEqual(len(found), 1)
                    self.assertEqual(found[0].ts, int(event['ts_ns']))

    def test_direct_selection_only_when_timestamp_and_duration_are_unique(self):
        fixture(self.path)
        result = report.analyze(self.path)
        ev = result['slow_calls'][0]['evidence']
        params = parse_qs(urlsplit(ev['perfetto_url']).fragment.split('?', 1)[1])
        self.assertEqual(params['ts'], [str(BASE+100*MS)])
        self.assertEqual(params['dur'], [str(140*MS)])
        self.assertNotIn('query', params)  # Open the selection details directly.
        self.assertEqual(ev['selection'], 'slice')
        trace = Trace.FromString(self.path.read_bytes())
        original = next(p for p in trace.packet if p.track_event.name == 'trace_end')
        extra = trace.packet.add()
        extra.CopyFrom(original)
        extra.track_event.categories[0] = 'other.tool'
        # Two instant tags at the same timestamp must not select the wrong one.
        self.path.write_bytes(trace.SerializeToString())
        result = report.analyze(self.path)
        meta = result['quality']['metadata'][0]['evidence']
        self.assertEqual(meta['selection'], 'ambiguous')
        params = parse_qs(urlsplit(meta['perfetto_url']).fragment.split('?', 1)[1])
        self.assertNotIn('ts', params)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for navigation regression')
    def test_perfetto_reuses_popup_and_reloads_selection(self):
        root = Path(__file__).resolve().parents[1]
        subprocess.run(['node', str(root/'tests/network_report_navigation.js'),
                        str(root/'skills/anettrace-analysis/assets/report.html')], check=True)

    @unittest.skipUnless(shutil.which('node'), 'Node.js is required for time formatting regression')
    def test_time_formatting_preserves_microseconds_and_missing_clocks(self):
        root = Path(__file__).resolve().parents[1]
        subprocess.run(['node', str(root/'tests/network_report_time.js'),
                        str(root/'skills/anettrace-analysis/assets/report.html')], check=True)

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

    def test_local_filter_api_recomputes_and_persists_full_selection(self):
        filter_fixture(self.path)
        out = Path(self.tmp.name)/'report'
        report.write_report(report.analyze(self.path, limit=1),out)
        server = report.make_server(out,port=0)
        self.addCleanup(server.server_close)
        threading.Thread(target=server.serve_forever,daemon=True).start()
        self.addCleanup(server.shutdown)
        url = f'http://127.0.0.1:{server.server_port}'
        body = json.dumps({'filters':{'uids':[1002]},'limit':1}).encode()
        with urlopen(Request(url+'/api/report',data=body,
                     headers={'Content-Type':'application/json','Origin':url})) as response:
            selected = json.load(response)
        self.assertEqual(selected['slow_calls'][0]['call_id'],'call-b')
        self.assertEqual(selected['calls']['ranked_total'],1)
        self.assertEqual(selected['quality']['calls'],4)
        self.assertEqual(json.loads((out/'report.json').read_text()), selected)
        report.validate_report(out)
        request = Request(url+'/api/report',data=body,
                          headers={'Content-Type':'application/json','Origin':'https://attacker.example'})
        with self.assertRaises(HTTPError) as error: urlopen(request)
        self.assertEqual(error.exception.code,403)
        error.exception.close()

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
