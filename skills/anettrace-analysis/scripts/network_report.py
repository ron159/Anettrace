#!/usr/bin/env python3
"""Offline network performance report; no device or root access required."""
from __future__ import annotations

from collections import defaultdict
import argparse
from decimal import Decimal, InvalidOperation
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import ipaddress
import math
from pathlib import Path
import shutil
import sys
import threading
from urllib.parse import urlencode
import webbrowser

SCHEMA = 'anettrace.network-performance.v1'
ASSETS = Path(__file__).resolve().parents[1] / 'assets'
CANONICAL = "s.category GLOB 'anettrace*' AND s.category != 'anettrace.socket.packet'"
FIELDS = ('syscall', 'call_id', 'socket_id', 'owner_socket_id', 'flow_id', 'flow_tag',
          'packet_id', 'tid', 'tgid', 'fd', 'direction', 'result', 'result_unit',
          'incomplete', 'start_clipped', 'local_addr', 'remote_addr',
          'local_port', 'remote_port', 'saddr', 'daddr', 'sport', 'dport',
          'ip_id', 'ip_id_valid', 'error', 'proto_l4', 'tcp_flags', 'tcp_seq', 'tcp_ack',
          'uid', 'owner_uid', 'owner_tid', 'owner_tgid', 'owner_valid', 'protocol')
APP_CATEGORIES = {'anettrace.syscall', 'anettrace.socket', 'anettrace.flow',
                  'anettrace.packet', 'anettrace.packet.drop'}
LIST_FILTERS = ('uids', 'pids', 'tids', 'flows', 'sockets', 'protocols',
                'addresses', 'ports', 'syscalls')
TIME_FILTERS = ('min_call_ms', 'max_call_ms', 'start_ms', 'end_ms')


def normalize_filters(filters):
    if filters is None:
        filters = {}
    if not isinstance(filters, dict) or set(filters) - set(LIST_FILTERS + TIME_FILTERS):
        raise ValueError('Unknown filter field')
    result = {}
    for key, values in filters.items():
        if key in LIST_FILTERS:
            if not isinstance(values, list) or len(values) > 100:
                raise ValueError(f'{key} must be a list of at most 100 values')
            parsed = []
            for value in values:
                value = str(value).strip()
                if not value: continue
                if key in ('uids', 'pids', 'tids', 'ports') and value != 'unknown':
                    value = int(value)
                    if not 0 <= value <= (65535 if key == 'ports' else 4294967295):
                        raise ValueError(f'{key} out of range')
                elif key == 'addresses' and value != 'unknown':
                    value = str(ipaddress.ip_address(value.strip('[]')))
                elif len(value) > 128:
                    raise ValueError(f'{key} value too long')
                else:
                    value = value.lower()
                if value not in parsed: parsed.append(value)
            if parsed: result[key] = parsed
        elif values is not None and str(values).strip() != '':
            try: value = Decimal(str(values))
            except InvalidOperation as error: raise ValueError(f'Invalid {key}') from error
            if (not value.is_finite() or value < 0 or value > Decimal('9223372036854.775807')
                    or value*1000000 != (value*1000000).to_integral_value()):
                raise ValueError(f'{key} must be nonnegative milliseconds with up to nanosecond precision')
            result[key] = format(value, 'f')
    for lower, upper in (('min_call_ms', 'max_call_ms'), ('start_ms', 'end_ms')):
        if lower in result and upper in result and Decimal(result[lower]) > Decimal(result[upper]):
            raise ValueError(f'{lower} must not exceed {upper}')
    if 'start_ms' in result and 'end_ms' in result and Decimal(result['start_ms']) == Decimal(result['end_ms']):
        raise ValueError('start_ms must precede end_ms for a nonempty time window')
    return result


def application_identity(event):
    owner = event['category'] in ('anettrace.packet', 'anettrace.packet.drop', 'anettrace.flow')
    if owner:
        known = event['owner_valid'] in (None, True, 1) and (event['owner_tgid'] or 0) > 0
        fields = (event['owner_uid'], event['owner_tgid'], event['owner_tid']) if known else (None, None, None)
        source = 'socket_owner' if known else 'unknown'
    else:
        uid = event['uid'] if event['uid'] is not None else event.get('process_uid')
        fields = uid, event['tgid'] or event.get('track_pid'), event['tid'] or event.get('track_tid')
        source = 'event' if event['uid'] is not None else 'thread_process' if uid is not None else 'unknown'
    event.update(zip(('app_uid', 'app_pid', 'app_tid'), fields))
    event['identity_source'] = source


def enrich_events(events):
    contexts = defaultdict(lambda: defaultdict(set))
    socket_protocols = defaultdict(set)
    for e in events:
        application_identity(e)
        protocol = {6: 'tcp', 17: 'udp', 1: 'icmp', 58: 'icmpv6'}.get(e['proto_l4'])
        protocol = protocol or (str(e['protocol']).lower().replace('udp-dns', 'udp') if e['protocol'] else None)
        e['protocols'] = [protocol] if protocol else []
        e['flows'] = sorted({str(v).lower() for v in (e['flow_id'], e['flow_tag']) if v})
        e['sockets'] = sorted({str(v).lower() for v in (e['socket_id'], e['owner_socket_id']) if v})
        addresses = set()
        for field in ('local_addr', 'remote_addr', 'saddr', 'daddr'):
            if not e[field]: continue
            try: addresses.add(str(ipaddress.ip_address(str(e[field]).strip('[]'))))
            except ValueError: pass
        e['addresses'] = sorted(addresses)
        e['ports'] = sorted({e[f] for f in ('local_port', 'remote_port', 'sport', 'dport') if e[f] is not None})
        e['syscalls'] = [e['syscall'] or e['name'].split(' ', 1)[0]] if e['category'] == 'anettrace.syscall' else []
        if e['flow_id']:
            for field in ('protocols', 'flows', 'addresses', 'ports'):
                contexts[e['flow_id']][field].update(e[field])
        for socket_id in e['sockets']:
            socket_protocols[socket_id].update(e['protocols'])
    for e in events:
        if e['flow_id']:
            for field in ('protocols', 'flows', 'addresses', 'ports'):
                e[field] = sorted(set(e[field]) | contexts[e['flow_id']][field])
        elif not e['protocols']:
            known = set().union(*(socket_protocols[s] for s in e['sockets']))
            if len(known) == 1: e['protocols'] = sorted(known)


def select_events(events, filters, start):
    def matches(event):
        fields = {'uids': 'app_uid', 'pids': 'app_pid', 'tids': 'app_tid'}
        for key in LIST_FILTERS:
            if key == 'syscalls' or key not in filters: continue
            values = event.get(fields.get(key, key))
            values = values if isinstance(values, list) else [values]
            if not set(filters[key]) & {v if v is not None else 'unknown' for v in values or [None]}:
                return False
        if 'start_ms' in filters and event['dur'] >= 0:
            lower = start + int(Decimal(filters['start_ms'])*1000000)
            if (event['ts']+event['dur'] <= lower if event['dur'] else event['ts'] < lower): return False
        if 'end_ms' in filters and event['ts'] >= start + int(Decimal(filters['end_ms'])*1000000):
            return False
        return True
    selected = [e for e in events if e['category'] in APP_CATEGORIES and matches(e)]
    call_filters = any(k in filters for k in ('syscalls', 'min_call_ms', 'max_call_ms'))
    def call_matches(e):
        if 'syscalls' in filters and not set(e['syscalls']) & set(filters['syscalls']): return False
        if any(k in filters for k in ('min_call_ms', 'max_call_ms')) and not eligible(e): return False
        if 'min_call_ms' in filters and e['dur'] < int(Decimal(filters['min_call_ms'])*1000000): return False
        if 'max_call_ms' in filters and e['dur'] > int(Decimal(filters['max_call_ms'])*1000000): return False
        return True
    calls = [e for e in selected if e['category'] == 'anettrace.syscall' and call_matches(e)]
    if call_filters:
        call_ids = {e['id'] for e in calls}
        flows = {e['flow_id'] for e in calls if e['flow_id']}
        sockets = {s for e in calls if not e['flow_id'] for s in e['sockets']}
        selected = [e for e in selected if e['id'] in call_ids or (e['category'] != 'anettrace.syscall' and
                    (e['flow_id'] in flows or (not e['flow_id'] and set(e['sockets']) & sockets)))]
    # Keep creation evidence through explicit socket IDs, even before a selected time window.
    sockets = {s for e in selected for s in e['sockets']}
    present = {e['id'] for e in selected}
    for e in events:
        if (e['category'] == 'anettrace.socket' and e['name'] == 'socket allocation'
                and e['id'] not in present and set(e['sockets']) & sockets):
            selected.append({**e, 'context_only': True})
    return sorted(selected, key=lambda e: (e['ts'], e['id']))


def inventory(events):
    result = {}
    for label, field in (('uids', 'app_uid'), ('pids', 'app_pid'), ('tids', 'app_tid'),
                         ('flows', 'flows'), ('sockets', 'sockets'), ('protocols', 'protocols'),
                         ('addresses', 'addresses'), ('ports', 'ports'), ('syscalls', 'syscalls')):
        counts = {}
        for event in events:
            if event['category'] not in APP_CATEGORIES: continue
            if label == 'syscalls' and event['category'] != 'anettrace.syscall': continue
            values = event.get(field)
            values = values if isinstance(values, list) else [values]
            for value in values or [None]:
                item = counts.setdefault(value, dict(value=value, events=0, calls=0))
                item['events'] += 1
                item['calls'] += event['category'] == 'anettrace.syscall'
        result[label] = sorted(counts.values(), key=lambda c: (c['value'] is None, str(c['value'])))
    return result


def rows(tp, sql):
    return [vars(row) for row in tp.query(sql)]


def quote(value):
    return "'" + str(value).replace("'", "''") + "'"


def missing_id(field):
    return f"LTRIM(COALESCE(CAST(EXTRACT_ARG(s.arg_set_id,'debug.{field}') AS TEXT),'0'),'0')=''"


def evidence(sql, ts=None, dur=None, *, selection=None):
    params = {'query': sql}
    if ts is not None:
        span = max(dur or 0, 1_000_000)
        params.update(visStart=max(0, ts - span), visEnd=ts + span * 2)
    if selection == 'slice':
        params.pop('query')  # Keep the selected tag's details in front, not a query tab.
        params.update(ts=ts, dur=dur)
    return {'sql': sql, 'ts_ns': str(ts) if ts is not None else None,
            'dur_ns': str(dur) if dur is not None else None,
            'perfetto_url': 'https://ui.perfetto.dev/#!/?' + urlencode(params),
            'selection': selection}


def slice_evidence(event):
    # Timestamp/category/name and explicit IDs survive Trace Processor ID changes.
    where = (f"s.ts={event['ts']} AND s.dur={event['dur']} "
             f"AND s.category={quote(event['category'])} AND s.name={quote(event['name'])}")
    for field in ('call_id', 'packet_id', 'flow_id', 'socket_id'):
        if event.get(field):
            where += f" AND CAST(EXTRACT_ARG(s.arg_set_id,'debug.{field}') AS TEXT)={quote(event[field])}"
    return evidence('SELECT s.* FROM slice s WHERE ' + where, event['ts'], event['dur'],
                    selection='ambiguous' if event.get('ambiguous') else 'slice')


def digest(path):
    hasher = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            hasher.update(chunk)
    return hasher.hexdigest()


def eligible(call):
    return (call['dur'] >= 0 and not call['incomplete']
            and not call['start_clipped'] and call['result'] is not None)


def scalar(value):
    # Native exporter annotations are strings; the JSONL converter uses typed values.
    if isinstance(value, str):
        if value.lower() in ('true', 'false'):
            return value.lower() == 'true'
        if value.lstrip('-').isdigit():
            return int(value)
    return value


def call_direction(call):
    name = call['syscall'] or call['name'].split(' ', 1)[0]
    if name.startswith(('send','write')):
        return 'tx'
    if name.startswith(('recv','read')):
        return 'rx'
    return 'unknown'


def endpoints(event):
    values = []
    for address, port in (('local_addr','local_port'), ('remote_addr','remote_port'),
                          ('saddr','sport'), ('daddr','dport')):
        if event[address]:
            values.append(f"[{event[address]}]:{event[port]}" if event[port] is not None else str(event[address]))
    return ' ↔ '.join(values)


def capture_quality(tp, events, packets, calls, excluded):
    metadata = []
    issues = []
    lost = None
    end_losses = []
    for event in events:
        if event['category'] != 'anettrace.metadata':
            continue
        fields = rows(tp, f"SELECT key,int_value,string_value FROM args WHERE arg_set_id={event['arg_set_id']}")
        fields = {f['key'][6:]: scalar(f['int_value'] if f['int_value'] is not None else f['string_value'])
                  for f in fields if f['key'].startswith('debug.')}
        metadata.append(dict(name=event['name'], fields=fields, evidence=slice_evidence(event)))
        if event['name'] == 'trace_end':
            end_losses.append(fields.get('lost_events'))
        for key in ('capacity_truncated', 'capacity_dropped_events', 'expired_events', 'unresolved_events'):
            if fields.get(key):
                issues.append(f"{event['name']}.{key}={fields[key]}")
    if len(end_losses) == 1:
        lost = end_losses[0]
    elif end_losses:
        issues.append('存在多个 trace_end，无法确认计数是否来自同一次采集；请查看各段元数据')
    notifications = sum(m['fields'].get('count', 0) for m in metadata if m['name']=='lost_events')
    observed_loss = notifications or any(value for value in end_losses if value is not None)
    if notifications:
        issues.append(f'lost_events 通知合计 {notifications} 个采集事件；不与 trace_end 累计值重复相加')
    stats_sql = "SELECT name,idx,severity,value FROM stats WHERE value>0 AND severity IN ('error','data_loss')"
    stats = rows(tp, stats_sql)
    if lost:
        issues.append(f'BPF lost_events={lost}（采集事件丢失，不是网络丢包）')
    if not end_losses or end_losses == [None]:
        issues.append('缺少 trace_end.lost_events，无法确认采集事件是否丢失')
    if excluded:
        issues.append(f'{len(excluded)} 个未完成、缺少结果或起点裁剪调用未计入排行')
    if stats:
        issues.append('Trace Processor 报告解析、时钟或数据丢失统计，请查看原始 stats')
    if not any(e['category'] == 'anettrace.flow' for e in events):
        issues.append('缺少连接生命周期，仅展示显式 ID 关联的观测（适用于 trace-tags）')
    state_count = rows(tp, 'SELECT COUNT(*) AS n FROM thread_state')[0]['n']
    if not state_count:
        issues.append('缺少 thread_state，无法计算调度时间；请使用包含 sched 数据的合并轨迹')
    pressure = any(m['fields'].get(k) for m in metadata
                   for k in ('capacity_truncated','capacity_dropped_events','expired_events'))
    if not calls:
        issues.append('未观测到应用系统调用，无法生成应用慢调用排行')
    status = 'degraded' if observed_loss or stats or pressure else 'partial' if lost is None or not state_count or not calls else 'observed'
    return dict(status=status, lost_events=lost, observed_loss_notifications=notifications, packet_events=len(packets),
                observed_skbs=len({p['packet_id'] for p in packets if p['packet_id']}),
                calls=len(calls), excluded_calls=len(excluded), parser_stats=stats,
                capture_end_observed=any(m['name']=='trace_end' for m in metadata),
                thread_states=state_count, issues=issues, metadata=metadata,
                unassociated_events=sum(not (e['flow_id'] or e['socket_id'] or e['owner_socket_id'])
                                        for e in packets+calls),
                evidence=evidence("SELECT s.* FROM slice s WHERE s.category='anettrace.metadata'"),
                packet_evidence=evidence("SELECT s.* FROM slice s WHERE s.category IN ('anettrace.packet','anettrace.packet.drop')"),
                call_evidence=evidence("SELECT s.* FROM slice s WHERE s.category='anettrace.syscall'"),
                stats_evidence=evidence(stats_sql))


def schedule(tp, call):
    duration = max(0, call['dur'])
    result = dict(status='unavailable', running_ns='0', runnable_ns='0',
                  other_ns='0', uncovered_ns=str(duration), utid=None)
    # Resolve the actual executing thread, never a socket owner or bare reused TID.
    thread_sql = f"""SELECT DISTINCT t.utid, t.tid, p.pid FROM slice s
      JOIN track tr ON tr.id=s.track_id
      LEFT JOIN thread_track tt ON tt.id=tr.id
      LEFT JOIN thread_track parent ON parent.id=tr.parent_id
      JOIN thread t ON t.utid=COALESCE(tt.utid,parent.utid)
      LEFT JOIN process p ON p.upid=t.upid
      WHERE s.id={call['id']} AND (t.start_ts IS NULL OR t.start_ts<=s.ts)
        AND (t.end_ts IS NULL OR t.end_ts>=s.ts+s.dur)"""
    threads = rows(tp, thread_sql)
    threads = [t for t in threads
               if (not call.get('tid') or int(call['tid']) == t['tid'])
               and (not call.get('tgid') or int(call['tgid']) == t['pid'])]
    if len(threads) != 1:
        return result
    utid = threads[0]['utid']
    start, end = call['ts'], call['ts'] + duration
    intervals = rows(tp, f"""SELECT id,ts,dur,state FROM thread_state
        WHERE utid={utid} AND ts<{end} AND (dur=-1 OR ts+dur>{start}) ORDER BY ts,id""")
    totals = defaultdict(int)
    previous = start
    for state in intervals:
        a = max(start, state['ts'])
        b = min(end, state['ts'] + state['dur'] if state['dur'] >= 0 else end)
        if a < previous:
            result['status'] = 'overlapping_states'
            return result
        previous = b
        if state['state'] is None:
            continue
        key = ('running_ns' if state['state'] == 'Running' else
               'runnable_ns' if state['state'] in ('R', 'R+') else 'other_ns')
        totals[key] += max(0, b-a)
    result.update({k: str(totals[k]) for k in ('running_ns', 'runnable_ns', 'other_ns')})
    covered = sum(totals.values())
    result.update(status='complete' if covered == duration else 'partial',
                  uncovered_ns=str(duration-covered), utid=utid)
    # Resolve the thread again from the call in the UI's own database.
    selector = call['evidence']['sql']
    sql = f"""WITH calls AS ({selector})
        SELECT st.* FROM calls s JOIN track tr ON tr.id=s.track_id
        LEFT JOIN thread_track tt ON tt.id=tr.id
        LEFT JOIN thread_track parent ON parent.id=tr.parent_id
        JOIN thread_state st ON st.utid=COALESCE(tt.utid,parent.utid)
        WHERE st.ts<s.ts+s.dur AND (st.dur=-1 OR st.ts+st.dur>s.ts) ORDER BY st.ts"""
    result['evidence'] = evidence(sql, start, duration)
    result['evidence']['kind'] = 'thread_state'
    return result


def report_time(tp, items):
    start = rows(tp, 'SELECT start_ts FROM trace_bounds')[0]['start_ts']
    timestamps = {start}
    for item in items:
        ev = item['evidence']
        if ev['ts_ns'] is not None:
            ts = int(ev['ts_ns'])
            timestamps.add(ts)
            if ev['dur_ns'] is not None and int(ev['dur_ns']) >= 0:
                timestamps.add(ts + int(ev['dur_ns']))
    ordered = sorted(timestamps)
    converted = {}
    # Query exact timestamps in batches; no assumed fixed realtime/boot offset.
    for offset in range(0, len(ordered), 500):
        values = ','.join(f'({ts})' for ts in ordered[offset:offset+500])
        for row in rows(tp, f'WITH times(ts) AS (VALUES {values}) '
                           'SELECT ts,TO_REALTIME(ts) AS realtime FROM times'):
            converted[str(row['ts'])] = str(row['realtime']) if row['realtime'] is not None else None
    return dict(timezone='UTC+8', trace_start_ns=str(start), realtime_by_ts=converted)


def analyze(path, *, limit=50, trace_processor=None, filters=None):
    from perfetto.trace_processor import TraceProcessor, TraceProcessorConfig
    path = Path(path).resolve(strict=True)
    if limit < 1 or limit > 1000:
        raise ValueError('limit must be between 1 and 1000')
    filters = normalize_filters(filters)
    config = TraceProcessorConfig(bin_path=trace_processor) if trace_processor else TraceProcessorConfig()
    with TraceProcessor(trace=str(path), config=config) as tp:
        columns = ','.join(f"EXTRACT_ARG(s.arg_set_id,'debug.{f}') AS {f}" for f in FIELDS)
        events = rows(tp, f"""SELECT s.id,s.ts,s.dur,s.name,s.category,s.track_id,s.arg_set_id,{columns},
            t.tid AS track_tid,p.pid AS track_pid,p.uid AS process_uid
            FROM slice s LEFT JOIN track tr ON tr.id=s.track_id
            LEFT JOIN thread_track tt ON tt.id=tr.id
            LEFT JOIN thread_track parent ON parent.id=tr.parent_id
            LEFT JOIN thread t ON t.utid=COALESCE(tt.utid,parent.utid)
              AND (t.start_ts IS NULL OR t.start_ts<=s.ts)
              AND (t.end_ts IS NULL OR t.end_ts>=s.ts+MAX(0,s.dur))
              AND (EXTRACT_ARG(s.arg_set_id,'debug.tid') IS NULL OR CAST(EXTRACT_ARG(s.arg_set_id,'debug.tid') AS INT)=t.tid)
            LEFT JOIN process p ON p.upid=t.upid
              AND (p.start_ts IS NULL OR p.start_ts<=s.ts)
              AND (p.end_ts IS NULL OR p.end_ts>=s.ts+MAX(0,s.dur))
              AND (EXTRACT_ARG(s.arg_set_id,'debug.tgid') IS NULL OR CAST(EXTRACT_ARG(s.arg_set_id,'debug.tgid') AS INT)=p.pid)
            WHERE {CANONICAL} ORDER BY s.ts,s.id""")
        if not events:
            raise ValueError('No Anettrace events found in trace')
        # Perfetto's public deep link selects by ts/dur alone, across all tracks.
        ambiguous = {(e['ts'], e['dur']) for e in rows(tp,
            f"SELECT ts,dur FROM slice WHERE (ts,dur) IN "
            f"(SELECT ts,dur FROM slice s WHERE {CANONICAL}) "
            "GROUP BY ts,dur HAVING COUNT(*)>1")}
        for e in events:
            e['ambiguous'] = (e['ts'], e['dur']) in ambiguous
            for f in ('tid','tgid','fd','result','error','incomplete','start_clipped',
                      'ip_id','proto_l4','tcp_flags','tcp_seq','tcp_ack','uid','owner_uid',
                      'owner_tid','owner_tgid','owner_valid','sport','dport','local_port','remote_port'):
                e[f] = scalar(e[f])
            for f in ('flow_id', 'socket_id', 'owner_socket_id', 'packet_id'):
                if str(e[f] or '').strip('0') == '':
                    e[f] = None
        enrich_events(events)
        available = inventory(events)
        all_calls = [e for e in events if e['category'] == 'anettrace.syscall']
        all_packets = [e for e in events if e['category'] in ('anettrace.packet', 'anettrace.packet.drop')]
        quality = capture_quality(tp, events, all_packets, all_calls, [c for c in all_calls if not eligible(c)])
        start = rows(tp, 'SELECT start_ts FROM trace_bounds')[0]['start_ts']
        events = select_events(events, filters, start)
        calls = [e for e in events if e['category'] == 'anettrace.syscall']
        complete = [c for c in calls if eligible(c)]
        excluded = [c for c in calls if not eligible(c)]
        ranked = sorted(complete, key=lambda c: (-c['dur'], c['ts'], c['id']))[:limit]
        for call in ranked:
            call['evidence'] = slice_evidence(call)
            call['schedule'] = schedule(tp, call)
        packets = [e for e in events if e['category'] in ('anettrace.packet', 'anettrace.packet.drop')]
        quality['schedule_assessed_calls'] = len(ranked)
        quality['schedule_covered_calls'] = sum(c['schedule']['status']=='complete' for c in ranked)
        if quality['schedule_covered_calls'] < len(ranked):
            quality['issues'].append('部分排行调用的调度状态未完整覆盖，请查看未覆盖时间')
            if quality['status'] == 'observed':
                quality['status'] = 'partial'
        quality['unassociated_evidence'] = evidence(
            "SELECT s.* FROM slice s WHERE s.category IN ('anettrace.syscall','anettrace.packet','anettrace.packet.drop') AND "
            + ' AND '.join(missing_id(f) for f in ('flow_id','socket_id','owner_socket_id')))
        connections = connection_overview(events)
        sockets = socket_timelines(events)
        selected_excluded = [{**c, 'evidence': slice_evidence(c)} for c in excluded[:limit]]
        time = report_time(tp, connections + ranked + selected_excluded + quality['metadata']
                           + [point for socket in sockets for point in socket['events']])
        def public(event):
            return {**{k: v for k, v in event.items() if k not in ('ts', 'dur', 'arg_set_id')},
                    'ts_ns': str(event['ts']), 'dur_ns': str(event['dur'])}
        return dict(schema=SCHEMA, trace=dict(name=path.name, path=str(path), size=path.stat().st_size,
                                             sha256=digest(path)), quality=quality,
                    time=time, connections=connections, sockets=sockets, inventory=available,
                    scope=dict(filters=filters, matched_events=sum(not e.get('context_only') for e in events), calls=len(calls),
                               packet_events=len(packets), context_events=sum(bool(e.get('context_only')) for e in events)),
                    calls=dict(ranked_total=len(complete),
                    excluded_total=len(excluded), truncated=len(complete)>limit, limit=limit),
                    slow_calls=[public(c) for c in ranked],
                    excluded_calls=[public(c) for c in selected_excluded])


def socket_timelines(events):
    groups = defaultdict(list)
    for event in events:
        socket_id = event['socket_id'] or event['owner_socket_id']
        if socket_id:
            groups[str(socket_id)].append(event)
    result = []
    for socket_id, group in sorted(groups.items()):
        points = []
        for event in group:
            kinds = []
            if event['category'] == 'anettrace.socket' and event['name'] == 'socket allocation':
                kinds.append('create')
            elif event['category'] in ('anettrace.packet', 'anettrace.packet.drop'):
                flags = event['tcp_flags']
                if (event['proto_l4'] not in (None, 6) or not isinstance(flags, int)
                        or not 0 <= flags <= 255):
                    continue
                if flags & 2:
                    kinds.append('syn_ack' if flags & 16 else 'syn')
                if flags & 1:
                    kinds.append('fin')
                if flags & 4:
                    kinds.append('rst')
            if kinds:
                points.append(dict(kinds=kinds, name=event['name'], category=event['category'],
                    ts_ns=str(event['ts']), dur_ns=str(event['dur']),
                    context_only=bool(event.get('context_only')),
                    **{k: event[k] for k in ('direction','flow_id','packet_id','ip_id',
                                            'tcp_flags','tcp_seq','tcp_ack','tid','tgid',
                                            'app_uid','app_pid','app_tid','identity_source')},
                    endpoints=endpoints(event), evidence=slice_evidence(event)))
        def first(kind):
            return next((p['ts_ns'] for p in points if kind in p['kinds']), None)
        result.append(dict(socket_id=socket_id, created_ns=first('create'),
            first_syn_ns=first('syn'), first_syn_ack_ns=first('syn_ack'),
            first_fin_ns=first('fin'), first_rst_ns=first('rst'), events=points,
            endpoints=sorted({endpoints(e) for e in group if endpoints(e)})))
    return result


def connection_overview(events):
    groups = defaultdict(list)
    relevant = {'anettrace.syscall', 'anettrace.packet', 'anettrace.packet.drop',
                'anettrace.flow', 'anettrace.socket'}
    for e in events:
        if e['category'] not in relevant or e.get('context_only'):
            continue
        key = 'flow:' + str(e['flow_id']) if e['flow_id'] else (
            'socket:' + str(e['socket_id'] or e['owner_socket_id'])
            if e['socket_id'] or e['owner_socket_id'] else None)
        if key:
            groups[key].append(e)
    result = []
    for key, group in sorted(groups.items()):
        field, value = key.split(':', 1)
        predicate = f"CAST(EXTRACT_ARG(s.arg_set_id,'debug.{field}_id') AS TEXT)={quote(value)}"
        if field == 'socket':
            predicate = (f"({predicate} OR CAST(EXTRACT_ARG(s.arg_set_id,'debug.owner_socket_id') AS TEXT)={quote(value)}) "
                         f"AND {missing_id('flow_id')}")
        sql = f'SELECT s.* FROM slice s WHERE {CANONICAL} AND {predicate} ORDER BY s.ts,s.id'
        calls = [e for e in group if e['category'] == 'anettrace.syscall']
        completed = [e for e in calls if eligible(e)]
        packets = [e for e in group if e['category'].startswith('anettrace.packet')]
        start = min(e['ts'] for e in group)
        end = max(e['ts'] + max(0,e['dur']) for e in group)
        result.append(dict(key=key, socket_ids=sorted({str(e['socket_id'] or e['owner_socket_id'])
                          for e in group if e['socket_id'] or e['owner_socket_id']}),
                          flow_tags=sorted({e['flow_tag'] for e in group if e['flow_tag']}),
                          lifecycle_observed=any(e['category']=='anettrace.flow' for e in group),
                          uids=sorted({e['app_uid'] for e in group if e['app_uid'] is not None}),
                          call_time=call_time(completed), calls=len(calls), packet_events=len(packets),
                          tx_events=sum(e['direction']=='tx' for e in packets),
                          rx_events=sum(e['direction']=='rx' for e in packets),
                          endpoints=sorted({endpoints(e) for e in group if endpoints(e)}),
                          observed_skbs=len({e['packet_id'] for e in packets if e['packet_id']}),
                          application_bytes=sum(max(0,e['result'] or 0) for e in completed if e['result_unit']=='bytes'),
                          application_tx_bytes=sum(max(0,e['result'] or 0) for e in completed
                                                   if e['result_unit']=='bytes' and call_direction(e)=='tx'),
                          application_rx_bytes=sum(max(0,e['result'] or 0) for e in completed
                                                   if e['result_unit']=='bytes' and call_direction(e)=='rx'),
                          completed_messages=sum(max(0,e['result'] or 0) for e in completed if e['result_unit']=='messages'),
                          evidence={**evidence(sql,start,end-start), 'connection_context': True}))
    return result


def call_time(calls):
    durations = sorted(c['dur'] for c in calls)
    return dict(count=len(durations), total_ns=str(sum(durations)),
                min_ns=str(durations[0]) if durations else None,
                max_ns=str(durations[-1]) if durations else None,
                p50_ns=str(durations[math.ceil(len(durations)*.5)-1]) if durations else None,
                p95_ns=str(durations[math.ceil(len(durations)*.95)-1]) if durations else None)


def write_report(result, output):
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    embedded = payload.replace('&', '\\u0026').replace('<', '\\u003c').replace('>', '\\u003e')
    embedded = embedded.replace('\u2028', '\\u2028').replace('\u2029', '\\u2029')
    template = (ASSETS/'report.html').read_text(encoding='utf-8')
    for name, content in [('report.json', payload+'\n'),
                          ('report.html', template.replace('/*REPORT_DATA*/null', embedded))]:
        path = output / name
        path.write_text(content, encoding='utf-8')
        path.chmod(0o600)


def make_server(output, *, trace=None, port=0, trace_processor=None):
    output = Path(output).resolve(strict=True)
    result = json.loads((output/'report.json').read_text(encoding='utf-8'))
    if result.get('schema') != SCHEMA:
        raise ValueError('Unsupported report schema')
    source = Path(trace or result['trace']['path']).resolve(strict=True)
    analysis_lock = threading.Lock()

    def verify_trace():
        return source.stat().st_size == result['trace']['size'] and digest(source) == result['trace']['sha256']

    if not verify_trace():
        raise ValueError('Trace SHA-256 does not match report; regenerate the report or select the original trace')

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def allowed_request(self):
            allowed_hosts = {f'127.0.0.1:{self.server.server_port}', f'localhost:{self.server.server_port}'}
            return self.headers.get('Host') in allowed_hosts and self.headers.get('Sec-Fetch-Site') != 'cross-site'

        def do_POST(self):
            origin = self.headers.get('Origin')
            if not self.allowed_request() or (origin and origin != 'http://'+self.headers.get('Host','')):
                self.send_error(403)
                return
            if self.path != '/api/report':
                self.send_error(404)
                return
            try:
                length = int(self.headers.get('Content-Length','0'))
                if not 0 < length <= 8192 or self.headers.get('Content-Type') != 'application/json':
                    raise ValueError('Expected a JSON filter request of at most 8192 bytes')
                request = json.loads(self.rfile.read(length))
                if not isinstance(request, dict) or set(request) - {'filters','limit'}:
                    raise ValueError('Unknown report request fields')
                filters = normalize_filters(request.get('filters'))
                limit = request.get('limit', result['calls']['limit'])
                if type(limit) is not int or not 1 <= limit <= 1000:
                    raise ValueError('limit must be between 1 and 1000')
                with analysis_lock:
                    if not verify_trace():
                        self.send_error(409, 'Original trace changed')
                        return
                    selected = analyze(source, limit=limit, filters=filters, trace_processor=trace_processor)
                    if selected['trace']['sha256'] != result['trace']['sha256'] or not verify_trace():
                        self.send_error(409, 'Original trace changed')
                        return
                    write_report(selected, output)
                payload = json.dumps(selected, ensure_ascii=False).encode('utf-8')
                self.send_response(200)
                self.send_header('Content-Type','application/json')
                self.send_header('Content-Length',str(len(payload)))
                self.send_header('Cache-Control','no-store')
                self.send_header('X-Content-Type-Options','nosniff')
                self.end_headers()
                self.wfile.write(payload)
            except (ValueError, TypeError) as error:
                self.send_error(400, str(error))
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as error:
                self.send_error(500, str(error))

        def do_GET(self):
            if not self.allowed_request():
                self.send_error(403)
                return
            if self.path == '/trace.pftrace':
                try:
                    valid = verify_trace()
                except OSError:
                    valid = False
                if not valid:
                    self.send_error(409, 'Trace changed; regenerate report')
                    return
                path, mime = source, 'application/octet-stream'
            elif self.path in ('/', '/report.html', '/report.json'):
                path = output / ('report.json' if self.path == '/report.json' else 'report.html')
                mime = 'application/json' if self.path == '/report.json' else 'text/html; charset=utf-8'
            elif self.path == '/favicon.ico':
                self.send_response(204)
                self.end_headers()
                return
            else:
                self.send_error(404)
                return
            try:
                with path.open('rb') as stream:
                    self.send_response(200)
                    self.send_header('Content-Type', mime)
                    self.send_header('Content-Length', str(path.stat().st_size))
                    self.send_header('Cache-Control', 'no-store')
                    self.send_header('X-Content-Type-Options', 'nosniff')
                    self.send_header('Referrer-Policy', 'no-referrer')
                    self.end_headers()
                    shutil.copyfileobj(stream, self.wfile)
            except (BrokenPipeError, ConnectionResetError):
                pass

    return ThreadingHTTPServer(('127.0.0.1', port), Handler)


def validate_report(output, trace=None):
    from jsonschema import Draft202012Validator
    output = Path(output)
    result = json.loads((output/'report.json').read_text(encoding='utf-8'))
    Draft202012Validator(json.loads((ASSETS/'report.schema.json').read_text())).validate(result)
    source = Path(trace or result['trace']['path']).resolve(strict=True)
    if source.stat().st_size != result['trace']['size'] or digest(source) != result['trace']['sha256']:
        raise ValueError('Trace SHA-256 does not match report')
    html = (output/'report.html').read_text(encoding='utf-8')
    marker = '<script id="report-data" type="application/json">'
    if marker not in html or json.loads(html.split(marker, 1)[1].split('</script>', 1)[0]) != result:
        raise ValueError('HTML and JSON report contents differ; regenerate report')
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    analyze_parser = commands.add_parser('analyze', help='Read a pftrace and write report.html + report.json')
    analyze_parser.add_argument('trace', type=Path)
    analyze_parser.add_argument('--out', type=Path, required=True)
    analyze_parser.add_argument('--limit', type=int, default=50, help='Slow / excluded call rows, 1..1000 (default: 50)')
    analyze_parser.add_argument('--serve', action='store_true', help='Start local Perfetto entry after generation')
    inspect_parser = commands.add_parser('inspect', help='List capture quality and available filter values as JSON')
    inspect_parser.add_argument('trace', type=Path)
    inspect_parser.add_argument('--out', type=Path, help='Write inventory JSON instead of stdout')
    validate_parser = commands.add_parser('validate', help='Verify schema, HTML/JSON agreement and original trace identity')
    validate_parser.add_argument('out', type=Path)
    validate_parser.add_argument('--trace', type=Path, help='Relocated original trace')
    serve_parser = commands.add_parser('serve', help='Open an existing report with its original trace')
    serve_parser.add_argument('out', type=Path)
    serve_parser.add_argument('--trace', type=Path, help='Relocated original trace; SHA-256 must match')
    for flag, dest in (('uid','uids'), ('pid','pids'), ('tid','tids'), ('flow','flows'),
                       ('socket','sockets'), ('protocol','protocols'), ('address','addresses'),
                       ('endpoint-port','ports'), ('syscall','syscalls')):
        aliases = ['--'+flag] + (['--'+flag+'-id'] if flag in ('flow','socket') else [])
        analyze_parser.add_argument(*aliases, dest=dest, action='append', help='Repeat for OR; different filters use AND')
    for flag in TIME_FILTERS:
        analyze_parser.add_argument('--'+flag.replace('_','-'), help='Milliseconds; relative to trace start for start/end')
    for sub in (analyze_parser, inspect_parser, serve_parser):
        sub.add_argument('--trace-processor', help='Local trace_processor_shell binary (otherwise Perfetto resolves it)')
    for sub in (analyze_parser, serve_parser):
        sub.add_argument('--port', type=int, default=0, help='Loopback HTTP port, default: random')
        sub.add_argument('--open', action='store_true', help='Open local report in a browser')
    args = parser.parse_args(argv)
    try:
        if args.command == 'validate':
            validate_report(args.out, args.trace)
            print(f'Report verified: {args.out.resolve()}')
            return 0
        if args.command == 'inspect':
            result = analyze(args.trace, limit=1, trace_processor=args.trace_processor)
            payload = json.dumps({k: result[k] for k in ('schema','trace','quality','inventory')}, ensure_ascii=False, indent=2)+'\n'
            if args.out: args.out.write_text(payload, encoding='utf-8')
            else: print(payload, end='')
            return 0
        if args.command == 'analyze':
            filters = {key: getattr(args, key) for key in LIST_FILTERS + TIME_FILTERS if getattr(args, key)}
            result = analyze(args.trace, limit=args.limit, trace_processor=args.trace_processor, filters=filters)
            write_report(result, args.out)
            print(f'Report: {(args.out / "report.html").resolve()}')
            print(f'Quality: {result["quality"]["status"]}; connections: {len(result["connections"])}; '
                  f'completed calls: {result["calls"]["ranked_total"]}')
            if not (args.serve or args.open):
                return 0
        server = make_server(args.out, trace=args.trace if args.command=='serve' else None,
                             port=args.port, trace_processor=args.trace_processor)
        url = f'http://127.0.0.1:{server.server_port}/'
        print(f'Local report / Perfetto entry: {url}', flush=True)
        if args.open:
            webbrowser.open(url)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
        return 0
    except ImportError:
        requirements = ASSETS.parent / 'requirements.txt'
        print(f'Install report dependencies in a virtual environment: python3 -m pip install -r "{requirements}"', file=sys.stderr)
    except Exception as error:
        print(f'network_report: {error}', file=sys.stderr)
    return 2


if __name__ == '__main__':
    raise SystemExit(main())
