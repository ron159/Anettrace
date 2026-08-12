-- Per-attempt scheduler and process-lifecycle evidence for report enrichment.
WITH attempts AS (
  SELECT
    CAST(EXTRACT_ARG(s.arg_set_id, 'debug.attempt_id') AS TEXT) AS attempt_id,
    CAST(EXTRACT_ARG(s.arg_set_id, 'debug.tid') AS INT) AS tid,
    CAST(EXTRACT_ARG(s.arg_set_id, 'debug.tgid') AS INT) AS tgid,
    s.ts AS started_ns,
    CASE WHEN s.dur < 0 THEN 0 ELSE s.dur END AS duration_ns
  FROM slice s
  WHERE s.category = 'anettrace.connect'
    AND s.name = 'TCP connect attempt'
), state_metrics AS (
  SELECT
    a.attempt_id,
    COALESCE(SUM(CASE
      WHEN st.state IN ('R', 'R+') THEN
        MAX(0, MIN(a.started_ns + a.duration_ns, st.ts + st.dur) -
               MAX(a.started_ns, st.ts))
      ELSE 0 END), 0) AS runnable_delay_ns,
    COALESCE(SUM(CASE
      WHEN st.state = 'Running' THEN
        MAX(0, MIN(a.started_ns + a.duration_ns, st.ts + st.dur) -
               MAX(a.started_ns, st.ts))
      ELSE 0 END), 0) AS running_ns
  FROM attempts a
  LEFT JOIN thread t ON t.tid = a.tid
    AND (t.start_ts IS NULL OR t.start_ts <= a.started_ns + a.duration_ns)
    AND (t.end_ts IS NULL OR t.end_ts >= a.started_ns)
  LEFT JOIN thread_state st ON st.utid = t.utid
    AND st.dur >= 0
    AND st.ts < a.started_ns + a.duration_ns
    AND st.ts + st.dur > a.started_ns
  GROUP BY a.attempt_id
)
SELECT
  a.attempt_id,
  a.started_ns,
  a.duration_ns,
  a.tid,
  a.tgid,
  m.runnable_delay_ns,
  m.running_ns,
  COALESCE((
    SELECT MIN(p.end_ts)
    FROM process p
    WHERE p.pid = a.tgid
      AND (p.start_ts IS NULL OR p.start_ts <= a.started_ns)
      AND p.end_ts IS NOT NULL
      AND p.end_ts >= a.started_ns
      AND p.end_ts <= a.started_ns + a.duration_ns
  ), 0) AS process_exit_ns
FROM attempts a
JOIN state_metrics m USING (attempt_id)
ORDER BY a.started_ns, a.attempt_id;
