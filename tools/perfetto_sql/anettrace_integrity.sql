-- Strict post-merge checks for a system trace plus Anettrace metadata.
SELECT
  (SELECT COUNT(*) FROM slice WHERE category GLOB 'anettrace*')
    AS anettrace_events,
  (SELECT COUNT(*) FROM slice WHERE category GLOB 'anettrace.packet*')
    AS packet_events,
  (SELECT COUNT(*) FROM slice WHERE category = 'anettrace.socket')
    AS socket_events,
  (SELECT COUNT(*) FROM thread_state) AS thread_states,
  (
    SELECT COUNT(*)
    FROM slice s
    JOIN thread_track tt ON s.track_id = tt.id
    JOIN thread_state st ON st.utid = tt.utid
    WHERE s.category GLOB 'anettrace.packet*'
      AND st.ts <= s.ts
      AND (st.dur = -1 OR st.ts + st.dur >= s.ts)
  ) AS packet_events_with_thread_state,
  (
    SELECT COALESCE(SUM(value), 0)
    FROM stats
    WHERE name = 'clock_sync_unrelatable_clock_domains'
  ) AS clock_sync_unrelatable_clock_domains,
  (
    SELECT COALESCE(SUM(value), 0)
    FROM stats
    WHERE name = 'clock_sync_failure_no_path'
  ) AS clock_sync_failure_no_path,
  (
    SELECT COALESCE(SUM(value), 0)
    FROM stats
    WHERE name = 'trace_sorter_negative_timestamp_dropped'
  ) AS trace_sorter_negative_timestamp_dropped,
  (
    SELECT COALESCE(SUM(value), 0)
    FROM stats
    WHERE severity = 'error' AND value > 0
  ) AS error_stats_total;
