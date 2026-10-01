-- Paste into Perfetto's SQL query tab and change the two strings below.
-- seed_kind: flow_tag, flow_id, socket_id, packet_id, call_id, io_id, handoff_id.
-- Example: SELECT 'flow_tag' AS seed_kind, 'tcp-1' AS seed_id
-- Flow/socket seeds select the stream; packet/call seeds follow only observed
-- packet/IO/call/handoff IDs, adding socket creation and flow context separately.
-- Shared socket, timestamp proximity, and thread ownership are NOT packet links.
-- A copy_attempt is not proof of successful copying; inspect syscall result and
-- incomplete. A socket-readable callback alone does not identify a packet/wakee.
WITH RECURSIVE
selection AS (SELECT '' AS seed_kind, '' AS seed_id),
events AS (
  SELECT s.id, s.ts, s.dur, s.name, s.category, s.track_id,
    COALESCE(t.tid, pt.tid, CAST(EXTRACT_ARG(s.arg_set_id, 'debug.tid') AS INT)) AS tid,
    COALESCE(t.name, pt.name) AS thread_name,
    EXTRACT_ARG(s.arg_set_id, 'debug.stage') AS stage,
    EXTRACT_ARG(s.arg_set_id, 'debug.flow_id') AS flow_id,
    EXTRACT_ARG(s.arg_set_id, 'debug.flow_tag') AS flow_tag,
    COALESCE(EXTRACT_ARG(s.arg_set_id, 'debug.socket_id'),
             EXTRACT_ARG(s.arg_set_id, 'debug.owner_socket_id'),
             EXTRACT_ARG(s.arg_set_id, 'debug.socket_instance_id')) AS socket_id,
    EXTRACT_ARG(s.arg_set_id, 'debug.packet_id') AS packet_id,
    EXTRACT_ARG(s.arg_set_id, 'debug.io_id') AS io_id,
    EXTRACT_ARG(s.arg_set_id, 'debug.call_id') AS call_id,
    EXTRACT_ARG(s.arg_set_id, 'debug.handoff_id') AS handoff_id,
    EXTRACT_ARG(s.arg_set_id, 'debug.direction') AS direction,
    EXTRACT_ARG(s.arg_set_id, 'debug.evidence') AS evidence,
    EXTRACT_ARG(s.arg_set_id, 'debug.association') AS association,
    EXTRACT_ARG(s.arg_set_id, 'debug.packet_association') AS packet_association,
    CAST(EXTRACT_ARG(s.arg_set_id, 'debug.wake_tid') AS INT) AS wake_tid,
    CAST(EXTRACT_ARG(s.arg_set_id, 'debug.result') AS INT) AS result,
    CAST(EXTRACT_ARG(s.arg_set_id, 'debug.bytes') AS INT) AS bytes,
    CAST(EXTRACT_ARG(s.arg_set_id, 'debug.error') AS INT) AS error,
    EXTRACT_ARG(s.arg_set_id, 'debug.incomplete') AS incomplete
  FROM slice s
  LEFT JOIN track tr ON tr.id = s.track_id
  LEFT JOIN thread_track tt ON tt.id = s.track_id
  LEFT JOIN thread t ON t.utid = tt.utid
  -- Network syscalls are on a child track below the actual application thread.
  LEFT JOIN thread_track ptt ON ptt.id = tr.parent_id
  LEFT JOIN thread pt ON pt.utid = ptt.utid
  WHERE s.category GLOB 'anettrace*'
),
raw_ids AS (
  SELECT id, 'packet_id' AS kind, packet_id AS value FROM events
  UNION ALL SELECT id, 'io_id', io_id FROM events
  UNION ALL SELECT id, 'call_id', call_id FROM events
  UNION ALL SELECT id, 'handoff_id', handoff_id FROM events
),
ids AS (
  SELECT * FROM raw_ids WHERE value IS NOT NULL AND LTRIM(value, '0') != ''
),
seed_events AS (
  SELECT e.id FROM events e, selection p
  WHERE p.seed_id != '' AND (p.seed_kind = 'flow_tag' OR LTRIM(p.seed_id, '0') != '')
    AND (CASE p.seed_kind
      WHEN 'flow_tag' THEN e.flow_tag WHEN 'flow_id' THEN e.flow_id
      WHEN 'socket_id' THEN e.socket_id WHEN 'packet_id' THEN e.packet_id
      WHEN 'call_id' THEN e.call_id WHEN 'io_id' THEN e.io_id
      WHEN 'handoff_id' THEN e.handoff_id
    END = p.seed_id
    OR (p.seed_kind = 'socket_id' AND e.flow_id IN (
      SELECT flow_id FROM events WHERE socket_id = p.seed_id
        AND flow_id IS NOT NULL AND LTRIM(flow_id, '0') != ''
    )))
),
linked(id) AS (
  SELECT id FROM seed_events
  UNION
  SELECT other.id FROM linked
  JOIN ids source ON source.id = linked.id
  JOIN ids other ON other.kind = source.kind AND other.value = source.value
),
selected_flows AS (
  SELECT DISTINCT flow_id FROM events JOIN linked USING (id)
  WHERE flow_id IS NOT NULL AND LTRIM(flow_id, '0') != ''
),
selected_sockets AS (
  SELECT DISTINCT socket_id FROM events
  WHERE (id IN (SELECT id FROM linked) OR flow_id IN (SELECT flow_id FROM selected_flows))
    AND socket_id IS NOT NULL AND LTRIM(socket_id, '0') != ''
)
SELECT e.*,
  CASE WHEN e.id IN (SELECT id FROM seed_events) THEN 'selected'
       WHEN e.id IN (SELECT id FROM linked) THEN 'observed_id_link'
       WHEN e.category IN ('anettrace.flow', 'anettrace.socket.flow') THEN 'flow_context'
       ELSE 'socket_context' END AS relation
FROM events e
WHERE e.id IN (SELECT id FROM linked)
   OR (e.flow_id IN (SELECT flow_id FROM selected_flows)
       AND e.category IN ('anettrace.flow', 'anettrace.socket.flow'))
   OR (e.socket_id IN (SELECT socket_id FROM selected_sockets)
       AND (e.name IN ('socket allocation', 'socket lifetime')
            OR e.category IN ('anettrace.socket.state', 'anettrace.connect')))
ORDER BY e.ts, e.id;
