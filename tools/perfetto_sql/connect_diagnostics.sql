-- Stable query contract for TCP connect diagnostic evidence in Trace Processor.
SELECT
  s.ts,
  s.dur,
  s.name,
  EXTRACT_ARG(s.arg_set_id, 'debug.attempt_id') AS attempt_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.socket_instance_id') AS socket_instance_id,
  CAST(EXTRACT_ARG(s.arg_set_id, 'debug.uid') AS INT) AS uid,
  CAST(EXTRACT_ARG(s.arg_set_id, 'debug.tid') AS INT) AS tid,
  CAST(EXTRACT_ARG(s.arg_set_id, 'debug.fd') AS INT) AS fd,
  CAST(EXTRACT_ARG(s.arg_set_id, 'debug.result') AS INT) AS result,
  CAST(EXTRACT_ARG(s.arg_set_id, 'debug.error') AS INT) AS error,
  CAST(EXTRACT_ARG(s.arg_set_id, 'debug.async_pending') AS TEXT)
    IN ('true', '1') AS async_pending,
  EXTRACT_ARG(s.arg_set_id, 'debug.new_state_name') AS new_state_name,
  CAST(EXTRACT_ARG(s.arg_set_id, 'debug.exact') AS TEXT)
    IN ('true', '1') AS exact,
  EXTRACT_ARG(s.arg_set_id, 'debug.reason') AS reason
FROM slice s
WHERE s.category = 'anettrace.connect'
ORDER BY s.ts, s.id;
