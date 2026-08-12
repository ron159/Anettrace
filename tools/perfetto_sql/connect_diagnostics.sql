-- Stable query contract for TCP connect diagnostic evidence in Trace Processor.
SELECT
  s.ts,
  s.dur,
  s.name,
  EXTRACT_ARG(s.arg_set_id, 'debug.attempt_id') AS attempt_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.socket_instance_id') AS socket_instance_id,
  EXTRACT_ARG(s.arg_set_id, 'debug.uid') AS uid,
  EXTRACT_ARG(s.arg_set_id, 'debug.tid') AS tid,
  EXTRACT_ARG(s.arg_set_id, 'debug.fd') AS fd,
  EXTRACT_ARG(s.arg_set_id, 'debug.result') AS result,
  EXTRACT_ARG(s.arg_set_id, 'debug.error') AS error,
  EXTRACT_ARG(s.arg_set_id, 'debug.async_pending') AS async_pending,
  EXTRACT_ARG(s.arg_set_id, 'debug.new_state_name') AS new_state_name,
  EXTRACT_ARG(s.arg_set_id, 'debug.exact') AS exact,
  EXTRACT_ARG(s.arg_set_id, 'debug.reason') AS reason
FROM slice s
WHERE s.category = 'anettrace.connect'
ORDER BY s.ts, s.id;
