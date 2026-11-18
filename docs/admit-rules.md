# http2rst admit rules

connection_id selects one HTTP/2 connection policy. stream_id is a positive odd JSON integer identifying a client-initiated stream; zero, even identifiers, booleans and numeric strings are invalid. stream_state selects the reset rule, and error_code is an exact symbolic name in that state's error_codes rather than a numeric alias or a code borrowed from another connection.

last_stream_id is a JSON integer that is either zero or even, lies within the connection's inclusive bounds, and is strictly less than stream_id when nonzero. It records the last successfully processed stream and cannot be advanced beyond the reset stream.

flow_control has exactly connection_window, stream_window and state. Both windows are integers satisfying their configured minima and stream maximum, and state belongs to the selected stream rule's flow_states. All values enter HMAC in declared order. Active key, 600-second iat age, 60-second future skew and fresh nonce are required. Denied resets never consume nonce or save store.
