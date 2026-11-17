# iouringx admit rules

Traverse rings[ring_id].ops[opcode]; an opcode known to another ring is invalid. fd_type must belong to the selected opcode. offset, buffer_len, queue_depth and timeout_ms are integers, not booleans. For ranged opcodes, offset and buffer_len are within the opcode's inclusive min/max values. For opcodes with offset_exact or buffer_exact, those fields equal the exact values.

queue_depth and timeout_ms use the selected ring's inclusive limits regardless of opcode. Numeric validity for one operation cannot be inherited from another. The signing line includes all numeric values in their stable integer representation. Enforce HMAC, active key, iat window and replay protection, writing nonce/store only for allow.
