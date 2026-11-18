import json
import tempfile
from .rings import Rings
from .transfer import begin, TransferCrash
from .leases import revoke
from .startup import recover
from .legacy_audit import key_audit

def main():
    with tempfile.TemporaryDirectory() as tmp:
        rings = Rings(tmp)
        try:
            begin(rings, 101, "pay-source", "pay-dest", crash=True)
        except TransferCrash:
            pass
        revoke(rings, 101)
        failures = recover(rings)
        view = key_audit(rings)
        locations = view["locations"]["101"]
        print(json.dumps({"recovery_failures": failures, "audit": view,
                          "half_migrated_key_duplicated": len(locations) == 2}, sort_keys=True))
        return 0 if failures and len(locations) == 2 else 1
