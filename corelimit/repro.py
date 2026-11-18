import json
import tempfile
from .vault import Vault
from .capture import start, finish, SealFailure
from .cleaner import recover
from .usage import legacy_usage

def main():
    with tempfile.TemporaryDirectory() as tmp:
        vault = Vault(tmp)
        start(vault, "core-7", 256, "pay-api")
        try:
            finish(vault, "core-7", fail=True)
        except SealFailure:
            pass
        once = legacy_usage(vault)["used_bytes"]
        recover(vault)
        view = legacy_usage(vault)
        print(json.dumps({"used_before_recovery": once, "usage_after_recovery": view,
                          "double_release": view["used_bytes"] < 0}, sort_keys=True))
        return 0 if once == 0 and view["used_bytes"] == -256 else 1
