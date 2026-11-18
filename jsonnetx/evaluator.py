import hashlib
import json


class Evaluator:
    def evaluate(self, closure, outputs):
        rendered = {}
        for path, template in outputs.items():
            rendered[path] = json.dumps({
                "template": template,
                "imports": closure,
            }, sort_keys=True, indent=2) + "\n"
        manifest = {path: hashlib.sha256(raw.encode()).hexdigest() for path, raw in rendered.items()}
        return rendered, manifest
