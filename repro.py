import tempfile
from pathlib import Path

from jsonnetx.legacy import LegacyOutput
from jsonnetx.pipeline import RenderPipeline, RenderError


with tempfile.TemporaryDirectory() as tmp:
    root = Path(tmp)
    (root / "legacy").mkdir()
    (root / "legacy" / "report.json").write_text("old-report")
    pipeline = RenderPipeline(root)
    imports = {"lib": {"x": 1}}
    outputs = {"legacy/report.json": "new", "z/last.json": "last"}
    _, closure = pipeline.closures.freeze(imports)
    _, manifest = pipeline.evaluator.evaluate(closure, outputs)
    good = pipeline.token({"legacy/report.json": manifest["legacy/report.json"]}, 1)
    try:
        pipeline.publish(imports, outputs, signatures={"legacy/report.json": good})
    except RenderError:
        pass
    try:
        LegacyOutput(root).read("legacy/report.json")
    except RuntimeError:
        print("REPRODUCED: rollback deleted an overwritten legacy output")
    else:
        raise AssertionError("baseline defect did not reproduce")
