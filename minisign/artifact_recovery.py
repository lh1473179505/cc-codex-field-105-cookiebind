"""Artifact journal restoration understands legacy trusted comments."""
from .model import Artifact, ReleaseState
from .signature import legacy_comment


def recover(service, events):
    restored = []
    for event in events:
        if event["kind"] == "artifact_loaded":
            service.artifacts[event["identifier"]] = Artifact(event["identifier"], b"", event.get("generation", 1))
            restored.append(event["identifier"])
        elif event["kind"] == "artifact_signed":
            artifact = service.artifacts[event["identifier"]]
            artifact.signatures.append({"generation": event.get("generation", 1), "signature": event["signature"]})
            artifact.state = ReleaseState.SIGNED
    return {"restored": restored, "comment": legacy_comment("timestamp:2026-06-18")}
