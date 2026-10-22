"""Per-request filesystem inspection effort, independent of syntax depth."""
from enum import Enum


class EvidenceEffort(str, Enum):
    FULL = "Full"
    PARTIAL = "Partial"
    NONE = "None"

    def lower(self):
        return EvidenceEffort.PARTIAL if self is EvidenceEffort.FULL else EvidenceEffort.NONE


def evidence_effort(value):
    if isinstance(value, EvidenceEffort):
        return value
    if isinstance(value, str):
        for effort in EvidenceEffort:
            if effort.value.casefold() == value.casefold():
                return effort
    from .models import InputError
    raise InputError("effort must be Full, Partial or None")
