import math
from typing import Tuple


class CVSS31Calculator:
    """
    Deterministic FIRST.org CVSS v3.1 Base Score Calculator & Severity Labeler.
    Vector example: CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N
    """

    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}
    PR_WEIGHTS_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_WEIGHTS_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    UI_WEIGHTS = {"N": 0.85, "R": 0.62}
    CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}

    @staticmethod
    def roundup(val: float) -> float:
        int_input = round(val * 100000)
        if (int_input % 10000) == 0:
            return int_input / 100000.0
        else:
            return (math.floor(int_input / 10000) + 1) / 10.0

    @classmethod
    def calculate(cls, vector: str) -> Tuple[float, str]:
        if not vector or not vector.startswith("CVSS:3.1/"):
            raise ValueError(f"Invalid CVSS v3.1 vector string: {vector}")

        parts = vector.replace("CVSS:3.1/", "").split("/")
        metrics = {}
        for part in parts:
            if ":" not in part:
                raise ValueError(f"Malformed metric in CVSS vector: {part}")
            k, v = part.split(":", 1)
            metrics[k] = v

        required = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}
        missing = required - set(metrics.keys())
        if missing:
            raise ValueError(f"Missing CVSS metrics: {', '.join(sorted(missing))}")

        av = cls.AV_WEIGHTS[metrics["AV"]]
        ac = cls.AC_WEIGHTS[metrics["AC"]]
        scope_changed = metrics["S"] == "C"
        pr = (
            cls.PR_WEIGHTS_CHANGED[metrics["PR"]]
            if scope_changed
            else cls.PR_WEIGHTS_UNCHANGED[metrics["PR"]]
        )
        ui = cls.UI_WEIGHTS[metrics["UI"]]
        c = cls.CIA_WEIGHTS[metrics["C"]]
        i = cls.CIA_WEIGHTS[metrics["I"]]
        a = cls.CIA_WEIGHTS[metrics["A"]]

        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

        if not scope_changed:
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)

        exploitability = 8.22 * av * ac * pr * ui

        if impact <= 0:
            base_score = 0.0
        else:
            if not scope_changed:
                base_score = cls.roundup(min(impact + exploitability, 10.0))
            else:
                base_score = cls.roundup(min(1.08 * (impact + exploitability), 10.0))

        label = cls.score_to_label(base_score)
        return base_score, label

    @staticmethod
    def score_to_label(score: float) -> str:
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "WARNING"
        elif score > 0.0:
            return "LOW"
        return "INFO"
