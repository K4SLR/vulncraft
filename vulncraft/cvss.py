import math
from typing import Dict, Tuple


class CVSS31Calculator:
    """Deterministic CVSS v3.1 Base Score calculator adhering strictly to FIRST.org specifications."""

    AV_WEIGHTS = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2}
    AC_WEIGHTS = {"L": 0.77, "H": 0.44}
    PR_UNCHANGED = {"N": 0.85, "L": 0.62, "H": 0.27}
    PR_CHANGED = {"N": 0.85, "L": 0.68, "H": 0.50}
    UI_WEIGHTS = {"N": 0.85, "R": 0.62}
    CIA_WEIGHTS = {"H": 0.56, "L": 0.22, "N": 0.0}

    REQUIRED_METRICS = {"AV", "AC", "PR", "UI", "S", "C", "I", "A"}

    @staticmethod
    def roundup(val: float) -> float:
        """Applies FIRST.org standard roundup function."""
        int_input = round(val * 100000)
        if (int_input % 10000) == 0:
            return int_input / 100000.0
        return (math.floor(int_input / 10000) + 1) / 10.0

    @classmethod
    def label_for_score(cls, score: float) -> str:
        """Maps a base score to official severity labels."""
        if score == 0.0:
            return "INFO"
        if score < 4.0:
            return "LOW"
        if score < 7.0:
            return "WARNING"
        if score < 9.0:
            return "HIGH"
        return "CRITICAL"

    @classmethod
    def calculate(cls, vector: str) -> Tuple[float, str]:
        """Calculates CVSS v3.1 base score and severity label from a metric vector string."""
        if not vector or not vector.strip():
            return 0.0, "INFO"

        clean = vector.strip()
        if clean.upper().startswith("CVSS:3.1/"):
            clean = clean[9:]
        elif clean.upper().startswith("CVSS:3.0/"):
            clean = clean[9:]

        metrics: Dict[str, str] = {}
        for part in clean.split("/"):
            if ":" not in part:
                continue
            k, v = part.split(":", 1)
            metrics[k.upper()] = v.upper()

        missing = cls.REQUIRED_METRICS - set(metrics.keys())
        if missing:
            raise ValueError(f"Missing required CVSS metrics: {', '.join(sorted(missing))}")

        scope = metrics["S"]
        if scope not in ("U", "C"):
            raise ValueError(f"Invalid Scope (S) metric: {scope}")

        try:
            av = cls.AV_WEIGHTS[metrics["AV"]]
            ac = cls.AC_WEIGHTS[metrics["AC"]]
            pr = cls.PR_CHANGED[metrics["PR"]] if scope == "C" else cls.PR_UNCHANGED[metrics["PR"]]
            ui = cls.UI_WEIGHTS[metrics["UI"]]
            c = cls.CIA_WEIGHTS[metrics["C"]]
            i = cls.CIA_WEIGHTS[metrics["I"]]
            a = cls.CIA_WEIGHTS[metrics["A"]]
        except KeyError as exc:
            raise ValueError(f"Invalid CVSS metric value: {exc}") from exc

        iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))
        if scope == "U":
            impact = 6.42 * iss
        else:
            impact = 7.52 * (iss - 0.029) - 3.25 * math.pow(iss - 0.02, 15)

        if impact <= 0:
            return 0.0, "INFO"

        exploitability = 8.22 * av * ac * pr * ui
        if scope == "U":
            base_score = cls.roundup(min(impact + exploitability, 10.0))
        else:
            base_score = cls.roundup(min(1.08 * (impact + exploitability), 10.0))

        return base_score, cls.label_for_score(base_score)