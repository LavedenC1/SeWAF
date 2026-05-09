from __future__ import annotations

from dataclasses import dataclass
from urllib.parse import unquote_plus

import joblib


def _preprocess(text: str) -> str:
    """Iterative URL-decode + whitespace normalisation + lowercase."""
    if not isinstance(text, str):
        text = str(text)
    for _ in range(3):
        decoded = unquote_plus(text)
        if decoded == text:
            break
        text = decoded
    return " ".join(text.split()).lower()

@dataclass
class DetectionResult:
    is_malicious: bool
    confidence: float      
    label: str             

class Detector:
    """
    WAF payload classifier.

    Parameters
    ----------
    model_path : str
        Path to the .pkl artefact produced by train.py.
    threshold : float
        Attack-probability threshold above which a request is blocked.
        Lower  → block more aggressively (fewer false negatives, more false positives).
        Higher → block more conservatively (fewer false positives, more false negatives).
        Default 0.5 matches standard argmax behaviour.
    """

    def __init__(self, model_path: str = "waf.pkl", threshold: float = 0.5) -> None:
        artefact = joblib.load(model_path)

        
        if isinstance(artefact, dict):
            self._model   = artefact["model"]
            self._classes = artefact["classes"]
        else:
            self._model   = artefact
            self._classes = list(artefact.classes_)

        
        
        self._attack_label = self._classes[-1]
        self._attack_idx   = self._classes.index(self._attack_label)
        self.threshold     = threshold

    

    def is_malicious(self, body: str) -> bool:
        """Quick boolean check — drop-in replacement for the original method."""
        return self.inspect(body).is_malicious

    def inspect(self, body: str) -> DetectionResult:
        """Full result with confidence score and raw label."""
        clean  = _preprocess(body)
        probas = self._model.predict_proba([clean])[0]

        attack_prob = float(probas[self._attack_idx])
        predicted   = self._classes[int(probas.argmax())]

        return DetectionResult(
            is_malicious=attack_prob >= self.threshold,
            confidence=round(attack_prob, 4),
            label=predicted,
        )

    def inspect_batch(self, bodies: list[str]) -> list[DetectionResult]:
        """Score multiple payloads in one call (faster than looping inspect())."""
        clean  = [_preprocess(b) for b in bodies]
        probas = self._model.predict_proba(clean)

        results = []
        for p in probas:
            attack_prob = float(p[self._attack_idx])
            predicted   = self._classes[int(p.argmax())]
            results.append(DetectionResult(
                is_malicious=attack_prob >= self.threshold,
                confidence=round(attack_prob, 4),
                label=predicted,
            ))
        return results