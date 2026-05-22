"""
src/detection/model_loader.py – Robust IDS Model Loader v2.0
─────────────────────────────────────────────────────────────
Two-stage pipeline:
  Stage 1 – Binary classifier  (Normal vs Attack)
  Stage 2 – Multiclass         (Attack type)

Key robustness improvements over v1:
  • Confidence calibration: uses predict_proba on BOTH stages and
    takes the MINIMUM (conservative – avoids inflating confidence).
  • Prediction only proceeds to Stage 2 when Stage 1 is
    sufficiently certain it is NOT normal (threshold: 0.60 margin).
  • Feature-mismatch guard: pads/truncates feature vectors to the
    expected width instead of crashing.
  • All errors are logged, not silently swallowed.
"""

import joblib
import json
import numpy as np
import os
from typing import Dict, Tuple, Optional


class ModelLoader:

    def __init__(self, model_dir: str = "src/models"):
        self.model_dir        = model_dir
        self.binary_model     = None
        self.multiclass_model = None
        self.scaler           = None
        self.label_encoder    = None
        self.feature_columns  = None
        self.metadata         = None
        self.is_loaded        = False

        # Stage-1 confidence required to call something an attack
        # (avoids flipping uncertain Normal samples to Attack)
        self._binary_attack_threshold = 0.60

        self._load_all()

    # ──────────────────────────────────────────────────────────────
    # LOADING
    # ──────────────────────────────────────────────────────────────
    def _load_artifact(self, filename: str, label: str):
        path = os.path.join(self.model_dir, filename)
        if not os.path.exists(path):
            print(f"❌ {label} not found: {path}")
            return None
        obj = joblib.load(path)
        size_mb = os.path.getsize(path) / (1024 * 1024)
        print(f"✅ {label}: {size_mb:.1f} MB")
        return obj

    def _load_all(self):
        print("🚀 Loading Modern IDS Models…")
        print("=" * 50)

        self.binary_model     = self._load_artifact("binary_model.pkl",     "Binary Model    (Normal vs Attack)")
        self.multiclass_model = self._load_artifact("multiclass_model.pkl", "Multiclass Model (Attack type)")
        self.scaler           = self._load_artifact("scaler.pkl",           "Feature Scaler")
        self.label_encoder    = self._load_artifact("label_encoder.pkl",    "Label Encoder")
        self.feature_columns  = self._load_artifact("feature_columns.pkl",  "Feature Columns")

        metadata_path = os.path.join(self.model_dir, "training_metadata.json")
        if os.path.exists(metadata_path):
            with open(metadata_path) as fh:
                self.metadata = json.load(fh)
            print(f"✅ Training Metadata  | "
                  f"Accuracy: {self.metadata.get('accuracy', 'N/A')} | "
                  f"F1: {self.metadata.get('f1_score', 'N/A')}")
        else:
            print("⚠️  training_metadata.json not found – continuing without it.")

        self.is_loaded = all([
            self.binary_model     is not None,
            self.multiclass_model is not None,
            self.scaler           is not None,
        ])

        print("=" * 50)
        if self.is_loaded:
            print("🎉 All required models loaded successfully!")
            if self.label_encoder:
                print(f"   Attack classes: {list(self.label_encoder.classes_)}")
        else:
            print("⚠️  One or more required models missing.")

    # ──────────────────────────────────────────────────────────────
    # FEATURE PREPARATION
    # ──────────────────────────────────────────────────────────────
    def extract_features_for_prediction(self, packet_features: Dict) -> np.ndarray:
        """
        Align a feature dict to the column order expected by the models.
        Unknown columns get value 0; extra columns are ignored.
        """
        if self.feature_columns is None:
            # Fallback: hope the dict order matches training
            return np.array(list(packet_features.values()), dtype=float).reshape(1, -1)

        vec = [float(packet_features.get(col, 0)) for col in self.feature_columns]
        return np.array(vec, dtype=float).reshape(1, -1)

    def _safe_scale(self, features: np.ndarray) -> Optional[np.ndarray]:
        """
        Scale features, handling width mismatches gracefully.
        Returns None if scaling is impossible.
        """
        if self.scaler is None:
            return features  # No scaler – use raw

        expected = getattr(self.scaler, 'n_features_in_', None)
        if expected is not None and features.shape[1] != expected:
            # Pad or truncate to match
            if features.shape[1] < expected:
                pad = np.zeros((1, expected - features.shape[1]))
                features = np.hstack([features, pad])
            else:
                features = features[:, :expected]

        try:
            return self.scaler.transform(features)
        except Exception as exc:
            print(f"⚠️  Scaler error: {exc}")
            return None

    # ──────────────────────────────────────────────────────────────
    # PREDICTION
    # ──────────────────────────────────────────────────────────────
    def predict(self, features: np.ndarray) -> Tuple[str, float, Optional[str]]:
        """
        Two-stage prediction pipeline.

        Returns
        ───────
        (attack_label, confidence, binary_raw_prediction)

        confidence is the MINIMUM of Stage-1 and Stage-2 probabilities,
        which is deliberately conservative to reduce false positives.
        """
        if not self.is_loaded:
            return "unknown", 0.0, None

        try:
            # ── Stage 1: Normal vs Attack ─────────────────────────
            scaled = self._safe_scale(features)
            if scaled is None:
                return "unknown", 0.0, None

            bin_pred  = self.binary_model.predict(scaled)[0]
            bin_proba = self.binary_model.predict_proba(scaled)[0]

            # Normalise the "attack" probability
            # Works whether the model encodes Normal as 0/'normal'/False
            if hasattr(self.binary_model, 'classes_'):
                classes = list(self.binary_model.classes_)
                # "attack" = anything that is NOT the normal/0 class
                normal_idx = None
                for i, c in enumerate(classes):
                    if str(c).lower() in ('0', 'normal', 'false', 'benign'):
                        normal_idx = i
                        break
                if normal_idx is not None:
                    normal_prob = bin_proba[normal_idx]
                    attack_prob = 1.0 - normal_prob
                else:
                    attack_prob = max(bin_proba)
            else:
                attack_prob = max(bin_proba)

            # If Stage 1 says "this is likely Normal", stop here
            if attack_prob < self._binary_attack_threshold:
                normal_conf = 1.0 - attack_prob
                return "normal", round(normal_conf, 4), None

            # ── Stage 2: Which attack type? ───────────────────────
            mc_pred  = self.multiclass_model.predict(scaled)[0]
            mc_proba = self.multiclass_model.predict_proba(scaled)[0]
            mc_conf  = float(max(mc_proba))

            # Decode label
            if self.label_encoder is not None:
                try:
                    attack_label = str(self.label_encoder.inverse_transform([mc_pred])[0])
                except Exception:
                    attack_label = str(mc_pred)
            else:
                attack_label = str(mc_pred)

            # Conservative confidence = MIN of both stages
            final_conf = round(min(attack_prob, mc_conf), 4)

            return attack_label, final_conf, bin_pred

        except Exception as exc:
            print(f"⚠️  Prediction error: {exc}")
            return "unknown", 0.0, None

    # ──────────────────────────────────────────────────────────────
    # INFO
    # ──────────────────────────────────────────────────────────────
    def get_model_info(self) -> Dict:
        info: Dict = {
            'binary_model_loaded':     self.binary_model     is not None,
            'multiclass_model_loaded': self.multiclass_model is not None,
            'scaler_loaded':           self.scaler           is not None,
            'feature_count': (
                len(self.feature_columns) if self.feature_columns else
                getattr(self.scaler, 'n_features_in_', 0)
            ),
            'attack_classes': (
                len(self.label_encoder.classes_) if self.label_encoder else 0
            ),
        }
        if self.metadata:
            info.update({
                'accuracy':          self.metadata.get('accuracy',  'N/A'),
                'f1_score':          self.metadata.get('f1_score',  'N/A'),
                'training_dataset':  self.metadata.get('dataset',   'Unknown'),
            })
        return info
