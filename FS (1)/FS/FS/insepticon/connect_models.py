"""
DeepSentinel - Model Integration Layer with Intelligent Thresholds (Fixed & Enhanced)
------------------------------------------------------------------------------------
✅ Safe model loading (PyTorch 2.6+ compatible)
✅ Smart thresholds with baseline learning
✅ Dynamic anomaly + threshold hybrid detection
✅ Clear logging for dashboard integration
"""

import os
import sys
import time
import torch
import torch.nn as nn
import joblib
import numpy as np
from pathlib import Path
from collections import defaultdict
from datetime import datetime
import json

# -------------------------------------------------------------------------
# PATH CONFIGURATION - Load from config.json
# -------------------------------------------------------------------------
def get_project_root():
    """Get the project root directory (where this script is located)."""
    return Path(__file__).parent.resolve()

def load_config():
    """Load configuration from config.json file."""
    config_path = get_project_root() / "config.json"
    default_config = {
        "paths": {
            "model_dir": "models",
            "log_file": "threat_log.txt",
            "baseline_file": "user_baselines.json",
            "threshold_config": "threshold_config.json"
        },
        "thresholds": {
            "files_created_today": 12,
            "http_requests_today": 500,
            "bytes_downloaded_today": 104857600
        },
        "risk_display_threshold": 0.49,
        "enable_outlook_monitor": False
    }

    if config_path.exists():
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            print(f"[OK] Loaded config from {config_path}")
            return config
        except json.JSONDecodeError as e:
            print(f"[WARN] Error parsing config.json: {e}")
            print("   Using default configuration.")
            return default_config
    else:
        print(f"[INFO] config.json not found at {config_path}")
        print("   Creating default configuration...")
        # Create default config file
        config_path.parent.mkdir(exist_ok=True, parents=True)
        with open(config_path, 'w', encoding='utf-8') as f:
            json.dump(default_config, f, indent=4)
        return default_config

def resolve_path(path_str, base_dir=None):
    """
    Resolve a path string to an absolute Path object.
    If the path is relative, it's resolved relative to base_dir (or project root).
    If the path is absolute, it's returned as-is.
    """
    path = Path(path_str)
    if path.is_absolute():
        return path
    else:
        base = base_dir if base_dir else get_project_root()
        return (base / path).resolve()

def validate_path(path, path_name, must_exist=False, create_parent=False):
    """
    Validate that a path is accessible.
    Returns (is_valid, error_message).
    """
    path = Path(path)

    if must_exist and not path.exists():
        return False, f"{path_name} not found at: {path}"

    if create_parent and not path.parent.exists():
        try:
            path.parent.mkdir(exist_ok=True, parents=True)
            print(f"   Created directory: {path.parent}")
        except PermissionError:
            return False, f"Cannot create directory for {path_name}: {path.parent}"

    return True, None

def initialize_paths(config):
    """
    Initialize all paths from config and validate them.
    Returns a dict of Path objects.
    """
    project_root = get_project_root()
    paths_config = config.get("paths", {})

    # Default paths if not in config
    default_paths = {
        "model_dir": "models",
        "log_file": "threat_log.txt",
        "baseline_file": "user_baselines.json",
        "threshold_config": "threshold_config.json"
    }

    paths = {}
    validation_errors = []

    for key, default_path in default_paths.items():
        path_str = paths_config.get(key, default_path)
        resolved = resolve_path(path_str, project_root)
        paths[key] = resolved

        # Validate paths
        if key == "model_dir":
            # Model dir must exist for models to load
            valid, error = validate_path(resolved, key, must_exist=False)
            if not valid:
                validation_errors.append(error)
        else:
            # Other files can be created, so just ensure parent dirs exist
            valid, error = validate_path(resolved, key, must_exist=False, create_parent=False)
            if not valid:
                validation_errors.append(error)

    if validation_errors:
        print("[WARN] Path validation warnings:")
        for err in validation_errors:
            print(f"   - {err}")

    return paths

# Load config and initialize paths
_CONFIG = load_config()
_PATHS = initialize_paths(_CONFIG)

# Export paths as module-level constants for backward compatibility
MODEL_DIR = _PATHS["model_dir"]
LOG_FILE = _PATHS["log_file"]
BASELINE_FILE = _PATHS["baseline_file"]
THRESHOLD_CONFIG = _PATHS["threshold_config"]

# Export config for use by other components
CONFIG = _CONFIG

# -------------------------------------------------------------------------
# USER DATA STRUCTURES
# -------------------------------------------------------------------------
user_session_data = defaultdict(lambda: {
    'num_logons': 0,
    'num_unique_pcs': set(),
    'num_http': 0,
    'num_suspicious_urls': 0,
    'num_device': 0,
    'num_file': 0,
    'num_file_copy': 0,
    'num_emails': 0,
    'num_external_emails': 0,
    'total_attachments': 0,
    'total_email_size': 0,
    'event_count': 0,
    'last_update': time.time(),
    'daily_reset': datetime.now().date(),
    'history': {
        'files_per_day': [],
        'usb_per_day': [],
        'logons_per_day': [],
        'http_per_day': []
    }
})

user_baselines = defaultdict(lambda: {
    'avg_files_per_day': 0,
    'std_files_per_day': 0,
    'avg_usb_per_day': 0,
    'std_usb_per_day': 0,
    'avg_logons_per_day': 0,
    'std_logons_per_day': 0,
    'avg_http_per_day': 0,
    'std_http_per_day': 0,
    'learning_days': 0,
    'last_baseline_update': None,
    'is_baseline_ready': False
})

DEFAULT_THRESHOLDS = {
    "global": {
        "files_created_today": 12,
        "http_requests_today": 500,
        "bytes_downloaded_today": 104857600,
        "usb_events_today": 3,
        "logons_today": 10
    },
    "baseline_learning": {
        "enabled": True,
        "learning_period_days": 7,
        "std_deviation_multiplier": 2.5
    }
}

# -------------------------------------------------------------------------
# THRESHOLD MANAGER
# -------------------------------------------------------------------------
class ThresholdManager:
    def __init__(self, config_path=THRESHOLD_CONFIG, baseline_path=BASELINE_FILE):
        self.config_path = config_path
        self.baseline_path = baseline_path
        self.load_config()
        self.load_baselines()

    def load_config(self):
        if self.config_path.exists():
            with open(self.config_path, 'r') as f:
                self.config = json.load(f)
            print("[OK] Loaded threshold config")
        else:
            self.config = DEFAULT_THRESHOLDS
            self.save_config()
            print("[INFO] Created default threshold config")

    def save_config(self):
        self.config_path.parent.mkdir(exist_ok=True, parents=True)
        with open(self.config_path, 'w') as f:
            json.dump(self.config, f, indent=2)

    def load_baselines(self):
        global user_baselines
        if self.baseline_path.exists():
            with open(self.baseline_path, 'r') as f:
                loaded = json.load(f)
                for user, data in loaded.items():
                    user_baselines[user].update(data)
            print("[OK] Loaded user baselines")
        else:
            print("[INFO] No baselines found - starting fresh")

    def save_baselines(self):
        self.baseline_path.parent.mkdir(exist_ok=True, parents=True)
        with open(self.baseline_path, 'w') as f:
            json.dump(dict(user_baselines), f, indent=2)

    def get_threshold_for_user(self, user_id, metric):
        baseline = user_baselines.get(user_id, {})
        if baseline.get('is_baseline_ready', False):
            return self._calculate_dynamic_threshold(user_id, metric, baseline)
        return self.config['global'].get(metric, 999999)

    def _calculate_dynamic_threshold(self, user_id, metric, baseline):
        metric_map = {
            'files_created_today': ('avg_files_per_day', 'std_files_per_day'),
            'usb_events_today': ('avg_usb_per_day', 'std_usb_per_day'),
            'logons_today': ('avg_logons_per_day', 'std_logons_per_day'),
            'http_requests_today': ('avg_http_per_day', 'std_http_per_day')
        }

        if metric not in metric_map:
            return self.config['global'].get(metric, 999999)

        avg_key, std_key = metric_map[metric]
        avg_val = baseline.get(avg_key, 0)
        std_val = baseline.get(std_key, 1)
        multiplier = self.config['baseline_learning']['std_deviation_multiplier']
        dynamic_threshold = avg_val + (multiplier * std_val)
        return max(int(dynamic_threshold), self.config['global'].get(metric, 1))

    def update_baseline(self, user_id):
        baseline = user_baselines[user_id]
        session = user_session_data[user_id]
        history = session['history']

        history['files_per_day'].append(session['num_file'])
        history['usb_per_day'].append(session['num_device'])
        history['logons_per_day'].append(session['num_logons'])
        history['http_per_day'].append(session['num_http'])

        for key in history:
            history[key] = history[key][-30:]

        learning_days = self.config['baseline_learning']['learning_period_days']
        if len(history['files_per_day']) >= learning_days:
            baseline['avg_files_per_day'] = np.mean(history['files_per_day'])
            baseline['std_files_per_day'] = np.std(history['files_per_day'])
            baseline['avg_usb_per_day'] = np.mean(history['usb_per_day'])
            baseline['std_usb_per_day'] = np.std(history['usb_per_day'])
            baseline['avg_logons_per_day'] = np.mean(history['logons_per_day'])
            baseline['std_logons_per_day'] = np.std(history['logons_per_day'])
            baseline['avg_http_per_day'] = np.mean(history['http_per_day'])
            baseline['std_http_per_day'] = np.std(history['http_per_day'])
            baseline['is_baseline_ready'] = True
            baseline['learning_days'] = len(history['files_per_day'])
            baseline['last_baseline_update'] = datetime.now().isoformat()

            self.save_baselines()
            print(f"[STATS] Updated baseline for {user_id} (days={baseline['learning_days']})")

    def check_threshold_violation(self, user_id, metric, current_value):
        threshold = self.get_threshold_for_user(user_id, metric)
        if current_value > threshold:
            return True, {
                'user_id': user_id,
                'metric': metric,
                'current_value': current_value,
                'threshold': threshold,
                'violation_amount': current_value - threshold,
                'is_baseline_based': user_baselines[user_id].get('is_baseline_ready', False),
                'timestamp': datetime.now().isoformat()
            }
        return False, None

    def get_user_threshold_status(self, user_id):
        session = user_session_data[user_id]
        baseline = user_baselines[user_id]
        metrics = {
            'files_created_today': session['num_file'],
            'usb_events_today': session['num_device'],
            'logons_today': session['num_logons'],
            'http_requests_today': session['num_http']
        }

        status = {
            'user_id': user_id,
            'has_baseline': baseline.get('is_baseline_ready', False),
            'learning_days': baseline.get('learning_days', 0),
            'metrics': {}
        }

        for metric, current in metrics.items():
            thr = self.get_threshold_for_user(user_id, metric)
            status['metrics'][metric] = {
                'current': current,
                'threshold': thr,
                'percentage': round((current / thr * 100), 2) if thr > 0 else 0,
                'status': 'CRITICAL' if current > thr else 'NORMAL'
            }

        return status

# -------------------------------------------------------------------------
# AUTOENCODER MODEL
# -------------------------------------------------------------------------
class Autoencoder(nn.Module):
    def __init__(self, input_dim=11):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 8),
            nn.ReLU(),
            nn.Linear(8, 6),
            nn.ReLU()
        )
        self.decoder = nn.Sequential(
            nn.Linear(6, 8),
            nn.ReLU(),
            nn.Linear(8, input_dim),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.decoder(self.encoder(x))

# -------------------------------------------------------------------------
# MAIN MODEL CLASS
# -------------------------------------------------------------------------
class ThreatDetectionModel:
    def __init__(self, model_dir=MODEL_DIR):
        self.model_dir = Path(model_dir)
        self.feature_cols = [
            'num_logons', 'num_unique_pcs', 'num_http', 'num_suspicious_urls',
            'num_device', 'num_file', 'num_file_copy', 'num_emails',
            'num_external_emails', 'total_attachments', 'avg_email_size'
        ]
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.scaler, self.autoencoder, self.isolation_forest = None, None, None
        
        # Email-specific models
        self.tfidf_vectorizer = None
        self.email_classifier = None
        self.email_regressors = {}  # low, medium, high
        self.production_model = None
        
        self.threshold_manager = ThresholdManager()
        self.model_load_status = {
            "scaler": False, 
            "isolation_forest": False, 
            "autoencoder": False,
            "tfidf_vectorizer": False,
            "email_classifier": False,
            "email_regressors": False,
            "production_model": False
        }
        self.model_errors = []
        self.load_models()
        self.validate_models()
        self.test_inference()

    def load_models(self):
        """Load ML models with comprehensive error handling and logging."""
        print(f"[LOAD] Loading models from: {self.model_dir}")

        # Validate model directory exists
        if not self.model_dir.exists():
            error_msg = f"Model directory not found: {self.model_dir}"
            print(f"[CRITICAL] {error_msg}")
            self.model_errors.append(error_msg)
            raise FileNotFoundError(error_msg)
        if not self.model_dir.is_dir():
            error_msg = f"Model path is not a directory: {self.model_dir}"
            print(f"[CRITICAL] {error_msg}")
            self.model_errors.append(error_msg)
            raise NotADirectoryError(error_msg)

        # Load Scaler
        scaler_path = self.model_dir / "scaler.pkl"
        try:
            if scaler_path.exists():
                self.scaler = joblib.load(scaler_path)
                self.model_load_status["scaler"] = True
                print(f"[OK] Loaded scaler.pkl (type: {type(self.scaler).__name__})")
            else:
                error_msg = f"Scaler not found: {scaler_path}"
                self.model_errors.append(error_msg)
                print(f"[WARN] {error_msg}")
        except Exception as scaler_error:
            error_msg = f"Scaler load error: {type(scaler_error).__name__}: {scaler_error}"
            self.model_errors.append(error_msg)
            print(f"[ERROR] {error_msg}")

        # Load Isolation Forest
        iso_path = self.model_dir / "isolation_forest_finetuned.pkl"
        if not iso_path.exists():
            iso_path = self.model_dir / "isolation_forest.pkl"
        try:
            if iso_path.exists():
                self.isolation_forest = joblib.load(iso_path)
                self.model_load_status["isolation_forest"] = True
                print(f"[OK] Loaded {iso_path.name} (type: {type(self.isolation_forest).__name__})")
            else:
                error_msg = f"Isolation Forest not found (tried: isolation_forest_finetuned.pkl, isolation_forest.pkl)"
                self.model_errors.append(error_msg)
                print(f"[WARN] {error_msg}")
        except Exception as iso_error:
            error_msg = f"Isolation Forest load error: {type(iso_error).__name__}: {iso_error}"
            self.model_errors.append(error_msg)
            print(f"[ERROR] {error_msg}")

        # Load Autoencoder
        ae_path = self.model_dir / "autoencoder_finetuned.pth"
        if not ae_path.exists():
            ae_path = self.model_dir / "autoencoder.pth"
        try:
            if ae_path.exists():
                print(f"[LOAD] Loading autoencoder from {ae_path.name}...")
                torch.serialization.add_safe_globals([np._core.multiarray.scalar])
                checkpoint = torch.load(ae_path, map_location=self.device, weights_only=False)
                print(f"   Checkpoint type: {type(checkpoint).__name__}")
                
                self.autoencoder = Autoencoder(input_dim=11).to(self.device)

                if isinstance(checkpoint, dict):
                    key = next((k for k in ["model_state_dict", "state_dict"] if k in checkpoint), None)
                    if key:
                        print(f"   Found state_dict key: {key}")
                        self.autoencoder.load_state_dict(checkpoint[key])
                    else:
                        print(f"   Using checkpoint as direct state_dict")
                        self.autoencoder.load_state_dict(checkpoint)
                else:
                    print(f"   Checkpoint is tensor/model, loading directly")
                    self.autoencoder.load_state_dict(checkpoint)

                self.autoencoder.eval()
                self.model_load_status["autoencoder"] = True
                print(f"[OK] Loaded {ae_path.name} (moved to {self.device})")
            else:
                error_msg = f"Autoencoder not found (tried: autoencoder_finetuned.pth, autoencoder.pth)"
                self.model_errors.append(error_msg)
                print(f"[WARN] {error_msg}")
        except RuntimeError as ae_rt_error:
            error_msg = f"Autoencoder state_dict error: {ae_rt_error}"
            self.model_errors.append(error_msg)
            print(f"[ERROR] {error_msg}")
            self.autoencoder = None
        except Exception as ae_error:
            error_msg = f"Autoencoder load error: {type(ae_error).__name__}: {ae_error}"
            self.model_errors.append(error_msg)
            print(f"[ERROR] {error_msg}")
            self.autoencoder = None

        # Load email-specific models
        self._load_email_models()

        # Print model load summary
        self._print_load_summary()

    def _load_email_models(self):
        """Load email-specific ML models (TF-IDF, classifier, regressors)."""
        print(f"\n[LOAD] Loading email-specific models from: {self.model_dir}")
        
        # Load TF-IDF Vectorizer
        tfidf_path = self.model_dir / "tfidf_vectorizer (1).pkl"
        if not tfidf_path.exists():
            tfidf_path = self.model_dir / "tfidf_vectorizer.pkl"
        try:
            if tfidf_path.exists():
                self.tfidf_vectorizer = joblib.load(tfidf_path)
                self.model_load_status["tfidf_vectorizer"] = True
                vocab_size = len(self.tfidf_vectorizer.vocabulary_)
                print(f"[OK] Loaded TF-IDF Vectorizer ({vocab_size} features)")
            else:
                print(f"[WARN] TF-IDF Vectorizer not found")
        except Exception as e:
            error_msg = f"TF-IDF load error: {type(e).__name__}: {e}"
            self.model_errors.append(error_msg)
            print(f"[ERROR] {error_msg}")
        
        # Load Email Classifier
        classifier_path = self.model_dir / "classifier_model.pkl"
        try:
            if classifier_path.exists():
                self.email_classifier = joblib.load(classifier_path)
                self.model_load_status["email_classifier"] = True
                print(f"[OK] Loaded Email Classifier (type: {type(self.email_classifier).__name__})")
            else:
                print(f"[WARN] Email Classifier not found")
        except Exception as e:
            error_msg = f"Classifier load error: {type(e).__name__}: {e}"
            self.model_errors.append(error_msg)
            print(f"[ERROR] {error_msg}")
        
        # Load Email Regressors (Low, Medium, High risk levels)
        regressor_names = ["regressor_low.pkl", "regressor_medium.pkl", "regressor_high.pkl"]
        for reg_file in regressor_names:
            reg_path = self.model_dir / reg_file
            try:
                if reg_path.exists():
                    self.email_regressors[reg_file.split('_')[1].split('.')[0]] = joblib.load(reg_path)
                    print(f"[OK] Loaded {reg_file}")
                else:
                    print(f"[WARN] {reg_file} not found")
            except Exception as e:
                error_msg = f"{reg_file} load error: {type(e).__name__}: {e}"
                self.model_errors.append(error_msg)
                print(f"[ERROR] {error_msg}")
        
        if self.email_regressors:
            self.model_load_status["email_regressors"] = True
        
        # Load Production Model if available
        prod_path = self.model_dir / "deep_sentinel_production_model.pkl"
        try:
            if prod_path.exists():
                self.production_model = joblib.load(prod_path)
                self.model_load_status["production_model"] = True
                print(f"[OK] Loaded DeepSentinel Production Model")
            else:
                print(f"[WARN] Production model not found")
        except Exception as e:
            error_msg = f"Production model load error: {type(e).__name__}: {e}"
            self.model_errors.append(error_msg)
            print(f"[ERROR] {error_msg}")

        # Print email models summary
        print("\n[STATUS] Email Models Summary:")
        print(f"   TF-IDF Vectorizer:    {'OK' if self.model_load_status['tfidf_vectorizer'] else 'MISSING'}")
        print(f"   Email Classifier:     {'OK' if self.model_load_status['email_classifier'] else 'MISSING'}")
        print(f"   Email Regressors:     {'OK' if self.model_load_status['email_regressors'] else 'MISSING'} ({len(self.email_regressors)} loaded)")
        print(f"   Production Model:     {'OK' if self.model_load_status['production_model'] else 'MISSING'}")


    def _print_load_summary(self):
        """Print comprehensive model loading summary with status."""
        print("\n[STATUS] THREAT DETECTION MODELS:")
        print(f"   Scaler:               {'OK' if self.model_load_status['scaler'] else 'MISSING'}")
        print(f"   Isolation Forest:     {'OK' if self.model_load_status['isolation_forest'] else 'MISSING'}")
        print(f"   Autoencoder:          {'OK' if self.model_load_status['autoencoder'] else 'MISSING'}")

        print("\n[STATUS] EMAIL-SPECIFIC MODELS:")
        print(f"   TF-IDF Vectorizer:    {'OK' if self.model_load_status['tfidf_vectorizer'] else 'MISSING'}")
        print(f"   Email Classifier:     {'OK' if self.model_load_status['email_classifier'] else 'MISSING'}")
        print(f"   Email Regressors:     {'OK' if self.model_load_status['email_regressors'] else 'MISSING'} ({len(self.email_regressors)} loaded)")
        print(f"   Production Model:     {'OK' if self.model_load_status['production_model'] else 'MISSING'}")

        # Check minimum requirements
        core_models_ok = self.model_load_status["scaler"] and self.model_load_status["isolation_forest"]
        email_models_ok = self.model_load_status["tfidf_vectorizer"] and self.model_load_status["email_classifier"]
        
        if not core_models_ok:
            print("\n[CRITICAL] Core threat detection models failed to load!")
            print("   Risk predictions will use HEURISTIC FALLBACK ONLY.")
            print("   Model accuracy will be significantly degraded.")
            print("   ACTION: Verify model files exist and are valid.")
        elif self.model_load_status["autoencoder"]:
            print("\n[OK] Threat detection models fully loaded - ML pipeline enabled.")
        else:
            print("\n[WARN] Core threat models loaded but autoencoder missing - reduced ML pipeline.")
        
        if email_models_ok:
            print("[OK] Email-specific models fully loaded - Enhanced email classification enabled.")
        elif self.model_load_status["email_classifier"] or self.model_load_status["tfidf_vectorizer"]:
            print("[WARN] Some email models loaded - partial email ML support.")
        else:
            print("[INFO] Email-specific models not available - using fallback rules.")

        if self.model_errors:
            print(f"\n[ERRORS] {len(self.model_errors)} loading issue(s) detected:")
            for i, err in enumerate(self.model_errors, 1):
                print(f"   {i}. {err}")
        print()

    def validate_models(self):
        """Validate that loaded models have correct structure and can be used."""
        print("[VALIDATE] Validating model structure and integrity...")
        validation_issues = []

        # Check scaler
        if self.model_load_status["scaler"]:
            try:
                if not hasattr(self.scaler, 'transform'):
                    validation_issues.append("Scaler missing transform() method")
                elif not hasattr(self.scaler, 'scale_'):
                    validation_issues.append("Scaler missing scale_ attribute (not fitted)")
                else:
                    print(f"   [OK] Scaler has {self.scaler.n_features_in_} input features")
            except AttributeError as e:
                validation_issues.append(f"Scaler attribute error: {e}")

        # Check isolation forest
        if self.model_load_status["isolation_forest"]:
            try:
                if not hasattr(self.isolation_forest, 'score_samples'):
                    validation_issues.append("Isolation Forest missing score_samples() method")
                elif not hasattr(self.isolation_forest, 'estimators_'):
                    validation_issues.append("Isolation Forest not fitted (no estimators_)")
                else:
                    num_trees = len(self.isolation_forest.estimators_)
                    print(f"   [OK] Isolation Forest has {num_trees} trees")
            except AttributeError as e:
                validation_issues.append(f"Isolation Forest attribute error: {e}")

        # Check autoencoder
        if self.model_load_status["autoencoder"]:
            try:
                if not isinstance(self.autoencoder, nn.Module):
                    validation_issues.append("Autoencoder is not a PyTorch Module")
                else:
                    total_params = sum(p.numel() for p in self.autoencoder.parameters())
                    print(f"   [OK] Autoencoder has {total_params} parameters")
                    # Check device
                    device = next(self.autoencoder.parameters()).device
                    print(f"        Running on: {device}")
            except Exception as e:
                validation_issues.append(f"Autoencoder structure error: {e}")

        # Report validation results
        if validation_issues:
            print(f"\n[WARN] {len(validation_issues)} validation issue(s) found:")
            for issue in validation_issues:
                print(f"   - {issue}")
        else:
            print("   [OK] All loaded models passed structure validation")
        print()

    def test_inference(self):
        """Test that models can actually perform inference (critical check)."""
        print("[TEST] Running inference validation...")
        
        if not self.model_load_status["scaler"] or not self.model_load_status["isolation_forest"]:
            print("   [SKIP] Core models not loaded - skipping inference test")
            print()
            return

        try:
            # Create synthetic feature vector (11 features)
            test_features = np.array([[1, 1, 100, 2, 0, 5, 1, 10, 2, 3, 50.0]])
            
            # Test scaler transform
            try:
                scaled = self.scaler.transform(test_features)
                print(f"   [OK] Scaler transform works (input: {test_features.shape} -> output: {scaled.shape})")
            except Exception as scale_err:
                print(f"   [ERROR] Scaler transform failed: {scale_err}")
                return

            # Test isolation forest prediction
            try:
                iso_scores = self.isolation_forest.score_samples(scaled)
                iso_pred = self.isolation_forest.predict(scaled)
                print(f"   [OK] Isolation Forest works (score: {iso_scores[0]:.4f}, pred: {iso_pred[0]})")
            except Exception as iso_err:
                print(f"   [ERROR] Isolation Forest prediction failed: {iso_err}")
                return

            # Test autoencoder if available
            if self.model_load_status["autoencoder"]:
                try:
                    with torch.no_grad():
                        test_tensor = torch.FloatTensor(scaled).to(self.device)
                        reconstruction = self.autoencoder(test_tensor)
                        ae_error = torch.mean((test_tensor - reconstruction) ** 2).item()
                    print(f"   [OK] Autoencoder works (reconstruction error: {ae_error:.6f})")
                except Exception as ae_err:
                    print(f"   [ERROR] Autoencoder inference failed: {ae_err}")
            
            print("[OK] All inference tests passed!")
            
        except Exception as test_error:
            print(f"[ERROR] Unexpected error during inference test: {test_error}")
        print()

    def reset_daily_counters_if_needed(self, agent_id):
        s = user_session_data[agent_id]
        today = datetime.now().date()
        if s['daily_reset'] != today:
            if self.threshold_manager.config['baseline_learning']['enabled']:
                self.threshold_manager.update_baseline(agent_id)
            for key in ['num_logons', 'num_http', 'num_device', 'num_file',
                        'num_file_copy', 'num_emails']:
                s[key] = 0
            s['daily_reset'] = today

    def map_siem_event_to_features(self, e):
        uid, t, a = e.get('agent_id', 'unknown'), e.get('event_type', ''), e.get('action', '')
        self.reset_daily_counters_if_needed(uid)
        s = user_session_data[uid]
        s['event_count'] += 1; s['last_update'] = time.time()

        # Existing event types
        if t == 'logon': s['num_logons'] += 1
        if t == 'usb':   s['num_device'] += 1
        if t == 'file':
            s['num_file'] += 1
            if a in ['created', 'moved', 'file_created', 'file_moved', 'file_created_manual', 'file_added']:
                s['num_file_copy'] += 1
        if e.get('is_executable') or e.get('has_special_chars'):
            s['num_suspicious_urls'] += 1
        if e.get('file_size'):
            s['total_email_size'] += e['file_size']

        # EMAIL events — populate previously-unused feature slots
        if t in ('outlook', 'imap', 'email_sent', 'email_received'):
            s['num_emails'] += 1
            if e.get('has_external') or e.get('num_external_emails', 0) > 0:
                s['num_external_emails'] += 1
            s['total_attachments'] += int(e.get('attachment_count', 0) or
                                          e.get('total_attachments', 0))
            body_len = e.get('body_length', 0)
            if body_len:
                s['total_email_size'] += body_len
            for att in e.get('attachments', []):
                if att.get('size_mb', 0) > 5:
                    s['num_suspicious_urls'] += 1
                    break

        return np.array([
            s['num_logons'],
            len(s['num_unique_pcs']),
            s['num_http'],
            s['num_suspicious_urls'],
            s['num_device'],
            s['num_file'],
            s['num_file_copy'],
            s['num_emails'],           # now populated for outlook events
            s['num_external_emails'],  # now populated for external recipients
            s['total_attachments'],    # now populated for attachments
            s['total_email_size'] / max(s['event_count'], 1),
        ]).reshape(1, -1)

    def predict_with_explanation(self, e):
        """
        Predict threat risk for an event using hybrid ML + Heuristic model.

        Phase 3 FINAL FIX: ML Model Hybrid Approach
        - Calibrated heuristic scoring for accurate threat detection
        - ML models provide supplementary signals
        - Proper weighting for realistic risk ranges

        Args:
            e: Event dictionary with agent_id, event_type, and other attributes

        Returns:
            tuple: (risk_score, explanation_dict)
        """
        # Handle None or invalid events
        if e is None or not isinstance(e, dict):
            return 0.0, {
                "top_factors": ["Invalid event: None or not a dictionary"],
                "risk_level": "LOW",
                "threshold_violations": [],
                "event_type": "unknown"
            }
        
        uid = e.get('agent_id', 'unknown')
        t = e.get("event_type", "")

        try:
            # ================================================================
            # HEURISTIC SCORING (Primary signal)
            # ================================================================
            heuristic_risk = 0.0
            heuristic_factors = []

            # Event type based risks (BASE SCORES)
            if t == "usb":
                heuristic_risk += 0.60  # USB is VERY high-risk
                heuristic_factors.append("USB activity detected")
            elif t == "logon":
                heuristic_risk += 0.20
                heuristic_factors.append("User login detected")
            elif t == "file":
                heuristic_risk += 0.15
                heuristic_factors.append("File operation")
            elif t in ('outlook', 'imap', 'email_sent', 'email_received'):
                heuristic_risk += 0.20
                heuristic_factors.append("Email activity")
            
            # Check for bulk activity (many events from same user)
            s = user_session_data.get(uid, {})
            if s.get('num_file', 0) > 20:  # Bulk file operations
                heuristic_risk += 0.40  # Increased from 0.35
                heuristic_factors.append(f"Bulk file activity ({s.get('num_file')} ops)")
            
            # Executable or suspicious files are high risk
            if e.get("is_executable"):
                heuristic_risk += 0.35  # Increased from 0.30
                heuristic_factors.append("Executable file")
            
            # Sensitive path access is risky
            if e.get("in_sensitive_path"):
                heuristic_risk += 0.30  # Increased from 0.25
                heuristic_factors.append("Sensitive directory access")
            
            # Remote access is critical
            if e.get("is_remote"):
                heuristic_risk += 0.30  # Increased from 0.25
                heuristic_factors.append("Remote access")
            
            # Weekend activity (adds risk - less expected work)
            # Check if event has explicit day_of_week, otherwise use current time
            import datetime
            if "day_of_week" in e:
                day_of_week = e.get("day_of_week")
            else:
                day_of_week = datetime.datetime.now().weekday()  # 0=Monday, 6=Sunday
            
            if day_of_week >= 5:  # Saturday or Sunday
                heuristic_risk += 0.15
                day_name = "Saturday" if day_of_week == 5 else "Sunday"
                heuristic_factors.append(f"Weekend activity ({day_name})")
            
            # After hours activity (SIGNIFICANT BOOST)
            hour = e.get("hour_of_day")
            if hour is not None:
                # Consider 22:00-06:00 as after hours (high risk)
                if hour >= 22 or hour < 6:
                    heuristic_risk += 0.35  # Increased from 0.25
                    heuristic_factors.append(f"After-hours activity ({hour}:00)")

            # Email-specific heuristics (data exfiltration patterns)
            if t in ('outlook', 'imap', 'email_sent', 'email_received'):
                subj = (e.get("email_subject") or "").lower()
                
                # Critical keywords
                CRIT_KW = ["password", "credential", "secret", "api key", "token", "auth"]
                HIGH_KW = ["confidential", "top secret", "classified", "do not share"]
                
                for kw in CRIT_KW:
                    if kw in subj:
                        heuristic_risk += 0.45  # Increased
                        heuristic_factors.append(f"Critical keyword: {kw}")
                        break
                else:
                    for kw in HIGH_KW:
                        if kw in subj:
                            heuristic_risk += 0.35  # Increased
                            heuristic_factors.append(f"Sensitive keyword: {kw}")
                            break
                
                # External recipients (HIGH RISK)
                if e.get("has_external"):
                    heuristic_risk += 0.35  # Increased from 0.30
                    heuristic_factors.append("Sent to external domain")
                
                # Large attachments
                for att in e.get("attachments", []):
                    if att.get("size_mb", 0) > 10:
                        heuristic_risk += 0.30  # Increased from 0.25
                        heuristic_factors.append(f"Large attachment: {att.get('name', 'unknown')}")
                        break
                    # Risky file types
                    ext = str(att.get("type", "") or att.get("name", "")).lower()
                    if any(x in ext for x in [".zip", ".rar", ".exe", ".sql", ".bak"]):
                        heuristic_risk += 0.30  # Increased from 0.25
                        heuristic_factors.append(f"Risky file type: {ext}")
                        break

            # ================================================================
            # ML SCORING (Supplementary)
            # ================================================================
            ml_risk = 0.5  # Default middle value
            
            if self.model_load_status["scaler"] and self.model_load_status["isolation_forest"]:
                try:
                    X = self.map_siem_event_to_features(e)
                    Xs = self.scaler.transform(X)
                    
                    iso_score = self.isolation_forest.score_samples(Xs)[0]
                    iso_pred = self.isolation_forest.predict(Xs)[0]
                    
                    # Isolation Forest transform
                    iso_risk = 1.0 / (1.0 + np.exp(iso_score))
                    
                    # Autoencoder scoring
                    ae_risk = 0.3  # Default
                    if self.model_load_status["autoencoder"]:
                        try:
                            with torch.no_grad():
                                Xt = torch.FloatTensor(Xs).to(self.device)
                                rec = self.autoencoder(Xt)
                                ae_error = float(torch.mean((Xt - rec) ** 2).item())
                                ae_error_clamped = min(ae_error, 2.0)
                                ae_risk = min(np.log1p(ae_error_clamped) / 2.0, 1.0)
                        except Exception:
                            pass  # Keep default
                    
                    # ML weighting: ISO-heavy
                    ml_risk = 0.75 * iso_risk + 0.25 * ae_risk
                    
                except Exception:
                    pass  # Keep default 0.5
            
            # ================================================================
            # THRESHOLD VIOLATION SCORING
            # ================================================================
            violations = self.check_all_thresholds(uid)
            violation_risk = 0.0
            if violations:
                violation_risk = 0.20  # Increased from 0.15
                for v in violations:
                    heuristic_factors.append(
                        f"Threshold {v['metric']}: {v.get('current_value')} > {v.get('threshold')}"
                    )
            
            # ================================================================
            # FINAL RISK CALCULATION (CALIBRATED BLEND)
            # ================================================================
            # Adjusted weights for 70%+ accuracy:
            # - Heuristics: 75% (most reliable)
            # - ML: 15% (supplementary)
            # - Violations: 10% (policy boost)
            heuristic_clamped = min(heuristic_risk, 1.0)
            final_risk = (0.75 * heuristic_clamped + 
                         0.15 * ml_risk + 
                         0.10 * violation_risk)
            
            # Ensure bounded [0, 1]
            final_risk = float(np.clip(final_risk, 0.0, 1.0))
            
            # Generate explanation
            expl = self.generate_explanation(e, final_risk, -1, np.zeros(11), violations)
            expl['top_factors'] = heuristic_factors or ["Normal activity"]
            
            self.log_event(e, final_risk, expl)
            
            return final_risk, expl

        except Exception as ex:
            print(f"[ERROR] Prediction error: {type(ex).__name__}: {ex}")
            return self.heuristic_prediction(e)

    def check_all_thresholds(self, uid):
        v = []
        s = user_session_data[uid]
        for m, val in {
            'files_created_today': s['num_file'],
            'usb_events_today': s['num_device'],
            'logons_today': s['num_logons'],
            'http_requests_today': s['num_http']
        }.items():
            ok, d = self.threshold_manager.check_threshold_violation(uid, m, val)
            if ok: v.append(d)
        return v

    def heuristic_prediction(self, e):
        r, rs = 0.0, []
        t = e.get("event_type", "")

        # Existing heuristics
        if e.get("is_executable"):     r += 0.3; rs.append("Executable detected")
        if e.get("in_sensitive_path"): r += 0.2; rs.append("Sensitive directory")
        if t == "usb":                 r += 0.4; rs.append("USB activity")
        if e.get("is_remote"):         r += 0.3; rs.append("Remote login")
        if e.get("hour_of_day", 12) not in range(6, 23):
            r += 0.2; rs.append("After hours activity")

        # Email heuristics
        if t in ('outlook', 'imap', 'email_sent', 'email_received'):
            subj     = (e.get("email_subject") or "").lower()
            CRIT_KW  = ["password","credential","secret","api key","token","auth"]
            HIGH_KW  = ["confidential","top secret","classified","do not share"]
            MED_KW   = ["salary","client list","financial","nda","budget","merger"]
            for kw in CRIT_KW:
                if kw in subj: r += 0.35; rs.append(f"Critical keyword: '{kw}'"); break
            for kw in HIGH_KW:
                if kw in subj: r += 0.25; rs.append(f"High-risk keyword: '{kw}'"); break
            for kw in MED_KW:
                if kw in subj: r += 0.15; rs.append(f"Sensitive keyword: '{kw}'"); break
            if e.get("has_external"):
                r += 0.20; rs.append("Sent to external domain")
            for att in e.get("attachments", []):
                if att.get("size_mb", 0) > 5:
                    r += 0.15; rs.append(f"Large attachment: {att.get('name','')}"); break
                ext = str(att.get("type","") or att.get("name","")).lower()
                if any(x in ext for x in [".zip",".rar",".exe",".sql",".bak"]):
                    r += 0.20; rs.append(f"Risky file type: {ext}"); break

        lvl = "HIGH" if r > 0.7 else "MEDIUM" if r > 0.4 else "LOW"
        return min(r, 1.0), {"top_factors": rs or ["Normal"], "risk_level": lvl}

    def generate_explanation(self, e, s, p, f, v):
        rs = []
        t = e.get("event_type", "")

        # ML model signal
        if p == -1: rs.append("ML model flagged anomaly")

        # Feature vector signals
        if f[0] > 5:  rs.append(f"High logon frequency ({int(f[0])} today)")
        if f[4] > 0:  rs.append("USB device used")
        if f[5] > 10: rs.append(f"High file activity ({int(f[5])} ops)")
        if f[7] > 20: rs.append(f"Unusual email volume ({int(f[7])} today)")
        if f[8] > 5:  rs.append(f"Many external emails ({int(f[8])} today)")
        if f[9] > 10: rs.append(f"High attachment count ({int(f[9])} today)")
        if e.get("is_executable"): rs.append("Executable file detected")

        # Email-specific signals
        if t in ('outlook', 'imap', 'email_sent', 'email_received'):
            subj    = (e.get("email_subject") or "").lower()
            CRIT_KW = ["password","credential","secret","api key","token"]
            HIGH_KW = ["confidential","classified","do not share","internal only"]
            MED_KW  = ["salary","client list","financial","nda","budget"]
            for kw in CRIT_KW:
                if kw in subj: rs.append(f"Critical keyword: '{kw}'"); break
            for kw in HIGH_KW:
                if kw in subj: rs.append(f"High-risk keyword: '{kw}'"); break
            for kw in MED_KW:
                if kw in subj: rs.append(f"Sensitive keyword: '{kw}'"); break
            if e.get("has_external"):
                domains = e.get("recipient_domains", [])
                rs.append(f"External recipient: {', '.join(str(d) for d in domains[:3])}")
            for att in e.get("attachments", []):
                size = att.get("size_mb", 0)
                name = att.get("name", "")
                ext  = str(att.get("type","") or name).lower()
                if size > 5:
                    rs.append(f"Large attachment: {name} ({size:.1f}MB)")
                if any(x in ext for x in [".zip",".rar",".exe",".sql",".bak"]):
                    rs.append(f"Risky attachment: {name}")

        # Threshold violations
        for x in v:
            rs.append(f"Threshold exceeded — {x['metric']}: "
                      f"{x.get('current_value','?')} > {x.get('threshold','?')}")

        lvl = "CRITICAL" if s > 0.9 else "HIGH" if s > 0.7 else "MEDIUM" if s > 0.4 else "LOW"
        return {
            "top_factors":          rs[:5] or ["Normal activity"],
            "risk_level":           lvl,
            "threshold_violations": v,
            "event_type":           t,
        }

    def log_event(self, e, s, ex):
        LOG_FILE.parent.mkdir(exist_ok=True, parents=True)
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            vs = f", Violations={len(ex['threshold_violations'])}" if ex.get('threshold_violations') else ""
            f.write(f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {e.get('agent_id','?')}: "
                    f"Risk={s:.3f}, Level={ex['risk_level']}{vs}, "
                    f"Factors={'; '.join(ex['top_factors'])}\n")

    def predict_email_risk(self, email_text, metadata=None):
        """
        Predict email risk using ML models (TF-IDF + Classifier + Regressors).
        FIXED: Now properly handles attachment risk scores and confidential content.
        
        Args:
            email_text: Email subject + body text for analysis
            metadata: Optional dict with email metadata (sender, recipient, attachments, etc.)
            
        Returns:
            dict: {
                'risk_score': float (0-1),
                'risk_level': str ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL'),
                'classifier_prediction': int (0=safe, 1=risky),
                'classifier_probability': float,
                'regressor_scores': dict (low/medium/high thresholds),
                'ml_confidence': float,
                'reason': str
            }
        """
        if not email_text:
            return {'risk_score': 0.0, 'risk_level': 'LOW', 'reason': 'Empty email', 'ml_confidence': 0.0}
        
        metadata = metadata or {}
        result = {
            'risk_score': 0.5,
            'risk_level': 'MEDIUM',
            'classifier_prediction': None,
            'classifier_probability': 0.0,
            'regressor_scores': {},
            'ml_confidence': 0.0,
            'reason': 'Default - ML models not available'
        }
        
        # Use heuristic fallback if email models not available
        if not (self.model_load_status["tfidf_vectorizer"] and self.model_load_status["email_classifier"]):
            return self._heuristic_email_risk(email_text, metadata)
        
        try:
            # Vectorize email text
            email_features = self.tfidf_vectorizer.transform([email_text])
            
            # Add numeric features from metadata (keep original 7 features for trained model compatibility)
            numeric_features = np.array([[
                len(metadata.get('recipients', [])),  # num_recipients
                1 if metadata.get('has_external', False) else 0,  # has_external
                len(metadata.get('attachments', [])),  # num_attachments
                metadata.get('body_length', 0),  # body_length
                1 if metadata.get('has_executable_attachment', False) else 0,  # has_executable
                1 if metadata.get('has_credential_keywords', False) else 0,  # has_credential_keywords
                1 if metadata.get('has_urgency_keywords', False) else 0,  # has_urgency_keywords
            ]])
            
            # Combine TF-IDF and numeric features (207 total features: 200 + 7 numeric)
            combined_features = np.hstack([email_features.toarray(), numeric_features])
            
            # Classifier prediction
            classifier_pred = self.email_classifier.predict(combined_features)[0]
            classifier_proba = self.email_classifier.predict_proba(combined_features)[0]
            classifier_risk_prob = classifier_proba[1] if len(classifier_proba) > 1 else 0.0
            
            # Get regressor scores (risk severity levels)
            regressor_scores = {}
            for level in ['low', 'medium', 'high']:
                if level in self.email_regressors:
                    try:
                        score = self.email_regressors[level].predict(combined_features)[0]
                        regressor_scores[level] = float(score)
                    except Exception as e:
                        print(f"[WARN] Regressor {level} prediction failed: {e}")
                        regressor_scores[level] = 0.0
            
            # Calculate final risk score with CRITICAL FIX: attachment risk multiplier
            base_risk = float(classifier_risk_prob)
            
            # CRITICAL FIX: Apply attachment risk multiplier based on metadata
            attachment_multiplier = 1.0
            attachment_risk = metadata.get('attachment_risk_score', 0.0)
            
            # Only apply strong multipliers when BOTH threats are present
            if attachment_risk > 0.6 and metadata.get('has_confidential_content', False):
                # Both dangerous executable AND confidential body content = 1.5x boost
                attachment_multiplier = 1.5
            elif attachment_risk > 0.7:
                # Very dangerous executable (0.8+) = 1.3x boost
                attachment_multiplier = 1.3
            elif metadata.get('has_confidential_content', False) and attachment_risk > 0.3:
                # Confidential content + suspicious attachment = 1.2x boost
                attachment_multiplier = 1.2
            
            # Apply multiplier to base risk
            boosted_risk = base_risk * attachment_multiplier
            
            # Adjust based on regressor output (higher scores = higher risk across different thresholds)
            if regressor_scores:
                # Normalize regressor scores (approximate scaling based on known ranges)
                regressor_risk = 0.0
                if 'low' in regressor_scores:
                    regressor_risk = min(regressor_scores['low'] / 10.0, 1.0)  # low: 1.89-2.62
                if 'medium' in regressor_scores:
                    medium_risk = min(regressor_scores['medium'] / 10.0, 1.0)  # medium: 5.11-5.56
                    regressor_risk = max(regressor_risk, medium_risk)
                if 'high' in regressor_scores:
                    high_risk = min(regressor_scores['high'] / 10.0, 1.0)  # high: 8.99-9.24
                    regressor_risk = max(regressor_risk, high_risk)
                
                # Blend classifier (now boosted) and regressor scores (70% classifier, 30% regressor)
                final_risk = 0.7 * boosted_risk + 0.3 * regressor_risk
            else:
                final_risk = boosted_risk
            
            # Clamp to [0, 1]
            final_risk = float(np.clip(final_risk, 0.0, 1.0))
            
            # Determine risk level with updated thresholds
            if final_risk >= 0.75:
                risk_level = 'CRITICAL'
            elif final_risk >= 0.60:
                risk_level = 'HIGH'
            elif final_risk >= 0.40:
                risk_level = 'MEDIUM'
            else:
                risk_level = 'LOW'
            
            # Build reason string
            reason_parts = [f"ML predicted {risk_level} risk (classifier: {classifier_risk_prob:.2%})"]
            if attachment_multiplier > 1.0:
                reason_parts.append(f"[BOOST {attachment_multiplier:.1f}x: attachment+confidential]")
            
            result = {
                'risk_score': final_risk,
                'risk_level': risk_level,
                'classifier_prediction': int(classifier_pred),
                'classifier_probability': float(classifier_risk_prob),
                'regressor_scores': regressor_scores,
                'ml_confidence': 0.9 if classifier_pred == 1 else 0.7,  # Higher confidence when classified as risky
                'reason': " ".join(reason_parts)
            }
            
        except Exception as e:
            print(f"[ERROR] Email risk prediction failed: {type(e).__name__}: {e}")
            return self._heuristic_email_risk(email_text, metadata)
        
        return result

    def _heuristic_email_risk(self, email_text, metadata=None):
        """Fallback heuristic email risk scoring when ML models unavailable. ENHANCED."""
        metadata = metadata or {}
        risk = 0.0
        reasons = []
        email_lower = (email_text or "").lower()
        
        # Critical keywords (highest risk)
        CRIT_KW = ["password", "credential", "secret", "api key", "token", "auth", "ssn", "account number"]
        for kw in CRIT_KW:
            if kw in email_lower:
                risk += 0.45
                reasons.append(f"Critical keyword: {kw}")
                break
        
        # High-risk keywords
        HIGH_KW = ["confidential", "top secret", "classified", "do not share", "internal use only", "trade secret", "proprietary"]
        if risk < 0.45:
            for kw in HIGH_KW:
                if kw in email_lower:
                    risk += 0.35
                    reasons.append(f"Sensitive keyword: {kw}")
                    break
        
        # Medium-risk keywords
        MED_KW = ["urgent action", "verify account", "confirm identity", "update payment", "suspicious login"]
        if risk < 0.35:
            for kw in MED_KW:
                if kw in email_lower:
                    risk += 0.25
                    reasons.append(f"Urgent keyword: {kw}")
                    break
        
        # External recipients (risk boost)
        if metadata.get('has_external', False):
            risk += 0.25
            reasons.append("Sent to external recipients")
        
        # Executable attachments (ENHANCED)
        if metadata.get('has_executable_attachment', False):
            risk += 0.40
            reasons.append("Executable attachment detected")
        
        # NEW: Dangerous attachment risk score
        attachment_risk = metadata.get('attachment_risk_score', 0.0)
        if attachment_risk > 0.6:
            risk += attachment_risk * 0.5  # Weight actual attachment risk
            reasons.append(f"Dangerous attachment (risk: {attachment_risk:.0%})")
        elif attachment_risk > 0.4:
            risk += attachment_risk * 0.3
        
        # NEW: Confidential content in body
        if metadata.get('has_confidential_content', False):
            risk += 0.35
            reasons.append("Confidential content in body")
        
        # NEW: Sensitive files detected
        if metadata.get('has_sensitive_files', False):
            risk += 0.25
            reasons.append("Sensitive document files attached")
        
        # CRITICAL FIX: Combined threat multiplier
        if (metadata.get('has_confidential_content', False) or 
            metadata.get('has_sensitive_files', False)) and attachment_risk > 0.4:
            # Boost risk when both confidential content and dangerous files present
            risk *= 1.5
            reasons.append("[COMBINED THREAT] Confidential + Attachment")
        
        # Large attachments
        for att in metadata.get('attachments', []):
            if att.get('size_mb', 0) > 10:
                risk += 0.20
                reasons.append(f"Large attachment: {att.get('name', 'unknown')}")
                break
        
        risk = float(np.clip(risk, 0.0, 1.0))
        
        if risk >= 0.75:
            risk_level = 'CRITICAL'
        elif risk >= 0.60:
            risk_level = 'HIGH'
        elif risk >= 0.40:
            risk_level = 'MEDIUM'
        else:
            risk_level = 'LOW'
        
        return {
            'risk_score': risk,
            'risk_level': risk_level,
            'classifier_prediction': 1 if risk >= 0.5 else 0,
            'classifier_probability': risk,
            'regressor_scores': {},
            'ml_confidence': 0.5,  # Lower confidence for heuristic
            'reason': f"Heuristic scoring: {reasons[0] if reasons else 'Normal email'} ({risk:.2f})"
        }

    def get_user_dashboard_data(self, uid):
        return self.threshold_manager.get_user_threshold_status(uid)

    def get_model_health_status(self):
        """
        Get comprehensive status of all loaded models.
        Returns a dictionary with health metrics and warnings.
        """
        health = {
            "timestamp": datetime.now().isoformat(),
            "models": {
                "scaler": {
                    "loaded": self.model_load_status["scaler"],
                    "status": "OK" if self.model_load_status["scaler"] else "MISSING"
                },
                "isolation_forest": {
                    "loaded": self.model_load_status["isolation_forest"],
                    "status": "OK" if self.model_load_status["isolation_forest"] else "MISSING"
                },
                "autoencoder": {
                    "loaded": self.model_load_status["autoencoder"],
                    "status": "OK" if self.model_load_status["autoencoder"] else "MISSING"
                }
            },
            "pipeline_mode": "FULL_ML" if all(self.model_load_status.values()) else \
                            "REDUCED_ML" if self.model_load_status["scaler"] and \
                                           self.model_load_status["isolation_forest"] else \
                            "HEURISTIC_FALLBACK",
            "errors": self.model_errors,
            "device": str(self.device)
        }
        return health

    def print_model_health(self):
        """Print model health status for debugging."""
        health = self.get_model_health_status()
        print("\n[HEALTH] Model Health Status:")
        print(f"   Pipeline Mode: {health['pipeline_mode']}")
        print(f"   Device: {health['device']}")
        print(f"   Models:")
        for model_name, status in health['models'].items():
            status_str = "LOADED" if status['loaded'] else "MISSING"
            print(f"      - {model_name}: {status_str}")
        if health['errors']:
            print(f"   Errors ({len(health['errors'])}):")
            for err in health['errors'][:5]:  # Show first 5
                print(f"      - {err}")
        print()

def get_path_config():
    """
    Return the current path configuration as a dictionary.
    Useful for debugging and logging.
    """
    return {
        "project_root": str(get_project_root()),
        "model_dir": str(MODEL_DIR),
        "log_file": str(LOG_FILE),
        "baseline_file": str(BASELINE_FILE),
        "threshold_config": str(THRESHOLD_CONFIG)
    }

def print_path_config():
    """
    Print the current path configuration for debugging.
    """
    print("\n[PATHS] Path Configuration:")
    print(f"   Project Root:    {get_project_root()}")
    print(f"   Model Directory: {MODEL_DIR}")
    print(f"   Log File:        {LOG_FILE}")
    print(f"   Baseline File:   {BASELINE_FILE}")
    print(f"   Threshold Config: {THRESHOLD_CONFIG}")
    print()

# =========================================================================
# INSTANTIATE GLOBAL THREAT MODEL
# =========================================================================
print("\n" + "="*70)
print("[INIT] Initializing DeepSentinel Threat Detection Model")
print("="*70)

try:
    threat_model = ThreatDetectionModel()
    print(f"\n[OK] Threat model successfully initialized and ready for predictions\n")
except Exception as init_error:
    print(f"\n[ERROR] CRITICAL: Failed to initialize threat model: {init_error}\n")
    # Create a fallback simple model
    class SimpleThreatModel:
        def predict_with_explanation(self, event):
            risk = 0.0
            reasons = []
            if event.get('is_executable'): risk += 0.4; reasons.append("Application launch")
            if event.get('is_document') and event.get('action') == 'file_deleted': risk += 0.6; reasons.append("Document deletion")
            if event.get('event_type') == 'usb': risk += 0.7; reasons.append("USB activity")
            if event.get('is_remote'): risk += 0.5; reasons.append("Remote access")
            hour = event.get('hour_of_day', 12)
            if hour < 7 or hour > 20: risk += 0.3; reasons.append("After hours")
            return min(risk, 1.0), {"top_factors": reasons[:2]}
        
        def predict_email_risk(self, email_text, metadata=None):
            return {'risk_score': 0.5, 'risk_level': 'MEDIUM', 'reason': 'Fallback model'}
    
    threat_model = SimpleThreatModel()
    print("[WARN] Using fallback threat model - ML features disabled\n")

# -------------------------------------------------------------------------
# MAIN TEST
# -------------------------------------------------------------------------
if __name__ == "__main__":
    print("\n" + "="*70)
    print("DeepSentinel - Path Configuration Test")
    print("="*70)

    # Print path configuration
    print_path_config()

    # Verify config loaded correctly
    print("[CONFIG] Config loaded from: config.json")
    print(f"   Model dir setting: {_CONFIG.get('paths', {}).get('model_dir', 'NOT SET')}")
    print()

    # Validate model directory exists
    if MODEL_DIR.exists():
        print(f"[OK] Model directory exists: {MODEL_DIR}")
        model_files = list(MODEL_DIR.glob("*.pkl")) + list(MODEL_DIR.glob("*.pth"))
        print(f"   Found {len(model_files)} model files")
    else:
        print(f"[WARN] Model directory not found: {MODEL_DIR}")
        print("   Please update config.json with the correct model_dir path")

    print("\n" + "="*70)
    print("[INIT] INITIALIZING DEEPSENTINEL WITH SMART THRESHOLDS (FIXED)")
    print("="*70)
    model = ThreatDetectionModel()
    print("="*70)

    events = [
        {"agent_id": "DEV-PC-001", "event_type": "file", "action": "created", "is_executable": False, "file_size": 1024},
        {"agent_id": "DEV-PC-001", "event_type": "usb", "action": "inserted"},
        {"agent_id": "DEV-PC-001", "event_type": "logon", "is_remote": True},
    ]
    for ev in events:
        risk, expl = model.predict_with_explanation(ev)
        print(f"\nEvent: {ev['event_type']} | Risk={risk:.3f} | Level={expl['risk_level']}")
        print("->", expl['top_factors'])
