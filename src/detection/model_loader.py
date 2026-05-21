# src/detection/model_loader.py - Model loading utility
import joblib
import os
import warnings
warnings.filterwarnings("ignore")

class ModelLoader:
    """Load and manage trained models"""
    
    def __init__(self, model_dir="src/models"):
        self.model_dir = model_dir
        self.models = {}
        self.load_all_models()
    
    def load_all_models(self):
        """Load all model files"""
        print("📦 Loading models...")
        
        model_files = {
            'xgb_model.pkl': 'xgb',
            'rf_model.pkl': 'rf',
            'target_encoder.pkl': 'target_encoder',
            'scaler.pkl': 'scaler',
            'label_encoders.pkl': 'label_encoders'
        }
        
        for filename, key in model_files.items():
            path = os.path.join(self.model_dir, filename)
            if os.path.exists(path):
                try:
                    self.models[key] = joblib.load(path)
                    print(f"  ✅ Loaded: {filename}")
                except Exception as e:
                    print(f"  ❌ Failed to load {filename}: {e}")
                    self.models[key] = None
            else:
                print(f"  ⚠️ Not found: {filename}")
                self.models[key] = None
    
    def get_model(self, name='xgb'):
        """Get loaded model by name"""
        return self.models.get(name)
    
    def predict(self, features, model_name='xgb'):
        """Make prediction using specified model"""
        model = self.get_model(model_name)
        scaler = self.get_model('scaler')
        target_encoder = self.get_model('target_encoder')
        
        if model is None or scaler is None:
            return None, 0.0
        
        try:
            # Scale features
            features_scaled = scaler.transform(features)
            
            # Predict
            prediction_encoded = model.predict(features_scaled)[0]
            
            # Get confidence
            if hasattr(model, 'predict_proba'):
                proba = model.predict_proba(features_scaled)[0]
                confidence = max(proba)
            else:
                confidence = 0.8
            
            # Decode prediction
            if target_encoder:
                prediction = target_encoder.inverse_transform([prediction_encoded])[0]
            else:
                prediction = str(prediction_encoded)
            
            return prediction, confidence
            
        except Exception as e:
            print(f"Prediction error: {e}")
            return None, 0.0
    
    def is_ready(self):
        """Check if critical models are loaded"""
        critical = ['xgb', 'scaler', 'target_encoder']
        return all(self.models.get(c) is not None for c in critical)
