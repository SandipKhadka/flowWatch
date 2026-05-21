# src/ml/threat_predictor.py
from sklearn.ensemble import RandomForestRegressor
import numpy as np

class ThreatPredictor:
    """Predict future threat levels using ML"""
    
    def __init__(self):
        self.model = RandomForestRegressor(n_estimators=100)
        self.is_trained = False
    
    def train(self, historical_data):
        """Train prediction model"""
        # Extract features
        X = []
        y = []
        
        for i in range(len(historical_data) - 60):  # Use last 60 for prediction
            window = historical_data[i:i+60]
            features = [
                np.mean(window),
                np.std(window),
                np.max(window),
                np.min(window),
                window[-10:].mean(),  # Recent trend
                window[-1]  # Last value
            ]
            X.append(features)
            y.append(historical_data[i+60])  # Predict next value
        
        self.model.fit(X, y)
        self.is_trained = True
    
    def predict_next_hour(self, recent_alerts):
        """Predict threat level for next hour"""
        if not self.is_trained or len(recent_alerts) < 60:
            return None
        
        # Calculate threat scores
        threat_scores = [AttackMapper.get_severity_score(a['attack_type']) * a['confidence'] 
                        for a in recent_alerts[-60:]]
        
        features = [
            np.mean(threat_scores),
            np.std(threat_scores),
            np.max(threat_scores),
            np.min(threat_scores),
            np.mean(threat_scores[-10:]),
            threat_scores[-1]
        ]
        
        prediction = self.model.predict([features])[0]
        return min(max(prediction, 0), 10)  # Clamp to 0-10
