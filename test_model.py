# test_accuracy.py - Test alert accuracy
import sys
sys.path.append('.')

from src.detection.real_time_detector import RealTimeIDS

def test_accuracy():
    print("="*60)
    print("🔍 Testing Alert Accuracy")
    print("="*60)
    
    detector = RealTimeIDS()
    
    # Test cases
    test_cases = [
        # (attack_type, confidence, should_alert)
        ('ddos', 0.96, True, "High confidence real threat"),
        ('ddos', 0.85, False, "Low confidence"),
        ('normal', 0.95, False, "Normal traffic"),
        ('infiltration', 0.94, True, "Critical threat"),
        ('port_scan', 0.91, True, "High confidence scan"),
        ('port_scan', 0.82, False, "Low confidence scan"),
        ('brute_force', 0.95, True, "Real brute force"),
        ('web_attack', 0.89, True, "Real web attack"),
        ('unknown', 0.92, False, "Unknown - default severity too low"),
    ]
    
    print("\n📋 Test Results:")
    print("-"*60)
    print(f"{'Attack':15} {'Confidence':10} {'Should Alert':12} {'Result':10} {'Reason'}")
    print("-"*60)
    
    for attack, conf, expected, reason in test_cases:
        severity_score, level, icon = detector.get_severity_level(attack)
        should_alert, reasons = detector.should_alert(conf, severity_score)
        
        status = "✅" if should_alert == expected else "❌"
        print(f"{attack:15} {conf*100:.0f}%{'':4} {str(expected):12} {status:8} {reason}")
    
    print("\n" + "="*60)
    print("✅ Accuracy test complete!")

if __name__ == "__main__":
    test_accuracy()
