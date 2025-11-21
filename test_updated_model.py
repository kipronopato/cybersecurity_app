import joblib
import numpy as np

# Load model and features
model = joblib.load('cyberattack/model_files/stacked_top13_model.pkl')
features = joblib.load('cyberattack/model_files/top13_features.pkl')

print("Testing updated scenarios...")

# Updated test cases with proper scaling
test_cases = [
    {
        'name': 'Normal HTTPS Traffic',
        'data': [443, 50000, 29200, 15200000, 2847, 28960, 1250.5, 30000, 45.2, 1460, 2100000, 1, 85.3]
    },
    {
        'name': 'Volumetric DDoS',
        'data': [80, 100, 2048, 500000, 50000, 0, 5000000.0, 100, 2500.0, 1500, 10000, 0, 8500.0]
    },
    {
        'name': 'SYN Flood',
        'data': [443, 10, 1024, 100000, 25000, 0, 8000000.0, 10, 5000.0, 64, 1000, 0, 15000.0]
    },
    {
        'name': 'Email Traffic',
        'data': [25, 100000, 16384, 8500000, 1024, 16384, 2500.0, 80000, 12.5, 512, 1200000, 1, 25.8]
    }
]

for test_case in test_cases:
    pred = model.predict([test_case['data']])
    proba = model.predict_proba([test_case['data']])
    
    print(f"\n{test_case['name']}:")
    print(f"  Prediction: {pred[0]} ({'DDoS' if pred[0] == 1 else 'BENIGN'})")
    print(f"  Probabilities: BENIGN={proba[0][0]:.4f}, DDoS={proba[0][1]:.4f}")

# Test with some extreme values that should definitely be DDoS
extreme_ddos = [80, 1, 512, 1000, 1000000, 0, 50000000, 1, 50000, 1500, 100, 0, 100000]
print(f"\nExtreme DDoS test:")
pred = model.predict([extreme_ddos])
proba = model.predict_proba([extreme_ddos])
print(f"  Prediction: {pred[0]} ({'DDoS' if pred[0] == 1 else 'BENIGN'})")
print(f"  Probabilities: BENIGN={proba[0][0]:.4f}, DDoS={proba[0][1]:.4f}")