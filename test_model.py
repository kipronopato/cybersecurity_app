import joblib
import numpy as np

try:
    print("Loading model and features...")
    model = joblib.load('cyberattack/model_files/stacked_top13_model.pkl')
    features = joblib.load('cyberattack/model_files/top13_features.pkl')
    
    print(f"Model type: {type(model)}")
    print(f"Features: {features}")
    print(f"Number of features: {len(features)}")
    
    # Test data that should clearly be DDoS
    ddos_test = [
        80,          # Destination Port
        0.00001,     # Flow IAT Min (very small)
        1024,        # Init_Win_bytes_forward (small)
        0.1,         # Flow Duration (very short)
        100000,      # Total Length of Fwd Packets (large)
        0,           # Init_Win_bytes_backward (zero)
        10000000,    # Flow Bytes/s (very high)
        0.00001,     # Fwd IAT Min (very small)
        10000,       # Bwd Packets/s (very high)
        1500,        # Fwd Packet Length Max
        0.001,       # Bwd IAT Total (very small)
        0,           # FIN Flag Count (no proper termination)
        20000        # Flow Packets/s (very high)
    ]
    
    # Test data that should be benign
    benign_test = [
        443,         # Destination Port (HTTPS)
        0.1,         # Flow IAT Min (normal)
        32768,       # Init_Win_bytes_forward (normal)
        30,          # Flow Duration (normal)
        1500,        # Total Length of Fwd Packets (normal)
        32768,       # Init_Win_bytes_backward (normal)
        5000,        # Flow Bytes/s (normal)
        0.05,        # Fwd IAT Min (normal)
        50,          # Bwd Packets/s (normal)
        1460,        # Fwd Packet Length Max (normal)
        5,           # Bwd IAT Total (normal)
        1,           # FIN Flag Count (proper termination)
        100          # Flow Packets/s (normal)
    ]
    
    print("\nTesting DDoS-like traffic:")
    print(f"Input: {ddos_test}")
    ddos_pred = model.predict([ddos_test])
    print(f"Prediction: {ddos_pred[0]} ({'DDoS' if ddos_pred[0] == 1 else 'BENIGN'})")
    
    print("\nTesting benign traffic:")
    print(f"Input: {benign_test}")
    benign_pred = model.predict([benign_test])
    print(f"Prediction: {benign_pred[0]} ({'DDoS' if benign_pred[0] == 1 else 'BENIGN'})")
    
    # Test with probabilities if available
    try:
        print("\nProbabilities for DDoS test:")
        ddos_proba = model.predict_proba([ddos_test])
        print(f"Probabilities: {ddos_proba[0]}")
        
        print("\nProbabilities for benign test:")
        benign_proba = model.predict_proba([benign_test])
        print(f"Probabilities: {benign_proba[0]}")
    except AttributeError:
        print("\nModel doesn't support predict_proba")
    
    # Check model attributes
    print(f"\nModel attributes: {dir(model)}")
    
    # Test with different ranges
    print("\nTesting with various inputs:")
    test_cases = [
        [80, 0.001, 1000, 1, 50000, 100, 1000000, 0.001, 1000, 1400, 0.1, 0, 5000],
        [443, 0.1, 30000, 20, 2000, 30000, 10000, 0.05, 100, 1460, 3, 1, 150],
        [22, 0.05, 16384, 10, 1024, 16384, 2000, 0.03, 25, 512, 2, 1, 50]
    ]
    
    for i, test_case in enumerate(test_cases):
        pred = model.predict([test_case])
        print(f"Test case {i+1}: {pred[0]} ({'DDoS' if pred[0] == 1 else 'BENIGN'})")

except Exception as e:
    print(f"Error: {e}")
    import traceback
    traceback.print_exc()