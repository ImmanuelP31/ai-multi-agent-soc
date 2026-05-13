import joblib
import numpy as np

# -----------------------------------
# LOAD MODEL
# -----------------------------------

model = joblib.load("severity_model.pkl")

print("Severity Model Loaded")

# -----------------------------------
# SAMPLE TRAFFIC EVENT
# -----------------------------------

import pandas as pd

sample = pd.DataFrame([{
    "Flow Duration": 500000,
    "Total Fwd Packets": 200,
    "Total Backward Packets": 150,
    "Flow Bytes/s": 12000,
    "Flow Packets/s": 8000
}])

# -----------------------------------
# PREDICT
# -----------------------------------

prediction = model.predict(sample)

print("\nPredicted Severity:", prediction[0])