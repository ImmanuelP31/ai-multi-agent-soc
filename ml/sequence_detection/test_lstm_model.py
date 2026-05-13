import numpy as np
import json

from tensorflow.keras.models import load_model

# -----------------------------------
# LOAD MODEL
# -----------------------------------

model = load_model("sequence_model.h5")

print("\nLSTM Model Loaded")

# -----------------------------------
# LOAD LABEL MAPPING
# -----------------------------------

with open("label_mapping.json", "r") as f:
    label_mapping = json.load(f)

# Reverse mapping
reverse_mapping = {
    v: k for k, v in label_mapping.items()
}

# -----------------------------------
# SAMPLE SEQUENCE
# -----------------------------------

sample_sequence = np.array([[
    [1, 1, 0.72, 4000, 2, 0],
    [1, 1, 0.75, 4200, 3, 0],
    [2, 2, 0.88, 9000, 5, 1],
    [2, 2, 0.91, 12000, 7, 1],
    [3, 3, 0.97, 20000, 10, 1]
]])

# -----------------------------------
# PREDICT
# -----------------------------------

prediction = model.predict(sample_sequence)

predicted_class = np.argmax(prediction)

predicted_attack = reverse_mapping[
    predicted_class
]

print("\nPredicted Next Attack:")
print(predicted_attack)