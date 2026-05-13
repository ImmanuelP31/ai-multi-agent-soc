import numpy as np
import json

from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import (
    LSTM,
    Dense,
    Dropout
)
from tensorflow.keras.utils import to_categorical
from tensorflow.keras.callbacks import EarlyStopping

from sklearn.model_selection import train_test_split

# -----------------------------------
# LOAD DATA
# -----------------------------------

X = np.load("processed_sequences.npy")

y = np.load("sequence_labels.npy")

print("\nSequences Loaded")
print("X shape:", X.shape)
print("y shape:", y.shape)

# -----------------------------------
# LOAD LABEL MAPPING
# -----------------------------------

with open("label_mapping.json", "r") as f:
    label_mapping = json.load(f)

num_classes = len(label_mapping)

print("\nNumber of attack classes:", num_classes)

# -----------------------------------
# ONE HOT ENCODE LABELS
# -----------------------------------

y = to_categorical(y, num_classes=num_classes)

# -----------------------------------
# TRAIN TEST SPLIT
# -----------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)

# -----------------------------------
# BUILD LSTM MODEL
# -----------------------------------

model = Sequential()

# LSTM Layer
model.add(
    LSTM(
        128,
        input_shape=(
            X.shape[1],
            X.shape[2]
        )
    )
)

# Dropout
model.add(Dropout(0.3))

# Dense Layer
model.add(Dense(64, activation="relu"))

# Output Layer
model.add(
    Dense(
        num_classes,
        activation="softmax"
    )
)

# -----------------------------------
# COMPILE MODEL
# -----------------------------------

model.compile(
    optimizer="adam",
    loss="categorical_crossentropy",
    metrics=["accuracy"]
)

print("\nLSTM Model Built Successfully")

# -----------------------------------
# EARLY STOPPING
# -----------------------------------

early_stop = EarlyStopping(
    monitor="val_loss",
    patience=3,
    restore_best_weights=True
)

# -----------------------------------
# TRAIN MODEL
# -----------------------------------

print("\nTraining LSTM Model...\n")

history = model.fit(
    X_train,
    y_train,
    validation_data=(X_test, y_test),
    epochs=10,
    batch_size=64,
    callbacks=[early_stop]
)

# -----------------------------------
# EVALUATE MODEL
# -----------------------------------

loss, accuracy = model.evaluate(
    X_test,
    y_test
)

print(f"\nTest Accuracy: {accuracy * 100:.2f}%")

# -----------------------------------
# SAVE MODEL
# -----------------------------------

model.save("sequence_model.h5")

print("\nLSTM Model Saved Successfully")