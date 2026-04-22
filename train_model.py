import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
import joblib

# ---------------- LOAD ----------------
df = pd.read_csv("ml_data.csv",
    names=["packet_rate", "avg_size", "unique_ports", "label"]
)

df.dropna(inplace=True)

# ---------------- ENCODE ----------------
le = LabelEncoder()
df["label"] = le.fit_transform(df["label"])

# ---------------- FEATURES ----------------
X = df[["packet_rate", "avg_size", "unique_ports"]]
y = df["label"]

# ---------------- TRAIN ----------------
model = RandomForestClassifier(n_estimators=150)
model.fit(X, y)

# ---------------- SAVE ----------------
joblib.dump(model, "model.pkl")
joblib.dump(le, "label_encoder.pkl")

print("🔥 Multi-class model trained")
