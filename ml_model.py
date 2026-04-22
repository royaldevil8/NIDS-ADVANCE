import joblib
import os

MODEL_PATH = "model.pkl"
ENCODER_PATH = "label_encoder.pkl"

model = None
encoder = None
last_loaded = 0


def load_model():
    global model, encoder, last_loaded

    if not os.path.exists(MODEL_PATH):
        return

    current_time = os.path.getmtime(MODEL_PATH)

    # reload only if changed
    if model is None or current_time != last_loaded:
        try:
            model = joblib.load(MODEL_PATH)
            encoder = joblib.load(ENCODER_PATH)
            last_loaded = current_time
            print("[ML] Model loaded/reloaded")
        except Exception as e:
            print("[ML LOAD ERROR]", e)


def predict_with_confidence(features):
    load_model()

    if model is None:
        return "NORMAL", 0.0

    try:
        probs = model.predict_proba([features])[0]
        pred_index = probs.argmax()

        label = encoder.inverse_transform([pred_index])[0]
        confidence = probs[pred_index]

        return label, round(confidence * 100, 2)

    except Exception as e:
        print("[ML ERROR]", e)
        return "NORMAL", 0.0