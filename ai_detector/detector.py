import joblib

class Detector:
    def __init__(self):
        self.model = joblib.load("waf.pkl")
    
    def is_malicious(self, body: str) -> bool:
        prediction = self.model.predict([body])[0]
        if prediction == 1:
            return True
        else:
            return False