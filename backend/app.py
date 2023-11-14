from fastapi import FastAPI, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from nfstream import NFStreamer
import joblib
from xgboost import XGBClassifier
import pandas as pd

app = FastAPI(
    title="Cyberpolice",
    description="XGBoost",
    version="0.0.1",
)

app.add_middleware(CORSMiddleware, allow_origins=["*"])

xgb = joblib.load("xgboost_model.joblib")

def analyze_pcap(file: UploadFile = File(...)):
    try:
        with open(file.filename, "wb") as f:
            f.write(file.file.read())

        streamer = NFStreamer(source=file.filename, statistical_analysis=True)
        df = streamer.to_pandas()

        features = [
            'bidirectional_first_seen_ms',
            'bidirectional_last_seen_ms',
            'dst2src_cwr_packets',
            'dst2src_ece_packets',
            'dst2src_urg_packets',
            'dst2src_ack_packets',
            'dst2src_psh_packets',
            'dst2src_rst_packets',
            'dst2src_fin_packets',
        ]

        X_test = df[features]  
        predictions = xgb.predict(X_test)

        return {"predictions": predictions.tolist()}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during analysis: {str(e)}")

@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    return analyze_pcap(file)
