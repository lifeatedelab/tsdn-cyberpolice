from fastapi import FastAPI, Request, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.wsgi import WSGIMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from nfstream import NFStreamer
import joblib
from xgboost import XGBClassifier
import pandas as pd
import uvicorn
from starlette.middleware.trustedhost import TrustedHostMiddleware

app = FastAPI(
    title="Cyberpolice",
    description="XGBoost",
    version="0.0.1",
)

# Add middleware for CORS and Trusted Host
app.add_middleware(CORSMiddleware, allow_origins=["*"])
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["*"])

app.mount("/static", StaticFiles(directory="static"), name="static")

# Initialize Jinja2Templates
templates = Jinja2Templates(directory="templates")

# Load the XGBoost model
xgb = joblib.load("bin/xgboost_model.joblib")

# Function to get DataFrame from pcap file
def get_df_from_pcap(file: UploadFile = File(...)):
    try:
        with open(file.filename, "wb") as f:
            f.write(file.file.read())

        # Use NFStreamer to convert pcap to DataFrame
        streamer = NFStreamer(source=file.filename, statistical_analysis=True)
        df = streamer.to_pandas()
        return df

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error during conversion: {str(e)}")

# Function to analyze pcap and make predictions
def analyze_pcap(file: UploadFile = File(...)):
    df = get_df_from_pcap(file)

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

# Route for testing if the app is running
@app.get("/")
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request" : request})

# Route to analyze pcap and make predictions
@app.post("/analyze")
async def analyze_endpoint(request: Request, file: UploadFile = File(...)):
    result = analyze_pcap(file=file)
    return templates.TemplateResponse("dashboard.html", {"request" : request})

# Run the app using UVicorn
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
