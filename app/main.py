import json
from fastapi import FastAPI, Request, UploadFile, File, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.wsgi import WSGIMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from nfstream import NFStreamer
import joblib   
import plotly
from xgboost import XGBClassifier
import pandas as pd
import uvicorn
from starlette.middleware.trustedhost import TrustedHostMiddleware
import plotly.express as px

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
def analyze_df(df: pd.DataFrame):
    # df = get_df_from_pcap(file)

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

def get_class_pie(predictions):
    count_class0 = predictions.count(0)
    count_class1 = predictions.count(1)

    labels = ['Class 0', 'Class 1']
    values = [count_class0, count_class1]

    fig = px.pie(names=labels, values=values, hole=0.3, title='Class Distribution Pie Chart', template="plotly_dark")
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return graphJSON

def get_bfs_histogram(df):
    # df = px.data.tips()
    fig = px.histogram(df, x="bidirectional_first_seen_ms", template="plotly_dark")
    # print(df["dst2src_fin_packets"].unique())
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return graphJSON

def get_application_bar(df):
    # df = px.data.tips()
    fig = px.histogram(df, y="application_name", template="plotly_dark").update_yaxes(categoryorder='total ascending')
    # print(df["dst2src_fin_packets"].unique())
    graphJSON = json.dumps(fig, cls=plotly.utils.PlotlyJSONEncoder)

    return graphJSON
    

# Route for testing if the app is running
@app.get("/")
def index(request: Request):
    return templates.TemplateResponse("index.html", {"request" : request})

# Route to analyze pcap and make predictions
@app.post("/analyze")
async def analyze_endpoint(request: Request, file: UploadFile = File(...)):
    df = get_df_from_pcap(file=file)
    results = analyze_df(df)['predictions'] #a binary array
    pie_chart = get_class_pie(results)
    bfs_histogram = get_bfs_histogram(df=df)
    app_bar = get_application_bar(df=df)

    return templates.TemplateResponse("dashboard.html", 
                                      {
                                          "request" : request,
                                            "pie_chart": pie_chart,
                                              "bfs_histogram" : bfs_histogram,
                                              "app_bar": app_bar})

# Run the app using UVicorn
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8080)
