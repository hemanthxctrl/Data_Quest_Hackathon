from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
import pandas as pd
from typing import Dict
from dotenv import load_dotenv
import joblib
from pymongo import MongoClient
from datetime import datetime, timezone

load_dotenv()

app = FastAPI(title="AI Network Threat Detection API")

# Configure CORS for frontend access
origins = [
    "http://localhost:5173", 
    "http://127.0.0.1:5173",
    "http://localhost:5174",
    "http://127.0.0.1:5174",
    "http://localhost:3000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global variables for models
rf_pipeline = None
iso_pipeline = None
network_threat_model = None
network_threat_features = None
network_threat_label_map = None

# MongoDB configuration
mongodb_uri = os.getenv("MONGODB_URI")
mongodb_database = os.getenv("MONGODB_DATABASE", "network_security")
mongo_client = None
db = None

@app.on_event("startup")
def load_models():
    global rf_pipeline, iso_pipeline
    global network_threat_model, network_threat_features, network_threat_label_map
    global mongo_client, db
    try:
        base_path = os.path.dirname(os.path.dirname(os.path.abspath(__file__))) # gets backend folder
        project_root = os.path.dirname(base_path)
        
        models_dir = os.path.join(project_root, 'ml', 'models')
        
        # Original models
        rf_path = os.path.join(models_dir, 'rf_pipeline.pkl')
        iso_path = os.path.join(models_dir, 'isolation_forest_pipeline.pkl')
        
        if os.path.exists(rf_path):
            rf_pipeline = joblib.load(rf_path)
            iso_pipeline = joblib.load(iso_path)
            print("Original ML Pipelines loaded successfully.")
        else:
            print(f"Original models not found at {models_dir}.")
            
        # New models
        nt_rf_path = os.path.join(models_dir, 'network_threat_rf_model.pkl')
        nt_features_path = os.path.join(models_dir, 'network_threat_feature_columns.pkl')
        nt_label_map_path = os.path.join(models_dir, 'network_threat_label_map.pkl')
        
        if os.path.exists(nt_rf_path):
            network_threat_model = joblib.load(nt_rf_path)
            network_threat_features = joblib.load(nt_features_path)
            network_threat_label_map = joblib.load(nt_label_map_path)
            print("New Network Threat models loaded successfully.")
        else:
            print(f"New network threat models not found at {models_dir}.")
            
        if mongodb_uri:
            mongo_client = MongoClient(mongodb_uri, serverSelectionTimeoutMS=2000)
            db = mongo_client[mongodb_database]
            mongo_client.admin.command('ping')
            print("Successfully connected to MongoDB.")
            
    except Exception as e:
        print(f"Error during startup/loading: {e}")
        if 'mongo_client' in locals() and mongo_client:
            mongo_client = None
            db = None

class NetworkFlow(BaseModel):
    features: Dict[str, float]

def calculate_risk_score(attack_type: str, confidence: float) -> tuple[int, str]:
    attack_upper = str(attack_type).upper()
    base_scores = {
        "BENIGN": 5,
        "BOT": 60,
        "BRUTEFORCE": 65,
        "BRUTE_FORCE": 65,
        "PORT_SCAN": 60,
        "PORTSCAN": 60,
        "DOS": 85,
        "DDOS": 95,
        "WEB_ATTACK": 75,
        "WEBATTACK": 75
    }
    
    # Find base score, default to 50 if unknown attack type
    base_score = 50
    for key in base_scores:
        if key in attack_upper:
            base_score = base_scores[key]
            break
            
    if "BENIGN" in attack_upper:
        # Keep BENIGN strictly low, adjust slightly with uncertainty
        score = 5 + int((1.0 - confidence) * 10)
    else:
        # Adjust based on confidence.
        adjustment = (confidence - 0.5) * 20
        score = base_score + int(adjustment)
        
    score = max(0, min(100, score))
    
    if score <= 24:
        level = "LOW"
    elif score <= 49:
        level = "MEDIUM"
    elif score <= 74:
        level = "HIGH"
    else:
        level = "CRITICAL"
        
    return score, level

def get_explanation_and_action(attack_type: str) -> tuple[str, str]:
    attack_upper = str(attack_type).upper()
    
    mappings = {
        "BENIGN": {
            "explanation": "Traffic is classified as normal network activity.",
            "action": "No immediate action required. Continue normal monitoring."
        },
        "BOT": {
            "explanation": "Traffic shows characteristics associated with automated or bot-driven activity.",
            "action": "Investigate the source hosts and monitor for repeated or coordinated suspicious connections."
        },
        "BRUTE_FORCE": {
            "explanation": "Traffic pattern is associated with repeated authentication or access attempts.",
            "action": "Investigate the source and target accounts, apply rate limiting, and review authentication logs."
        },
        "DDOS": {
            "explanation": "Traffic pattern is classified as DDoS activity with high-volume or abnormal request characteristics.",
            "action": "Investigate the traffic sources and consider rate limiting, filtering, or blocking suspicious sources."
        },
        "DOS": {
            "explanation": "Traffic pattern is associated with denial-of-service activity.",
            "action": "Investigate abnormal traffic volume and consider rate limiting or filtering suspicious sources."
        },
        "PORT_SCAN": {
            "explanation": "Traffic shows characteristics of systematic probing across network ports.",
            "action": "Investigate the source host and review accessed ports. Consider network filtering if the activity is unauthorized."
        },
        "WEB_ATTACK": {
            "explanation": "Traffic pattern is associated with suspicious web application activity.",
            "action": "Review web-server and application logs and investigate the source and affected endpoints."
        }
    }
    
    for key, value in mappings.items():
        if key in attack_upper:
            return value["explanation"], value["action"]
            
    # Fallback
    return (
        "Traffic pattern is classified as abnormal network activity.",
        "Review network traffic logs and investigate the source."
    )

@app.get("/")
def read_root():
    return {"message": "Welcome to AI Network Threat Detection API"}

@app.get("/api/health")
def health_check():
    models_status = "loaded" if (rf_pipeline or network_threat_model) else "missing"
    return {"status": "ok", "service": "backend", "models": models_status, "message": "API is healthy"}

@app.post("/api/predict")
def predict_threat(flow: NetworkFlow):
    if not network_threat_model or not network_threat_features:
        raise HTTPException(status_code=503, detail="Network threat models are not loaded.")
    
    # Create a DataFrame initialized with 0.0 for all expected features
    df = pd.DataFrame(0.0, index=[0], columns=network_threat_features)
    
    # Populate the dataframe with incoming features that match expected columns
    for key, value in flow.features.items():
        if key in network_threat_features:
            df.at[0, key] = value
            
    # Predict
    # Scikit-learn random forest natively outputs string classes
    prediction = network_threat_model.predict(df)[0]
    probabilities = network_threat_model.predict_proba(df)[0]
    confidence = float(max(probabilities))
    
    risk_score, risk_level = calculate_risk_score(prediction, confidence)
    explanation, recommended_action = get_explanation_and_action(prediction)
    
    response_data = {
        "attack_type": prediction,
        "confidence": confidence,
        "features_processed": len(flow.features),
        "risk_score": risk_score,
        "risk_level": risk_level,
        "explanation": explanation,
        "recommended_action": recommended_action
    }
    
    if db is not None:
        try:
            document = {
                "timestamp": datetime.now(timezone.utc),
                "attack_type": prediction,
                "confidence": confidence,
                "risk_score": risk_score,
                "risk_level": risk_level,
                "explanation": explanation,
                "recommended_action": recommended_action,
                "features_processed": len(flow.features)
            }
            db.security_events.insert_one(document)
        except Exception as e:
            print(f"MongoDB insertion failed: {e}")
            
    return response_data

@app.get("/api/dashboard/stats")
def get_dashboard_stats():
    if db is None:
        return {"total_events": 0, "total_threats": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
        
    try:
        pipeline = [
            {"$group": {
                "_id": None,
                "total_events": {"$sum": 1},
                "total_threats": {"$sum": {"$cond": [{"$ne": ["$attack_type", "BENIGN"]}, 1, 0]}},
                "critical": {"$sum": {"$cond": [{"$eq": ["$risk_level", "CRITICAL"]}, 1, 0]}},
                "high": {"$sum": {"$cond": [{"$eq": ["$risk_level", "HIGH"]}, 1, 0]}},
                "medium": {"$sum": {"$cond": [{"$eq": ["$risk_level", "MEDIUM"]}, 1, 0]}},
                "low": {"$sum": {"$cond": [{"$eq": ["$risk_level", "LOW"]}, 1, 0]}}
            }}
        ]
        result = list(db.security_events.aggregate(pipeline))
        if result:
            res = result[0]
            res.pop("_id", None)
            return res
        return {"total_events": 0, "total_threats": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}
    except Exception as e:
        print(f"Error fetching stats: {e}")
        return {"total_events": 0, "total_threats": 0, "critical": 0, "high": 0, "medium": 0, "low": 0}

@app.get("/api/dashboard/attack-distribution")
def get_attack_distribution():
    if db is None:
        return {"distribution": []}
    try:
        pipeline = [
            {"$group": {"_id": "$attack_type", "count": {"$sum": 1}}},
            {"$project": {"attack_type": "$_id", "count": 1, "_id": 0}},
            {"$sort": {"count": -1}}
        ]
        result = list(db.security_events.aggregate(pipeline))
        return {"distribution": result}
    except Exception as e:
        print(f"Error fetching attack distribution: {e}")
        return {"distribution": []}

@app.get("/api/dashboard/timeline")
def get_timeline():
    if db is None:
        return {"timeline": []}
    try:
        pipeline = [
            {"$group": {
                "_id": {
                    "year": {"$year": "$timestamp"},
                    "month": {"$month": "$timestamp"},
                    "day": {"$dayOfMonth": "$timestamp"},
                    "hour": {"$hour": "$timestamp"},
                    "minute": {"$minute": "$timestamp"}
                },
                "events": {"$sum": 1},
                "threats": {"$sum": {"$cond": [{"$ne": ["$attack_type", "BENIGN"]}, 1, 0]}}
            }},
            {"$sort": {"_id.year": 1, "_id.month": 1, "_id.day": 1, "_id.hour": 1, "_id.minute": 1}},
            {"$limit": 60}
        ]
        result = list(db.security_events.aggregate(pipeline))
        timeline = []
        for r in result:
            _id = r["_id"]
            time_str = f"{_id.get('hour', 0):02d}:{_id.get('minute', 0):02d}"
            timeline.append({"time": time_str, "events": r["events"], "threats": r["threats"]})
        return {"timeline": timeline}
    except Exception as e:
        print(f"Error fetching timeline: {e}")
        return {"timeline": []}

@app.get("/api/dashboard/recent-alerts")
def get_recent_alerts():
    if db is None:
        return {"alerts": []}
    try:
        cursor = db.security_events.find({}, {"_id": 0}).sort("timestamp", -1).limit(10)
        alerts = list(cursor)
        return {"alerts": alerts}
    except Exception as e:
        print(f"Error fetching recent alerts: {e}")
        return {"alerts": []}
