# backend/main.py
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy.orm import Session
from datetime import datetime, timedelta
from typing import List
import logging
import redis
import json

from database import SessionLocal, engine, Base
from models import User, Threat, Activity, Alert
from schemas import (
    UserCreate, UserLogin, ThreatCreate, 
    ActivityCreate, AlertCreate, MLRequest
)
from alerts import send_email_alert
from ml_models import detect_anomalies
from elk_connector import ElasticsearchClient

# Create tables
Base.metadata.create_all(bind=engine)

app = FastAPI(title="Insider Threat Detection API", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Security
security = HTTPBearer()

# Redis
redis_client = redis.Redis(host='redis', port=6379, decode_responses=True)

# ELK
es_client = ElasticsearchClient()

logger = logging.getLogger(__name__)

# Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
):
    token = credentials.credentials
    user_id = redis_client.get(f"token:{token}")
    
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )
    
    user = db.query(User).filter(User.id == int(user_id)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )
    
    return user

@app.get("/")
async def root():
    return {
        "message": "Insider Threat Detection API",
        "version": "1.0.0",
        "status": "running"
    }

@app.post("/auth/register")
async def register(user_data: UserCreate, db: Session = Depends(get_db)):
    """Register new user"""
    # Check if user exists
    existing = db.query(User).filter(
        (User.email == user_data.email) | (User.username == user_data.username)
    ).first()
    
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User already exists"
        )
    
    # Create user
    user = User(
        username=user_data.username,
        email=user_data.email,
        full_name=user_data.full_name,
        role=user_data.role,
        department=user_data.department
    )
    user.set_password(user_data.password)
    
    db.add(user)
    db.commit()
    db.refresh(user)
    
    return {
        "message": "User created successfully",
        "user_id": user.id,
        "username": user.username
    }

@app.post("/auth/login")
async def login(login_data: UserLogin, db: Session = Depends(get_db)):
    """User login"""
    user = db.query(User).filter(User.email == login_data.email).first()
    
    if not user or not user.verify_password(login_data.password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials"
        )
    
    # Generate token
    import secrets
    token = secrets.token_hex(32)
    
    # Store in Redis (24 hours expiry)
    redis_client.setex(f"token:{token}", 86400, str(user.id))
    
    return {
        "access_token": token,
        "token_type": "bearer",
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "role": user.role,
            "department": user.department
        }
    }

@app.post("/threats")
async def create_threat(
    threat_data: ThreatCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Create new threat"""
    threat = Threat(
        threat_id=f"THREAT-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
        threat_type=threat_data.threat_type,
        severity=threat_data.severity,
        description=threat_data.description,
        source_ip=threat_data.source_ip,
        user_affected=threat_data.user_affected,
        department=threat_data.department,
        status="New",
        created_by=current_user.id
    )
    
    db.add(threat)
    db.commit()
    db.refresh(threat)
    
    # Send email alert for critical/high threats
    if threat.severity in ["Critical", "High"]:
        send_email_alert(threat)
    
    # Index in Elasticsearch
    es_client.index_threat(threat)
    
    return {
        "message": "Threat created",
        "threat_id": threat.threat_id,
        "alert_sent": threat.severity in ["Critical", "High"]
    }

@app.get("/threats")
async def get_threats(
    skip: int = 0,
    limit: int = 100,
    severity: str = None,
    status: str = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get threats with filters"""
    query = db.query(Threat)
    
    if severity:
        query = query.filter(Threat.severity == severity)
    if status:
        query = query.filter(Threat.status == status)
    
    threats = query.order_by(Threat.created_at.desc()).offset(skip).limit(limit).all()
    
    return {
        "threats": threats,
        "count": len(threats),
        "total": db.query(Threat).count()
    }

@app.post("/activities")
async def create_activity(
    activity_data: ActivityCreate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Log user activity"""
    activity = Activity(
        user_id=activity_data.user_id,
        activity_type=activity_data.activity_type,
        resource=activity_data.resource,
        risk_score=activity_data.risk_score,
        ip_address=activity_data.ip_address,
        department=activity_data.department
    )
    
    db.add(activity)
    db.commit()
    db.refresh(activity)
    
    # Check for anomalies using ML
    anomaly_score = detect_anomalies(activity)
    
    if anomaly_score > 0.7:  # High anomaly
        # Create automatic threat
        threat = Threat(
            threat_id=f"AUTO-{datetime.now().strftime('%Y%m%d-%H%M%S')}",
            threat_type="Suspicious Activity",
            severity="High",
            description=f"Anomalous activity detected: {activity.activity_type}",
            source_ip=activity.ip_address,
            user_affected=activity.user_id,
            department=activity.department,
            status="Investigating",
            created_by=current_user.id
        )
        
        db.add(threat)
        db.commit()
        
        # Send alert
        send_email_alert(threat)
        
        # Index in Elasticsearch
        es_client.index_threat(threat)
    
    # Index activity in Elasticsearch
    es_client.index_activity(activity)
    
    return {
        "message": "Activity logged",
        "activity_id": activity.id,
        "anomaly_score": anomaly_score,
        "threat_created": anomaly_score > 0.7
    }

@app.post("/ml/detect")
async def ml_detection(
    ml_request: MLRequest,
    current_user: User = Depends(get_current_user)
):
    """ML-based threat detection"""
    results = detect_anomalies(ml_request.data)
    
    return {
        "anomaly_scores": results,
        "threshold": 0.7,
        "high_risk_count": sum(1 for score in results if score > 0.7)
    }

@app.get("/dashboard/stats")
async def get_dashboard_stats(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Get dashboard statistics"""
    # Total counts
    total_threats = db.query(Threat).count()
    total_activities = db.query(Activity).count()
    total_users = db.query(User).count()
    
    # Threats by severity
    severity_counts = {}
    for severity in ["Critical", "High", "Medium", "Low"]:
        count = db.query(Threat).filter(Threat.severity == severity).count()
        severity_counts[severity] = count
    
    # Recent threats (last 24 hours)
    recent_threats = db.query(Threat).filter(
        Threat.created_at >= datetime.now() - timedelta(hours=24)
    ).count()
    
    # High risk activities
    high_risk_activities = db.query(Activity).filter(
        Activity.risk_score >= 70
    ).count()
    
    return {
        "total_threats": total_threats,
        "total_activities": total_activities,
        "total_users": total_users,
        "severity_distribution": severity_counts,
        "recent_threats_24h": recent_threats,
        "high_risk_activities": high_risk_activities,
        "system_status": "operational"
    }

@app.get("/elk/status")
async def get_elk_status():
    """Check ELK stack status"""
    return es_client.get_status()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)