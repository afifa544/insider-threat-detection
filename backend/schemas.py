# backend/schemas.py
from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional, List, Dict, Any

class UserBase(BaseModel):
    username: str
    email: EmailStr
    full_name: str
    role: str = "viewer"
    department: str

class UserCreate(UserBase):
    password: str

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserResponse(UserBase):
    id: int
    is_active: bool
    created_at: datetime
    
    class Config:
        from_attributes = True

class ThreatBase(BaseModel):
    threat_type: str
    severity: str
    description: str
    source_ip: str
    user_affected: str
    department: str

class ThreatCreate(ThreatBase):
    status: str = "new"

class ThreatResponse(ThreatBase):
    id: int
    threat_id: str
    status: str
    created_by: int
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True

class ActivityBase(BaseModel):
    user_id: str
    activity_type: str
    resource: str
    risk_score: int
    ip_address: str
    department: str

class ActivityCreate(ActivityBase):
    pass

class ActivityResponse(ActivityBase):
    id: int
    timestamp: datetime
    anomaly_score: float
    is_anomaly: int
    
    class Config:
        from_attributes = True

class AlertCreate(BaseModel):
    alert_type: str
    message: str
    severity: str
    threat_id: Optional[int] = None

class MLRequest(BaseModel):
    data: List[Dict[str, Any]]

class StatsResponse(BaseModel):
    total_threats: int
    total_activities: int
    total_users: int
    severity_distribution: Dict[str, int]
    recent_threats_24h: int
    high_risk_activities: int
    system_status: str

class ELKStatus(BaseModel):
    connected: bool
    elasticsearch: bool
    kibana: bool
    logstash: bool
    indices: List[str]