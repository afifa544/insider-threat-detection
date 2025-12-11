# backend/models.py
from sqlalchemy import Column, Integer, String, DateTime, Text, ForeignKey, Float
from sqlalchemy.orm import relationship
from datetime import datetime
from passlib.context import CryptContext
from database import Base

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class User(Base):
    __tablename__ = "users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(50), unique=True, nullable=False)
    email = Column(String(100), unique=True, nullable=False)
    full_name = Column(String(100))
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(50), default="viewer")  # admin, analyst, viewer
    department = Column(String(100))
    is_active = Column(Integer, default=1)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    threats_created = relationship("Threat", back_populates="creator")
    alerts = relationship("Alert", back_populates="user")
    
    def set_password(self, password):
        self.hashed_password = pwd_context.hash(password)
    
    def verify_password(self, password):
        return pwd_context.verify(password, self.hashed_password)

class Threat(Base):
    __tablename__ = "threats"
    
    id = Column(Integer, primary_key=True, index=True)
    threat_id = Column(String(50), unique=True, nullable=False)
    threat_type = Column(String(100))  # malware, phishing, data_exfiltration
    severity = Column(String(20))  # critical, high, medium, low
    description = Column(Text)
    source_ip = Column(String(50))
    user_affected = Column(String(100))
    department = Column(String(100))
    status = Column(String(50), default="new")  # new, investigating, resolved
    created_by = Column(Integer, ForeignKey("users.id"))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    creator = relationship("User", back_populates="threats_created")
    alerts = relationship("Alert", back_populates="threat")

class Activity(Base):
    __tablename__ = "activities"
    
    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(String(100), nullable=False)
    activity_type = Column(String(100))  # login, file_access, download
    resource = Column(String(200))
    risk_score = Column(Integer)  # 0-100
    ip_address = Column(String(50))
    department = Column(String(100))
    timestamp = Column(DateTime, default=datetime.utcnow)
    
    # ML features
    anomaly_score = Column(Float, default=0.0)
    is_anomaly = Column(Integer, default=0)  # 0=normal, 1=anomaly

class Alert(Base):
    __tablename__ = "alerts"
    
    id = Column(Integer, primary_key=True, index=True)
    alert_id = Column(String(50), unique=True, nullable=False)
    alert_type = Column(String(100))
    message = Column(Text)
    severity = Column(String(20))
    threat_id = Column(Integer, ForeignKey("threats.id"), nullable=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    status = Column(String(50), default="unread")  # unread, read, acknowledged
    created_at = Column(DateTime, default=datetime.utcnow)
    sent_at = Column(DateTime, nullable=True)
    
    # Relationships
    threat = relationship("Threat", back_populates="alerts")
    user = relationship("User", back_populates="alerts")

class SysmonUser(Base):
    __tablename__ = "sysmon_users"
    
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(100))
    domain = Column(String(100))
    full_name = Column(String(200))
    department = Column(String(100))
    role = Column(String(100))
    risk_level = Column(String(50))  # critical, high, medium, low
    risk_score = Column(Float)
    threat_count = Column(Integer, default=0)
    is_service_account = Column(Integer, default=0)
    first_seen = Column(DateTime)
    last_seen = Column(DateTime)
    processes = Column(Text)  # JSON string of processes
    extracted_at = Column(DateTime, default=datetime.utcnow)