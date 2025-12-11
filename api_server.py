# api_server.py - COMPLETE WORKING VERSION
from fastapi import FastAPI, HTTPException, status, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
import os
from dotenv import load_dotenv
import logging
import hashlib
import secrets
from datetime import datetime, timedelta
from typing import Optional
import json

load_dotenv()

# ============================================
# CONFIGURATION
# ============================================
APP_SECRET = os.getenv("APP_SECRET", "insider-threat-detection-secret-2024")
EMAIL_SMTP = os.getenv("SMTP_SERVER", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("SMTP_PORT", 587))
SENDER_EMAIL = os.getenv("SENDER_EMAIL", "taskeenafifa934@gmail.com")
SENDER_PASSWORD = os.getenv("SENDER_PASSWORD", "rkzi jjpi yydy ldhc")
ADMIN_EMAIL = os.getenv("ADMIN_EMAILS", "taskeenafifa934@gmail.com")

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("security_api")

# ============================================
# FASTAPI APP
# ============================================
app = FastAPI(
    title="Insider Threat Detection API",
    description="Backend API for Insider Threat Detection System",
    version="2.0.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration - Allow all for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================
# PASSWORD HASHING
# ============================================
def hash_password(password: str, salt: str = "insider-threat-salt") -> str:
    """Simple but secure password hashing for demo"""
    return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()

# ============================================
# USER DATABASE
# ============================================
USERS_DB = {
    "admin": {
        "username": "admin",
        "password_hash": hash_password("admin123"),
        "full_name": "System Administrator",
        "email": "admin@company.com",
        "role": "admin",
        "department": "IT Security",
        "permissions": ["view", "edit", "delete", "admin"]
    }
}

TOKENS_DB = {}
THREATS_DB = {}  # Store threats in memory

# ============================================
# PYDANTIC MODELS
# ============================================
class LoginRequest(BaseModel):
    username: str
    password: str

class ThreatItem(BaseModel):
    id: str
    timestamp: str
    threat_type: str
    severity: str
    user_id: str
    department: str = "Unknown"
    description: str
    status: str = "New"
    risk_score: int
    mitre_technique: Optional[str] = None
    nist_category: Optional[str] = None
    action_required: Optional[str] = "Review"
    affected_data: Optional[str] = "Various"

# ============================================
# AUTHENTICATION FUNCTIONS
# ============================================
def authenticate_user(username: str, password: str) -> Optional[dict]:
    """Authenticate user with username and password"""
    user = USERS_DB.get(username)
    if not user:
        return None
    
    if user["password_hash"] != hash_password(password):
        return None
    
    return {
        "username": user["username"],
        "full_name": user["full_name"],
        "email": user["email"],
        "role": user["role"],
        "department": user["department"],
        "permissions": user["permissions"]
    }

def create_token(user_info: dict) -> str:
    """Create a secure token for the user"""
    token = f"token_{user_info['username']}_{secrets.token_hex(16)}"
    TOKENS_DB[token] = {
        "user": user_info,
        "created": datetime.now(),
        "expires": datetime.now().timestamp() + 3600  # 1 hour
    }
    return token

def verify_token(token: str) -> Optional[dict]:
    """Verify if token is valid"""
    if token not in TOKENS_DB:
        return None
    
    token_data = TOKENS_DB[token]
    if datetime.now().timestamp() > token_data["expires"]:
        del TOKENS_DB[token]  # Cleanup expired token
        return None
    
    return token_data["user"]

# ============================================
# HELPER FUNCTIONS
# ============================================
def send_real_email(threat: dict) -> bool:
    """Send real email using SMTP"""
    try:
        import smtplib
        from email.mime.multipart import MIMEMultipart
        from email.mime.text import MIMEText
        
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = ADMIN_EMAIL
        msg['Subject'] = f"🚨 {threat['severity']} Threat Alert: {threat['threat_type']}"
        
        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
                .alert {{ border: 2px solid #dc2626; border-radius: 10px; padding: 20px; margin: 20px 0; }}
                .header {{ background: #dc2626; color: white; padding: 15px; border-radius: 8px 8px 0 0; }}
                .details {{ background: #f8fafc; padding: 15px; border-radius: 0 0 8px 8px; }}
                .field {{ margin: 10px 0; }}
                .label {{ font-weight: bold; color: #475569; }}
            </style>
        </head>
        <body>
            <div class="alert">
                <div class="header">
                    <h2>🛡️ Insider Threat Detected</h2>
                    <h3>Severity: {threat['severity']} | Action Required: {threat.get('action_required', 'Immediate')}</h3>
                </div>
                <div class="details">
                    <div class="field"><span class="label">Threat ID:</span> {threat['id']}</div>
                    <div class="field"><span class="label">Time:</span> {threat['timestamp']}</div>
                    <div class="field"><span class="label">Type:</span> {threat['threat_type']}</div>
                    <div class="field"><span class="label">User:</span> {threat['user_id']}</div>
                    <div class="field"><span class="label">Risk Score:</span> {threat['risk_score']}/100</div>
                    <div class="field"><span class="label">Status:</span> {threat['status']}</div>
                    <div class="field"><span class="label">Description:</span> {threat['description']}</div>
                </div>
            </div>
            <p>This is an automated alert from the Insider Threat Detection System.</p>
            <p>Please investigate this threat immediately.</p>
        </body>
        </html>
        """
        
        msg.attach(MIMEText(html_content, 'html'))
        
        with smtplib.SMTP(EMAIL_SMTP, EMAIL_PORT) as server:
            server.starttls()
            server.login(SENDER_EMAIL, SENDER_PASSWORD)
            server.send_message(msg)
        
        logger.info(f"✅ Email sent successfully for threat {threat['id']}")
        return True
    except Exception as e:
        logger.error(f"❌ Failed to send email: {str(e)}")
        return False

def generate_sample_threats(count: int = 10):
    """Generate sample threats for testing"""
    threats = []
    threat_types = ["Data Exfiltration", "Unauthorized Access", "Privilege Abuse", 
                   "Suspicious Download", "After Hours Activity", "Policy Violation",
                   "Credential Theft", "Data Destruction", "Insider Trading"]
    
    for i in range(count):
        severity = ["Low", "Medium", "High", "Critical"][i % 4]
        threat_type = threat_types[i % len(threat_types)]
        
        threat = {
            "id": f"THREAT-{1000 + i}",
            "timestamp": (datetime.now() - timedelta(hours=i)).isoformat(),
            "threat_type": threat_type,
            "severity": severity,
            "user_id": f"USER{1500 + (i * 7) % 50}",
            "department": ["IT", "Finance", "HR", "Engineering"][i % 4],
            "description": f"Sample {severity.lower()} level {threat_type.lower()} detected",
            "status": ["New", "Investigating", "Resolved"][i % 3],
            "risk_score": 30 + (i * 7) % 70,
            "mitre_technique": "Initial Access" if i % 2 == 0 else "Exfiltration",
            "nist_category": "Detect" if severity in ["High", "Critical"] else "Protect",
            "action_required": "Immediate" if severity in ["Critical", "High"] else "Review",
            "affected_data": "Various"
        }
        threats.append(threat)
        THREATS_DB[threat["id"]] = threat
    
    logger.info(f"✅ Generated {len(threats)} sample threats")
    return threats

# ============================================
# API ENDPOINTS
# ============================================

@app.get("/")
async def root():
    """Root endpoint - API info"""
    return {
        "message": "Insider Threat Detection API",
        "version": "2.0.0",
        "status": "running",
        "timestamp": datetime.now().isoformat(),
        "endpoints": {
            "auth": "POST /api/login",
            "email": "POST /api/send-email",
            "threats": {
                "index": "POST /api/index-threat",
                "get": "GET /api/threats",
                "delete": "DELETE /api/threats/{id}"
            },
            "health": "GET /health",
            "stats": "GET /api/stats",
            "docs": "GET /docs"
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {
        "status": "healthy",
        "service": "insider-threat-api",
        "timestamp": datetime.now().isoformat(),
        "users_online": len(TOKENS_DB),
        "threats_stored": len(THREATS_DB),
        "uptime": "100%"
    }

@app.get("/api/test")
async def test_endpoint():
    """Test endpoint for dashboard connection check"""
    return {
        "status": "ok",
        "message": "API is working",
        "timestamp": datetime.now().isoformat(),
        "version": "2.0.0"
    }

@app.post("/api/login")
async def login(request: LoginRequest):
    """User login endpoint"""
    try:
        user = authenticate_user(request.username, request.password)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid username or password"
            )
        
        token = create_token(user)
        
        return {
            "access_token": token,
            "token_type": "bearer",
            "user": user,
            "expires_in": 3600
        }
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Login failed: {str(e)}"
        )

@app.post("/api/send-email")
async def send_email(threat: ThreatItem, request: Request):
    """Send email alert for a threat"""
    # Get token from header (optional for testing)
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        user = verify_token(token)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )
    
    # Convert to dict
    threat_dict = threat.dict()
    
    # Try to send real email
    success = send_real_email(threat_dict)
    
    # Store threat
    THREATS_DB[threat.id] = {
        **threat_dict,
        "email_sent": success,
        "email_timestamp": datetime.now().isoformat(),
        "indexed": True
    }
    
    return {
        "status": "sent" if success else "simulated",
        "message": f"Email {'sent' if success else 'simulated'} for {threat.severity} threat",
        "threat_id": threat.id,
        "method": "smtp" if success else "simulation"
    }

@app.post("/api/index-threat")
async def index_threat(threat: ThreatItem, request: Request):
    """Index threat to database"""
    # Get token from header (optional for testing)
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        user = verify_token(token)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )
    
    # Store threat
    threat_dict = threat.dict()
    threat_dict["indexed_at"] = datetime.now().isoformat()
    threat_dict["indexed_by"] = "api"
    
    THREATS_DB[threat.id] = threat_dict
    
    return {
        "indexed": True,
        "id": threat.id,
        "message": f"Threat {threat.id} indexed successfully",
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/threats")
async def get_threats(request: Request, limit: int = 100):
    """Get all threats"""
    # Get token from header (optional for testing)
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        user = verify_token(token)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )
    
    # Return stored threats
    threats = list(THREATS_DB.values())
    
    # Sort by timestamp (newest first)
    threats.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    
    return {
        "threats": threats[:limit],
        "count": len(threats[:limit]),
        "total": len(threats),
        "timestamp": datetime.now().isoformat()
    }

@app.get("/api/stats")
async def get_stats(request: Request):
    """Get system statistics"""
    # Get token from header (optional for testing)
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        user = verify_token(token)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )
    
    threats = list(THREATS_DB.values())
    
    # Calculate statistics
    severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    for threat in threats:
        severity = threat.get('severity', 'Unknown')
        if severity in severity_counts:
            severity_counts[severity] += 1
    
    avg_risk_score = sum(t.get('risk_score', 0) for t in threats) / len(threats) if threats else 0
    
    stats = {
        "total_threats": len(threats),
        "severity_distribution": severity_counts,
        "average_risk_score": round(avg_risk_score, 2),
        "users_online": len(TOKENS_DB),
        "emails_sent": sum(1 for t in threats if t.get('email_sent', False)),
        "system_uptime": "99.8%",
        "api_version": "2.0.0",
        "last_updated": datetime.now().isoformat()
    }
    
    return stats

@app.delete("/api/threats/{threat_id}")
async def delete_threat(threat_id: str, request: Request):
    """Delete a threat"""
    # Get token from header
    auth_header = request.headers.get("Authorization")
    if not auth_header or not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization header required"
        )
    
    token = auth_header.split(" ")[1]
    user = verify_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token"
        )
    
    if threat_id in THREATS_DB:
        del THREATS_DB[threat_id]
        return {
            "deleted": True,
            "id": threat_id,
            "message": f"Threat {threat_id} deleted"
        }
    else:
        raise HTTPException(
            status_code=404,
            detail=f"Threat {threat_id} not found"
        )

@app.post("/api/threats/bulk")
async def create_bulk_threats(threats: list[ThreatItem], request: Request):
    """Create multiple threats at once"""
    # Get token from header (optional for testing)
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.split(" ")[1]
        user = verify_token(token)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired token"
            )
    
    results = []
    for threat in threats:
        threat_dict = threat.dict()
        THREATS_DB[threat.id] = threat_dict
        results.append({
            "id": threat.id,
            "status": "created",
            "timestamp": datetime.now().isoformat()
        })
    
    return {
        "created": len(results),
        "results": results
    }

# ============================================
# ERROR HANDLERS
# ============================================
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "status_code": exc.status_code,
            "path": request.url.path
        }
    )

@app.exception_handler(404)
async def not_found_handler(request, exc):
    return JSONResponse(
        status_code=404,
        content={
            "error": "Endpoint not found",
            "path": request.url.path,
            "available_endpoints": [
                "/",
                "/health",
                "/docs",
                "/api/login",
                "/api/send-email",
                "/api/index-threat",
                "/api/threats",
                "/api/stats",
                "/api/test"
            ]
        }
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": str(exc),
            "path": request.url.path
        }
    )

# ============================================
# INITIALIZATION
# ============================================
# Generate sample threats when module loads
generate_sample_threats(20)