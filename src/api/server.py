import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional
from fastapi import Depends, FastAPI, HTTPException, Security, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, Field
import redis.asyncio as redis
from celery import Celery

app=FastAPI(title="Hobbit-NG API",version="3.1.0")
security=HTTPBearer()
REDIS_URL=os.getenv("REDIS_URL","redis://localhost:6379/0")
JWT_SECRET=os.getenv("JWT_SECRET","")
redis_client=redis.from_url(REDIS_URL,decode_responses=True)
celery_app=Celery("hobbit",broker=REDIS_URL)
TENANTS={"tenant-1":{"name":"Development Tenant","plan":"development","rate_limit":100}}
USERS={"admin-1":{"tenant_id":"tenant-1","role":"admin","permissions":["scan:read","scan:create","remediate:plan"]}}
origins=[x for x in os.getenv("HOBBIT_CORS_ORIGINS","http://localhost:3000").split(',') if x]
app.add_middleware(CORSMiddleware,allow_origins=origins,allow_credentials=True,allow_methods=["GET","POST"],allow_headers=["Authorization","Content-Type"] )

class LoginRequest(BaseModel): username:str; password:str
class ScanRequest(BaseModel):
    targets:List[str]=Field(min_length=1,max_length=100)
    modules:List[str]=Field(default_factory=lambda:["recon","portscan","service_detect","vulnscan","webscan"])
    scan_depth:str=Field(default="standard",pattern="^(quick|standard|deep|comprehensive)$")
    authorized:bool=False
    schedule:Optional[str]=None
class RemediationRequest(BaseModel): finding_ids:List[str]; dry_run:bool=True; approval_ticket:Optional[str]=None

def _now(): return datetime.now(timezone.utc)
def verify_token(credentials:HTTPAuthorizationCredentials=Security(security)):
    if not JWT_SECRET: raise HTTPException(status_code=503,detail="JWT_SECRET is not configured")
    try: payload=jwt.decode(credentials.credentials,JWT_SECRET,algorithms=["HS256"])
    except JWTError: raise HTTPException(status_code=401,detail="Invalid token")
    user=USERS.get(payload.get("sub")); tenant=TENANTS.get(user.get("tenant_id")) if user else None
    if not user or not tenant: raise HTTPException(status_code=401,detail="Invalid principal")
    return {"user":user,"tenant":tenant}

@app.post("/auth/login")
async def login(request:LoginRequest):
    if os.getenv("HOBBIT_DEV_AUTH")!="1": raise HTTPException(status_code=503,detail="Development login disabled; configure an identity provider")
    expected=os.getenv("HOBBIT_DEV_ADMIN_PASSWORD","")
    if not expected or request.username!="admin-1" or request.password!=expected: raise HTTPException(status_code=401,detail="Invalid credentials")
    if not JWT_SECRET: raise HTTPException(status_code=503,detail="JWT_SECRET is not configured")
    token=jwt.encode({"sub":request.username,"exp":_now()+timedelta(hours=8)},JWT_SECRET,algorithm="HS256")
    return {"access_token":token,"token_type":"bearer"}

@app.post("/scans")
async def create_scan(request:ScanRequest,auth:Dict=Depends(verify_token)):
    if not request.authorized: raise HTTPException(status_code=400,detail="authorized=true is required and confirms permission to assess the supplied targets")
    tenant_id=auth["user"]["tenant_id"]; scan_id=hashlib.sha256(f"{tenant_id}:{_now().isoformat()}".encode()).hexdigest()[:16]
    count=int(await redis_client.get(f"rate_limit:{tenant_id}") or 0)
    if count>=auth["tenant"]["rate_limit"]: raise HTTPException(status_code=429,detail="Rate limit exceeded")
    pipe=redis_client.pipeline(); pipe.incr(f"rate_limit:{tenant_id}"); pipe.expire(f"rate_limit:{tenant_id}",3600); await pipe.execute()
    task=celery_app.send_task("src.workers.scanner.run_scan",args=[scan_id,tenant_id,request.model_dump()],queue="hobbit-scans")
    await redis_client.setex(f"scan:{scan_id}",86400,json.dumps({"status":"queued","tenant_id":tenant_id,"created_at":_now().isoformat()}))
    return {"scan_id":scan_id,"task_id":task.id,"status":"queued"}

@app.get("/scans/{scan_id}")
async def status(scan_id:str,auth:Dict=Depends(verify_token)):
    raw=await redis_client.get(f"scan:{scan_id}")
    if not raw: raise HTTPException(status_code=404,detail="Scan not found")
    scan=json.loads(raw)
    if scan.get("tenant_id")!=auth["user"]["tenant_id"]: raise HTTPException(status_code=403,detail="Access denied")
    return scan

@app.get("/scans/{scan_id}/results")
async def results(scan_id:str,auth:Dict=Depends(verify_token)):
    raw=await redis_client.get(f"scan:{scan_id}")
    if not raw: raise HTTPException(status_code=404,detail="Scan not found")
    scan=json.loads(raw)
    if scan.get("tenant_id")!=auth["user"]["tenant_id"]: raise HTTPException(status_code=403,detail="Access denied")
    if scan.get("status")!="completed": raise HTTPException(status_code=409,detail=f"Scan is {scan.get('status','unknown')}")
    return scan.get("report",{})

@app.post("/remediate")
async def remediate(request:RemediationRequest,auth:Dict=Depends(verify_token)):
    if not request.dry_run: raise HTTPException(status_code=403,detail="Automatic remediation execution is disabled in the baseline build")
    return {"remediation_id":"rem-"+hashlib.sha256(str(_now()).encode()).hexdigest()[:8],"dry_run":True,"actions":[]}

@app.websocket("/ws/scans/{scan_id}")
async def ws(websocket:WebSocket,scan_id:str):
    await websocket.accept(); pubsub=redis_client.pubsub(); await pubsub.subscribe(f"scan_updates:{scan_id}")
    try:
        async for message in pubsub.listen():
            if message.get("type")=="message": await websocket.send_text(message["data"])
    finally:
        await pubsub.unsubscribe(f"scan_updates:{scan_id}"); await pubsub.close()

@app.get("/health")
async def health():
    try: redis_ok=bool(await redis_client.ping())
    except Exception: redis_ok=False
    return {"status":"healthy" if redis_ok else "degraded","version":"3.1.0","components":{"redis":redis_ok,"worker":"external"}}
