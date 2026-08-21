import asyncio
import json
import os
import redis
from src.core.engine import AIEnhancedEngine
from src.workers.celery_app import celery_app

@celery_app.task(name="src.workers.scanner.run_scan")
def run_scan(scan_id,tenant_id,request):
    client=redis.from_url(os.getenv("REDIS_URL","redis://localhost:6379/0"),decode_responses=True)
    key=f"scan:{scan_id}"
    client.setex(key,86400,json.dumps({"status":"running","tenant_id":tenant_id}))
    try:
        engine=AIEnhancedEngine(os.getenv("HOBBIT_CONFIG","config/default.yaml"),authorized=bool(request.get("authorized")))
        modules=request.get("modules") or ["portscan","service_detect","vulnscan","webscan"]
        report=asyncio.run(engine.run_scan(request.get("targets") or [],modules,request.get("scan_depth","standard")))
        client.setex(key,86400,json.dumps({"status":"completed","tenant_id":tenant_id,"report":report},default=str))
        return {"scan_id":scan_id,"status":"completed"}
    except Exception as exc:
        client.setex(key,86400,json.dumps({"status":"failed","tenant_id":tenant_id,"error":str(exc)}))
        raise
