from fastapi import FastAPI, HTTPException, Depends, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel, HttpUrl
import requests
import os
import hashlib
import zipfile
import shutil
import uuid
import re
import ast
import time
import threading
from typing import Optional, Dict, Any, List
from datetime import datetime
import stat

# ==============================================
# การตั้งค่าหลัก
# ==============================================
app = FastAPI(
    title="VIDER Install API",
    description="ระบบจัดการติดตั้งส่วนขยาย พร้อมควบคุมสิทธิ์และความปลอดภัย",
    version="1.3.0",
    docs_url="/docs",
    redoc_url="/redoc"
)

# 🔑 รหัสปลดล็อกทั้งหมด
UNLOCK_CODES = {
    "main": "SC.Thanva",
    "secondary": "Chani",
    "private": "install244"
}
ALLOWED_PLATFORMS = ["microsoft", "genai", "vider"]

# 🌐 เซิร์ฟเวอร์ควบคุมกลาง (แก้ไขเป็นลิงก์ของคุณเองได้)
CONTROL_SERVER = "https://api.vider-control.example.com"
CONTROL_KEY = "VIDER_ROOT_2026_244_SECURE"

# 🛡️ ความปลอดภัย
SAFE_FILE_EXTENSIONS = [".py", ".txt", ".md", ".json", ".csv", ".yml", ".yaml"]
DANGEROUS_PATTERNS = [
    r"os\.system", r"os\.popen", r"subprocess\.", r"eval\(", r"exec\(",
    r"__import__", r"builtins\.", r"globals\(", r"locals\(",
    r"shutil\.rmtree", r"os\.remove", r"os\.unlink", r"os\.chmod",
    r"open\(.+,\s*['\"]w['\"]", r"open\(.+,\s*['\"]a['\"]",
    r"socket\.", r"urllib\.", r"requests\.", r"http\.",
    r"base64\.decode", r"pickle\.", r"marshal\.", r"cryptography\."
]
ALLOWED_IMPORTS = [
    "math", "random", "datetime", "json", "re", "typing",
    "collections", "itertools", "uuid", "hashlib", "time"
]

# 📂 โฟลเดอร์ทำงาน
BASE_DIR = "./vider_extensions"
DOWNLOAD_DIR = f"{BASE_DIR}/downloads"
INSTALLED_DIR = f"{BASE_DIR}/installed"
BACKUP_DIR = f"{BASE_DIR}/backup"
QUARANTINE_DIR = f"{BASE_DIR}/quarantine"

for folder in [BASE_DIR, DOWNLOAD_DIR, INSTALLED_DIR, BACKUP_DIR, QUARANTINE_DIR]:
    os.makedirs(folder, exist_ok=True)
    os.chmod(folder, stat.S_IRWXU | stat.S_IXGRP | stat.S_IXOTH)

# 📊 ข้อมูลระบบ
INSTALLED_EXTENSIONS: Dict[str, Any] = {}
USER_LOGS: List[Dict[str, Any]] = []
BLOCKED_IPS = set()
BLOCKED_COUNTRIES = set()
DISABLED_CODES = set()
LAST_VERIFICATION = 0
VERIFY_INTERVAL = 3600

# ==============================================
# ฟังก์ชันช่วยเหลือ
# ==============================================
def get_client_ip(request: Request) -> str:
    x_forwarded = request.headers.get("X-Forwarded-For")
    if x_forwarded:
        return x_forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"

def get_country_from_ip(ip: str) -> str:
    try:
        res = requests.get(f"https://ipapi.co/{ip}/country_name/", timeout=3)
        if res.status_code == 200:
            return res.text.strip()
    except:
        pass
    return "unknown"

def verify_with_server(code: str, platform: str, ip: str, country: str) -> Dict[str, Any]:
    global BLOCKED_IPS, BLOCKED_COUNTRIES, DISABLED_CODES
    try:
        res = requests.post(
            f"{CONTROL_SERVER}/verify",
            json={
                "unlock_code": code,
                "platform": platform,
                "ip": ip,
                "country": country,
                "timestamp": int(time.time())
            },
            headers={"X-Control-Key": CONTROL_KEY},
            timeout=10
        )
        if res.status_code == 200:
            data = res.json()
            BLOCKED_IPS = set(data.get("blocked_ips", []))
            BLOCKED_COUNTRIES = set(data.get("blocked_countries", []))
            DISABLED_CODES = set(data.get("disabled_codes", []))
            return {"valid": data.get("valid", False), "level": data.get("level", "none")}
    except:
        pass
    if code in DISABLED_CODES:
        return {"valid": False, "reason": "รหัสถูกระงับ"}
    if code in UNLOCK_CODES.values():
        return {"valid": True, "level": "full" if code == UNLOCK_CODES["main"] else 
                "standard" if code == UNLOCK_CODES["secondary"] else "private_full"}
    return {"valid": False, "reason": "รหัสไม่ถูกต้อง"}

def calculate_file_hash(file_path: str) -> str:
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256.update(chunk)
        return sha256.hexdigest()
    except:
        return ""

def scan_code_security(file_path: str) -> Dict[str, Any]:
    issues = []
    blocked = []
    risk_score = 0
    try:
        ext = os.path.splitext(file_path)[1].lower()
        if ext not in SAFE_FILE_EXTENSIONS:
            issues.append(f"นามสกุลไม่อนุญาต: {ext}")
            risk_score += 30

        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()

        for pattern in DANGEROUS_PATTERNS:
            if re.search(pattern, content):
                blocked.append(pattern)
                issues.append(f"พบโค้ดเสี่ยง: {pattern}")
                risk_score += 15

        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        mod = alias.name.split('.')[0]
                        if mod not in ALLOWED_IMPORTS:
                            issues.append(f"โมดูลไม่อนุญาต: {mod}")
                            risk_score += 10
        except SyntaxError:
            issues.append("ไวยากรณ์ไม่ถูกต้อง")
            risk_score += 25

        risk_score = min(risk_score, 100)
        risk_level = "critical" if risk_score >=70 else "high" if risk_score >=40 else "medium" if risk_score >=20 else "low"
        return {"safe": risk_score < 40, "risk_level": risk_level, "issues": issues, "score": 100 - risk_score}
    except:
        return {"safe": False, "risk_level": "unknown", "issues": ["อ่านไฟล์ไม่ได้"], "score": 0}

def download_file(url: str, save_path: str) -> bool:
    try:
        res = requests.get(
            url, 
            headers={"User-Agent": "VIDER-Install/1.3"}, 
            timeout=45, 
            stream=True,
            verify=True
        )
        res.raise_for_status()
        if int(res.headers.get("content-length", 0)) > 50 * 1024 * 1024:
            raise ValueError("ไฟล์ใหญ่เกิน 50MB")
        with open(save_path, "wb") as f:
            for chunk in res.iter_content(8192):
                f.write(chunk)
        return True
    except Exception as e:
        raise HTTPException(400, detail=f"ดาวน์โหลดล้มเหลว: {str(e)}")

def extract_package(file_path: str, extract_to: str) -> bool:
    try:
        if not file_path.endswith(".zip"):
            return False
        with zipfile.ZipFile(file_path, "r") as zf:
            for info in zf.infolist():
                if info.filename.startswith("/") or ".." in info.filename:
                    raise ValueError("เส้นทางไฟล์อันตราย")
            zf.extractall(extract_to)
        return True
    except:
        return False

# ==============================================
# ระบบตรวจสอบสิทธิ์
# ==============================================
def verify_access(
    request: Request,
    x_unlock_code: Optional[str] = Header(None),
    x_platform: Optional[str] = Header(None)
):
    global LAST_VERIFICATION
    client_ip = get_client_ip(request)
    client_country = get_country_from_ip(client_ip)
    platform = x_platform.lower() if x_platform else "unknown"

    if not x_unlock_code or not x_platform:
        raise HTTPException(401, detail="ต้องระบุรหัสปลดล็อกและแพลตฟอร์ม")
    if platform not in ALLOWED_PLATFORMS:
        raise HTTPException(403, detail="แพลตฟอร์มไม่ได้รับอนุญาต")
    if client_ip in BLOCKED_IPS:
        raise HTTPException(403, detail="IP ถูกระงับ")

    if int(time.time()) - LAST_VERIFICATION > VERIFY_INTERVAL:
        result = verify_with_server(x_unlock_code, platform, client_ip, client_country)
        LAST_VERIFICATION = int(time.time())
    else:
        result = verify_with_server(x_unlock_code, platform, client_ip, client_country)

    if not result["valid"]:
        raise HTTPException(403, detail=f"ไม่มีสิทธิ์: {result['reason']}")

    USER_LOGS.append({
        "timestamp": datetime.now().isoformat(),
        "ip": client_ip,
        "country": client_country,
        "platform": platform,
        "code": x_unlock_code,
        "success": True
    })

    return {
        "level": result["level"],
        "ip": client_ip,
        "country": client_country,
        "platform": platform
    }

# ==============================================
# API Endpoints
# ==============================================
class InstallRequest(BaseModel):
    name: str
    description: Optional[str] = ""
    source_url: HttpUrl
    version: str = "latest"
    expected_hash: Optional[str] = None
    unlock_code: str

@app.get("/", summary="ตรวจสอบสถานะระบบ")
async def root():
    return {
        "system": "VIDER Install API",
        "version": "1.3.0",
        "status": "active",
        "docs": "/docs"
    }

@app.post("/install/extension", summary="ติดตั้งส่วนขยาย")
async def install_extension(req: InstallRequest, access: Dict = Depends(verify_access)):
    ext_id = f"ext_{datetime.now().strftime('%Y%m%d%H%M%S')}_{uuid.uuid4().hex[:8]}"
    temp_file = f"{DOWNLOAD_DIR}/{ext_id}.zip"
    install_path = f"{INSTALLED_DIR}/{ext_id}"

    try:
        download_file(str(req.source_url), temp_file)
        file_hash = calculate_file_hash(temp_file)

        if req.expected_hash and file_hash != req.expected_hash:
            shutil.move(temp_file, f"{QUARANTINE_DIR}/{ext_id}.zip")
            raise HTTPException(400, detail="แฮชไฟล์ไม่ตรงกับที่ระบุ")

        security = scan_code_security(temp_file)
        if not security["safe"]:
            shutil.move(temp_file, f"{QUARANTINE_DIR}/{ext_id}.zip")
            raise HTTPException(400, detail=f"ตรวจพบความเสี่ยง: {security['issues']}")

        os.makedirs(install_path, exist_ok=True)
        if not extract_package(temp_file, install_path):
            raise HTTPException(500, detail="ติดตั้งไม่สำเร็จ")

        INSTALLED_EXTENSIONS[ext_id] = {
            "id": ext_id,
            "name": req.name,
            "version": req.version,
            "install_date": datetime.now().isoformat(),
            "hash": file_hash,
            "security_score": security["score"],
            "risk_level": security["risk_level"],
            "installed_by": access["ip"]
        }

        os.remove(temp_file)
        return {
            "status": "success",
            "message": "ติดตั้งสำเร็จ",
            "extension": INSTALLED_EXTENSIONS[ext_id]
        }

    except Exception as e:
        if os.path.exists(temp_file):
            os.remove(temp_file)
        if os.path.exists(install_path):
            shutil.rmtree(install_path)
        raise HTTPException(400, detail=str(e))

@app.get("/extensions/list", summary="ดูรายการที่ติดตั้ง")
async def list_extensions(access: Dict = Depends(verify_access)):
    return {
        "total": len(INSTALLED_EXTENSIONS),
        "extensions": list(INSTALLED_EXTENSIONS.values())
    }

@app.get("/admin/logs", summary="ดูบันทึกการใช้งาน")
async def get_logs(access: Dict = Depends(verify_access)):
    if access["level"] not in ["full", "private_full"]:
        raise HTTPException(403, detail="ไม่มีสิทธิ์")
    return {
        "total_logs": len(USER_LOGS),
        "recent": USER_LOGS[-50:]
    }

@app.get("/status", summary="สถานะระบบ")
async def status(access: Dict = Depends(verify_access)):
    return {
        "system": "VIDER Install",
        "version": "1.3.0",
        "user": access,
        "total_extensions": len(INSTALLED_EXTENSIONS),
        "blocked_ips": len(BLOCKED_IPS)
    }

# ==============================================
# รันระบบ
# ==============================================
if __name__ == "__main__":
    print("=" * 70)
    print("🚀 VIDER INSTALL API - พร้อมใช้งาน")
    print("🔑 รหัส: SC.Thanva | Chani | install244")
    print("📚 เอกสาร: http://localhost:8000/docs")
    print("=" * 70)
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=False)

