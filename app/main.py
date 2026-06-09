"""
Cortex Cloud ASPM/DSPM 테스트용 취약 FastAPI 앱
각 엔드포인트는 의도적으로 취약하게 구성되어 있음
"""
from fastapi import FastAPI, Request, Depends, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy import create_engine, text
from sqlalchemy.orm import Session
import os, subprocess, json, hashlib

app = FastAPI(
    title="Cortex Test App",
    description="Intentionally vulnerable app for Cortex Cloud ASPM/DSPM testing",
    version="1.0.0"
)

# 템플릿 설정
templates = Jinja2Templates(directory="app/templates")

# ────────────────────────────────────────────
# VULNERABLE: 시크릿 평문 하드코딩 → Code Security 탐지 대상
# ────────────────────────────────────────────
AWS_ACCESS_KEY_ID     = "AKIAIOSFODNN7EXAMPLE"          # 하드코딩된 AWS Key
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfi" # 하드코딩된 Secret
DB_PASSWORD           = "SuperSecret1234!"               # 하드코딩된 DB 패스워드
SECRET_KEY            = "mysecretkey123"                 # JWT Secret 하드코딩
ADMIN_TOKEN           = "admin-token-12345"              # 관리자 토큰 하드코딩

DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "admin")
DB_NAME = os.getenv("DB_NAME", "testdb")

DATABASE_URL = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"

engine = create_engine(DATABASE_URL, echo=True)

def get_db():
    with engine.connect() as conn:
        yield conn

# ────────────────────────────────────────────
# Health check & Dashboard
# ────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def root(request: Request):
    """
    개편된 보안 테스트 대시보드 렌더링
    """
    return templates.TemplateResponse("index.html", {
        "request": request,
        "db_host": DB_HOST,
        "db_user": DB_USER,
        "env_vars": dict(os.environ)
    })

@app.get("/health")
def health():
    # VULNERABLE: 내부 환경정보 노출 → ASPM 탐지 대상
    return {
        "status": "ok",
        "db_host": DB_HOST,
        "db_user": DB_USER,
        "db_name": DB_NAME,
        "aws_key_preview": AWS_ACCESS_KEY_ID[:8] + "...",  # 키 일부 노출
        "python_path": os.environ.get("PATH"),
        "env_vars": dict(os.environ)  # VULNERABLE: 전체 환경변수 노출
    }

# ────────────────────────────────────────────
# VULNERABLE: SQL Injection → ASPM 탐지 대상
# ────────────────────────────────────────────
@app.get("/users")
def get_user(id: str, db: Session = Depends(get_db)):
    """
    VULNERABLE: SQL Injection
    예시 공격: /users?id=1 OR 1=1
    """
    # VULNERABLE: 입력값을 직접 쿼리에 삽입 (parameterized query 미사용)
    query = f"SELECT * FROM users WHERE id = {id}"
    try:
        result = db.execute(text(query))
        rows = [dict(row._mapping) for row in result]
        return {"users": rows}
    except Exception as e:
        return {"error": str(e), "query": query}  # VULNERABLE: 쿼리 노출

@app.get("/search")
def search_users(name: str, db: Session = Depends(get_db)):
    """
    VULNERABLE: SQL Injection (LIKE 절)
    예시 공격: /search?name=' OR '1'='1
    """
    query = f"SELECT id, name, email FROM users WHERE name LIKE '%{name}%'"
    try:
        result = db.execute(text(query))
        return {"results": [dict(row._mapping) for row in result]}
    except Exception as e:
        return {"error": str(e)}

# ────────────────────────────────────────────
# VULNERABLE: XSS → ASPM 탐지 대상
# ────────────────────────────────────────────
@app.get("/greet", response_class=HTMLResponse)
def greet(name: str = "Guest"):
    """
    VULNERABLE: Reflected XSS
    예시 공격: /greet?name=<script>alert('xss')</script>
    """
    # VULNERABLE: 입력값을 HTML에 직접 삽입 (이스케이프 없음)
    html = f"""
    <html>
      <body>
        <h1>Hello, {name}!</h1>
        <p>Welcome to the test application.</p>
      </body>
    </html>
    """
    return HTMLResponse(content=html)

# ────────────────────────────────────────────
# VULNERABLE: 인증 없는 관리자 엔드포인트 → ASPM 탐지 대상
# ────────────────────────────────────────────
@app.get("/admin")
def admin_panel(db: Session = Depends(get_db)):
    """
    VULNERABLE: 인증 없이 관리자 데이터 접근 가능
    """
    try:
        users = db.execute(text("SELECT * FROM users")).fetchall()
        cards = db.execute(text("SELECT * FROM credit_cards")).fetchall()
        return {
            "message": "Admin panel - no auth required!",
            "total_users": len(users),
            "all_users": [dict(r._mapping) for r in users],
            "credit_cards": [dict(r._mapping) for r in cards],  # 카드 정보 노출
        }
    except Exception as e:
        return {"error": str(e)}

@app.delete("/admin/users/{user_id}")
def delete_user(user_id: int, db: Session = Depends(get_db)):
    """
    VULNERABLE: 인증 없이 사용자 삭제 가능
    """
    db.execute(text(f"DELETE FROM users WHERE id = {user_id}"))
    db.commit()
    return {"message": f"User {user_id} deleted (no auth required)"}

# ────────────────────────────────────────────
# VULNERABLE: Command Injection → ASPM 탐지 대상
# ────────────────────────────────────────────
@app.get("/ping")
def ping_host(host: str):
    """
    VULNERABLE: OS Command Injection
    예시 공격: /ping?host=127.0.0.1; cat /etc/passwd
    """
    # VULNERABLE: 사용자 입력을 shell 명령에 직접 삽입
    result = subprocess.run(
        f"ping -c 1 {host}",
        shell=True,  # VULNERABLE: shell=True 사용
        capture_output=True,
        text=True,
        timeout=5
    )
    return {
        "host": host,
        "stdout": result.stdout,
        "stderr": result.stderr,
        "returncode": result.returncode
    }

# ────────────────────────────────────────────
# VULNERABLE: IDOR (Insecure Direct Object Reference)
# ────────────────────────────────────────────
@app.get("/profile/{user_id}")
def get_profile(user_id: int, db: Session = Depends(get_db)):
    """
    VULNERABLE: IDOR — 다른 사용자 프로필 접근 가능
    인증 없이 모든 user_id에 접근 가능
    """
    try:
        result = db.execute(
            text(f"SELECT * FROM users WHERE id = {user_id}")
        ).fetchone()
        if result:
            return dict(result._mapping)  # 민감 정보 포함 전체 반환
        return {"error": "User not found"}
    except Exception as e:
        return {"error": str(e)}

# ────────────────────────────────────────────
# VULNERABLE: 취약한 패스워드 해싱 (MD5)
# ────────────────────────────────────────────
@app.post("/register")
async def register(request: Request, db: Session = Depends(get_db)):
    """
    VULNERABLE: MD5 해싱 사용 (salt 없음)
    """
    data = await request.json()
    username = data.get("username")
    password = data.get("password")

    # VULNERABLE: MD5 해싱 사용
    hashed = hashlib.md5(password.encode()).hexdigest()

    try:
        db.execute(
            text(f"INSERT INTO users (name, password) VALUES ('{username}', '{hashed}')")
        )
        db.commit()
        return {"message": "User registered", "hashed_password": hashed}  # 해시 노출
    except Exception as e:
        return {"error": str(e)}

# ────────────────────────────────────────────
# VULNERABLE: 민감 데이터 평문 반환 → DSPM 탐지 대상
# ────────────────────────────────────────────
@app.get("/data/export")
def export_data(db: Session = Depends(get_db)):
    """
    VULNERABLE: 인증 없이 민감 데이터 전체 export
    DSPM: 주민번호, 카드번호, 의료정보 노출
    """
    try:
        users       = db.execute(text("SELECT * FROM users")).fetchall()
        cards       = db.execute(text("SELECT * FROM credit_cards")).fetchall()
        medical     = db.execute(text("SELECT * FROM medical_records")).fetchall()
        return {
            "users":           [dict(r._mapping) for r in users],
            "credit_cards":    [dict(r._mapping) for r in cards],
            "medical_records": [dict(r._mapping) for r in medical],
        }
    except Exception as e:
        return {"error": str(e)}
