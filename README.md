# nexile_app.py



import os
import jwt
import bcrypt
from datetime import datetime, timedelta
from typing import Optional, List

from fastapi import FastAPI, Depends, HTTPException, Header, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware

from pydantic import BaseModel, EmailStr
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Text, Float, ForeignKey
from sqlalchemy.orm import sessionmaker, declarative_base, relationship, Session

# -----------------------------
# Config
# -----------------------------
JWT_SECRET = os.getenv("JWT_SECRET", "change-me")
JWT_ALGO = "HS256"
DATABASE_URL = "sqlite:///./nexile.db"

# -----------------------------
# DB setup
# -----------------------------
engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False, autocommit=False)
Base = declarative_base()

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# -----------------------------
# Models
# -----------------------------
class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    password_hash = Column(String)
    role = Column(String, default="pharmacist")  # pharmacist, owner, manager, patient
    name = Column(String, default="User")
    org = Column(String, default="Nexile")

class Medicine(Base):
    __tablename__ = "medicines"
    id = Column(Integer, primary_key=True)
    name = Column(String, index=True)
    generic_name = Column(String, index=True)
    form = Column(String)   # tablet, syrup
    strength = Column(String)  # 500mg, etc.
    advice = Column(Text)   # general pharmacist advice
    max_daily_dose = Column(Float) 
    min_age_years = Column(Float)  

class InventoryItem(Base):
    __tablename__ = "inventory"
    id = Column(Integer, primary_key=True)
    medicine_id = Column(Integer, ForeignKey("medicines.id"))
    quantity = Column(Integer, default=0)
    price = Column(Float, default=0.0)
    batch = Column(String)
    expires_on = Column(String)
    medicine = relationship("Medicine")

class Consultation(Base):
    __tablename__ = "consultations"
    id = Column(Integer, primary_key=True)
    patient_desc = Column(Text)
    ai_summary = Column(Text)        # AI triage summary (not a prescription)
    ai_options = Column(Text)        # JSON-like string of suggestions
    pharmacist_notes = Column(Text)  # final notes/approval
    approved = Column(Boolean, default=False)
    created_by = Column(Integer, ForeignKey("users.id"))
    created_role = Column(String, default="patient")
    created_at = Column(String, default=lambda: datetime.utcnow().isoformat())

class Feedback(Base):
    __tablename__ = "feedback"
    id = Column(Integer, primary_key=True)
    consultation_id = Column(Integer, ForeignKey("consultations.id"))
    rating = Column(Integer)  # 1-5
    comments = Column(Text)

Base.metadata.create_all(bind=engine)

# -----------------------------
# Schemas
# -----------------------------
class SignUp(BaseModel):
    email: EmailStr
    password: str
    name: Optional[str] = "User"
    org: Optional[str] = "Nexile"
    role: Optional[str] = "pharmacist"  # pharmacist, owner, manager, patient

class Login(BaseModel):
    email: EmailStr
    password: str
    role: Optional[str] = None  # optional role hint for redirection

class MedicineCreate(BaseModel):
    name: str
    generic_name: str
    form: str
    strength: str
    advice: str
    max_daily_dose: Optional[float] = None
    min_age_years: Optional[float] = None

class InventoryCreate(BaseModel):
    medicine_id: int
    quantity: int
    price: float
    batch: str
    expires_on: str

class TriageInput(BaseModel):
    patient_description: str
    age_years: Optional[float] = None
    weight_kg: Optional[float] = None
    allergies: Optional[List[str]] = []
    current_meds: Optional[List[str]] = []

class DoseInput(BaseModel):
    medicine_name: str
    weight_kg: Optional[float] = None
    age_years: Optional[float] = None

class FeedbackCreate(BaseModel):
    consultation_id: int
    rating: int
    comments: Optional[str] = None

# -----------------------------
# Security helpers
# -----------------------------
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode(), bcrypt.gensalt()).decode()

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(plain.encode(), hashed.encode())

def create_token(user: User) -> str:
    payload = {
        "sub": user.id,
        "email": user.email,
        "role": user.role,
        "name": user.name,
        "org": user.org,
        "exp": datetime.utcnow() + timedelta(hours=12),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGO)

def decode_token(token: str):
    return jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGO])

def require_role(authorization: str, db: Session, roles: List[str]) -> User:
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Missing token")
    token = authorization.split("Bearer ")[1]
    try:
        payload = decode_token(token)
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")
    user = db.query(User).get(payload["sub"])
    if not user or user.role not in roles:
        raise HTTPException(status_code=403, detail=f"Access requires roles: {roles}")
    return user

# -----------------------------
# FastAPI app
# -----------------------------
app = FastAPI(title="Nexile Multi-role Portal")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"],
)

# -----------------------------
# Auth endpoints
# -----------------------------
@app.post("/auth/signup")
def signup(data: SignUp, db: Session = Depends(get_db)):
    if data.role not in ["pharmacist", "owner", "manager", "patient"]:
        raise HTTPException(status_code=400, detail="Invalid role")
    existing = db.query(User).filter(User.email == data.email).first()
    if existing:
        raise HTTPException(status_code=400, detail="Email already registered.")
    user = User(
        email=data.email,
        password_hash=hash_password(data.password),
        role=data.role,
        name=data.name,
        org=data.org
    )
    db.add(user)
    db.commit()
    return {"message": "Signup successful", "email": data.email, "role": data.role}

@app.post("/auth/login")
def login(data: Login, db: Session = Depends(get_db)):
    user = db.query(User).filter(User.email == data.email).first()
    if not user or not verify_password(data.password, user.password_hash):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_token(user)
    return {"token": token, "name": user.name, "org": user.org, "role": user.role}

# -----------------------------
# Inventory endpoints
# -----------------------------
@app.post("/inventory/medicine")
def add_medicine(
    data: MedicineCreate,
    db: Session = Depends(get_db),
    authorization: str = Header(None)
):
    user = require_role(authorization, db, roles=["pharmacist", "owner", "manager"])
    med = Medicine(**data.dict())
    db.add(med)
    db.commit()
    return {"message": "Medicine added", "id": med.id}

@app.get("/inventory/medicine")
def list_medicines(
    db: Session = Depends(get_db),
    authorization: str = Header(None)
):
    user = require_role(authorization, db, roles=["pharmacist", "owner", "manager"])
    meds = db.query(Medicine).all()
    return [{
        "id": m.id, "name": m.name, "generic_name": m.generic_name,
        "form": m.form, "strength": m.strength, "advice": m.advice
    } for m in meds]

@app.post("/inventory/stock")
def add_stock(
    data: InventoryCreate,
    db: Session = Depends(get_db),
    authorization: str = Header(None)
):
    user = require_role(authorization, db, roles=["pharmacist", "owner", "manager"])
    med = db.query(Medicine).get(data.medicine_id)
    if not med:
        raise HTTPException(status_code=404, detail="Medicine not found")
    item = InventoryItem(**data.dict())
    db.add(item)
    db.commit()
    return {"message": "Stock added", "id": item.id}

@app.get("/inventory/stock")
def list_stock(
    db: Session = Depends(get_db),
    authorization: str = Header(None)
):
    user = require_role(authorization, db, roles=["pharmacist", "owner", "manager"])
    items = db.query(InventoryItem).all()
    return [{
        "id": i.id, "medicine": i.medicine.name, "qty": i.quantity,
        "price": i.price, "batch": i.batch, "expires": i.expires_on
    } for i in items]

# -----------------------------
# AI triage: pharmacist review only
# -----------------------------
def simple_rule_engine(desc: str, medicines: List[Medicine]):
    desc_lower = desc.lower()
    suggestions = []

    if any(k in desc_lower for k in ["fever", "temperature", "pyrexia"]):
        for m in medicines:
            if "paracetamol" in (m.generic_name or "").lower() or "acetaminophen" in (m.generic_name or "").lower():
                suggestions.append({"medicine_id": m.id, "name": m.name, "reason": "Common first-line for fever", "advice": m.advice})
    if any(k in desc_lower for k in ["pain", "ache"]):
        for m in medicines:
            if "ibuprofen" in (m.generic_name or "").lower():
                suggestions.append({"medicine_id": m.id, "name": m.name, "reason": "Analgesic option", "advice": m.advice})

    # De-duplicate
    seen = set()
    unique = []
    for s in suggestions:
        if s["medicine_id"] not in seen:
            unique.append(s)
            seen.add(s["medicine_id"])
    return unique

@app.post("/ai/triage")
def triage(
    data: TriageInput,
    db: Session = Depends(get_db),
    authorization: str = Header(None)
):
    user = require_role(authorization, db, roles=["pharmacist"])
    meds = db.query(Medicine).all()
    options = simple_rule_engine(data.patient_description, meds)
    summary = (
        "AI triage summary for pharmacist review. "
        "Suggestions below are not a prescription and must be confirmed by a pharmacist."
    )
    consult = Consultation(
        patient_desc=data.patient_description,
        ai_summary=summary,
        ai_options=str(options),
        created_by=user.id,
        created_role=user.role,
        approved=False,
    )
    db.add(consult)
    db.commit()
    return {"consultation_id": consult.id, "ai_summary": summary, "options": options}

@app.post("/ai/approve/{consultation_id}")
def approve_consultation(
    consultation_id: int,
    notes: str,
    db: Session = Depends(get_db),
    authorization: str = Header(None)
):
    user = require_role(authorization, db, roles=["pharmacist"])
    consult = db.query(Consultation).get(consultation_id)
    if not consult:
        raise HTTPException(status_code=404, detail="Consultation not found")
    consult.pharmacist_notes = notes
    consult.approved = True
    db.commit()
    return {"message": "Consultation approved"}

# -----------------------------
# Dose calculator (pharmacist-only)
# -----------------------------
@app.post("/dose/calculate")
def calculate_dose(
    data: DoseInput,
    db: Session = Depends(get_db),
    authorization: str = Header(None)
):
    user = require_role(authorization, db, roles=["pharmacist"])
    med = db.query(Medicine).filter(Medicine.name.ilike(f"%{data.medicine_name}%")).first()
    if not med:
        raise HTTPException(status_code=404, detail="Medicine not found")

    suggested = {"per_dose": None, "max_daily": med.max_daily_dose, "notes": ""}

    if data.weight_kg and "paracetamol" in (med.generic_name or "").lower():
        per_dose = min(10 * data.weight_kg, med.max_daily_dose / 4 if med.max_daily_dose else 500)
        suggested["per_dose"] = round(per_dose, 2)
        suggested["notes"] = "Conservative placeholder; pharmacist must verify."

    if med.min_age_years and data.age_years and data.age_years < med.min_age_years:
        suggested["notes"] += " Not recommended below configured age."

    return {"medicine": med.name, "suggested": suggested, "warning": "Not a prescription. Pharmacist approval required."}

# -----------------------------
# Feedback (pharmacist-only)
# -----------------------------
@app.post("/feedback")
def submit_feedback(
    data: FeedbackCreate,
    db: Session = Depends(get_db),
    authorization: str = Header(None)
):
    user = require_role(authorization, db, roles=["pharmacist"])
    consult = db.query(Consultation).get(data.consultation_id)
    if not consult:
        raise HTTPException(status_code=404, detail="Consultation not found")
    fb = Feedback(consultation_id=data.consultation_id, rating=data.rating, comments=data.comments or "")
    db.add(fb)
    db.commit()
    return {"message": "Feedback recorded"}

# -----------------------------
# Patient intake (patient can create a consultation; pharmacist reviews)
# -----------------------------
@app.post("/patient/intake")
def patient_intake(
    data: TriageInput,
    db: Session = Depends(get_db),
    authorization: str = Header(None)
):
    user = require_role(authorization, db, roles=["patient"])
    consult = Consultation(
        patient_desc=data.patient_description,
        ai_summary="Submitted for pharmacist review. No prescription provided.",
        ai_options="[]",
        created_by=user.id,
        created_role=user.role,
        approved=False,
    )
    db.add(consult)
    db.commit()
    return {"message": "Your information has been submitted. A pharmacist will review it.", "consultation_id": consult.id}

# -----------------------------
# HTML pages (inline with animation + branding)
# -----------------------------
STYLE = """
<style>
:root { --nexile:#6b5bff; --bg:#0f1220; --card:#181c2f; --text:#e6e8ff; --accent:#00d4ff; }
* { box-sizing:border-box; }
body {
  margin:0; font-family: Inter, system-ui, -apple-system, Segoe UI, Roboto;
  background: radial-gradient(1000px 500px at 20% 10%, rgba(107,91,255,.25), transparent),
              linear-gradient(180deg, #0f1220 0%, #0a0d18 100%);
  color: var(--text); min-height: 100vh;
}
.layer-nexile { position:fixed; inset:0; pointer-events:none;
  background-image: repeating-linear-gradient(45deg, rgba(107,91,255,0.04) 0 20px, transparent 20px 40px);
}
.card {
  width: 360px; margin: 10vh auto; padding: 28px; background: var(--card);
  border-radius: 14px; box-shadow: 0 20px 60px rgba(0,0,0,.4), inset 0 0 0 1px rgba(255,255,255,.06);
  animation: floatIn .8s ease forwards, glow 6s ease-in-out infinite; opacity:0; transform: translateY(20px) scale(.98);
}
@keyframes floatIn { to { opacity: 1; transform: translateY(0) scale(1);} }
@keyframes glow { 0%,100% { box-shadow: 0 20px 60px rgba(0,0,0,.4), 0 0 0 0 rgba(0,212,255,.0);}
                  50% { box-shadow: 0 20px 60px rgba(0,0,0,.4), 0 0 30px 6px rgba(0,212,255,.2);} }

h1.brand { text-align:center; letter-spacing:1px; margin-bottom:18px; }
h1.brand span { color: var(--nexile); }
input, button, select, textarea {
  width: 100%; padding: 12px 14px; border-radius: 10px;
  border: 1px solid rgba(255,255,255,.1); background: #121528; color: var(--text);
  margin-top: 10px;
}
button {
  background: linear-gradient(90deg, var(--nexile), var(--accent));
  border: none; font-weight: 600; cursor: pointer; transition: transform .15s ease, filter .2s ease;
}
button:hover { transform: translateY(-2px); filter: brightness(1.1); }
.link { display:block; text-align:center; margin-top:10px; color: var(--accent); text-decoration:none; }
small.hint { display:block; margin-top:6px; opacity:.7; }
pre { background:#0e1122; padding:12px; border-radius:10px; overflow:auto; }
section { margin-top: 16px; }
.wrapper { width: 960px; max-width: 96vw; margin: 6vh auto; }
.card-wide { max-width: 960px; width: auto; }
.nav { display:flex; gap:8px; justify-content:flex-end; margin: 12px 0; }
.badge { display:inline-block; padding:6px 10px; border-radius: 999px; background: #121528; border:1px solid rgba(255,255,255,.08); }
</style>
"""

SCRIPT = """
<script>
const API = window.location.origin;
let TOKEN = localStorage.getItem("token");
let ROLE = localStorage.getItem("role");
let NAME = localStorage.getItem("name");

function setSession(token, role, name) {
  TOKEN = token; ROLE = role; NAME = name;
  localStorage.setItem("token", token);
  localStorage.setItem("role", role);
  localStorage.setItem("name", name);
}

async function signup() {
  const body = {
    email: document.getElementById("email").value,
    name: document.getElementById("name").value,
    org: document.getElementById("org").value,
    password: document.getElementById("password").value,
    role: document.getElementById("role").value
  };
  const r = await fetch(`${API}/auth/signup`, { method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(body) });
  const d = await r.json();
  alert(d.message || "Signed up");
  window.location.href = "/login";
}

async function login() {
  const body = { email: document.getElementById("email").value, password: document.getElementById("password").value, role: document.getElementById("role").value };
  const r = await fetch(`${API}/auth/login`, { method:"POST", headers:{"Content-Type":"application/json"}, body: JSON.stringify(body) });
  const d = await r.json();
  if (d.token) {
    setSession(d.token, d.role, d.name);
    if (d.role === "owner") window.location.href = "/owner";
    else if (d.role === "manager") window.location.href = "/manager";
    else if (d.role === "patient") window.location.href = "/patient";
    else window.location.href = "/pharmacist";
  } else alert("Login failed");
}

async function authed(path, opts = {}) {
  opts.headers = Object.assign({}, opts.headers || {}, { Authorization: `Bearer ${TOKEN}` });
  return fetch(`${API}${path}`, opts);
}

// Pharmacist dashboard helpers
async function loadMedicines() {
  const r = await authed("/inventory/medicine");
  document.getElementById("meds").textContent = JSON.stringify(await r.json(), null, 2);
}
async function loadStock() {
  const r = await authed("/inventory/stock");
  document.getElementById("stock").textContent = JSON.stringify(await r.json(), null, 2);
}
async function triage() {
  const body = {
    patient_description: document.getElementById("desc").value,
    age_years: parseFloat(document.getElementById("age").value || "0") || null,
    weight_kg: parseFloat(document.getElementById("weight").value || "0") || null
  };
  const r = await authed("/ai/triage", { method:"POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(body) });
  document.getElementById("triage").textContent = JSON.stringify(await r.json(), null, 2);
}
async function approve() {
  const id = parseInt(prompt("Consultation ID to approve:"));
  const notes = prompt("Pharmacist notes:");
  const r = await authed(`/ai/approve/${id}?notes=${encodeURIComponent(notes)}`, { method:"POST" });
  alert((await r.json()).message || "Done");
}
async function dose() {
  const body = {
    medicine_name: document.getElementById("dose-med").value,
    age_years: parseFloat(document.getElementById("dose-age").value || "0") || null,
    weight_kg: parseFloat(document.getElementById("dose-weight").value || "0") || null
  };
  const r = await authed("/dose/calculate", { method:"POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(body) });
  document.getElementById("dose").textContent = JSON.stringify(await r.json(), null, 2);
}

// Patient intake
async function patientSubmit() {
  const body = {
    patient_description: document.getElementById("p-desc").value,
    age_years: parseFloat(document.getElementById("p-age").value || "0") || null,
    weight_kg: parseFloat(document.getElementById("p-weight").value || "0") || null
  };
  const r = await authed("/patient/intake", { method:"POST", headers: {"Content-Type":"application/json"}, body: JSON.stringify(body) });
  const d = await r.json();
  document.getElementById("p-res").textContent = JSON.stringify(d, null, 2);
}
</script>
"""

def page_shell(title: str, body_html: str) -> str:
    return f"""<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8" />
  <title>{title}</title>
  {STYLE}
</head>
<body>
  <div class="layer-nexile"></div>
  {body_html}
  {SCRIPT}
</body>
</html>"""

# -----------------------------
# Page routes
# -----------------------------
@app.get("/", response_class=HTMLResponse)
def home():
    return page_shell("Nexile | Home", """
    <div class="card">
      <h1 class="brand">Welcome to <span>Nexile</span></h1>
      <a class="link" href="/login">Login</a>
      <a class="link" href="/signup">Create account</a>
      <small class="hint">Pharmacists, Owners, Managers, and Patients have role-based access.</small>
    </div>
    """)

@app.get("/login", response_class=HTMLResponse)
def login_page():
    return page_shell("Nexile | Login", """
    <div class="card">
      <h1 class="brand">Log in to <span>Nexile</span></h1>
      <select id="role">
        <option value="pharmacist">Pharmacist</option>
        <option value="owner">Owner</option>
        <option value="manager">Manager</option>
        <option value="patient">Patient</option>
      </select>
      <input id="email" type="email" placeholder="Email" />
      <input id="password" type="password" placeholder="Password" />
      <button onclick="login()">Log in</button>
      <a class="link" href="/signup">Create account</a>
      <small class="hint">Access is limited by permissions. Unauthorized use is prohibited.</small>
    </div>
    """)

@app.get("/signup", response_class=HTMLResponse)
def signup_page():
    return page_shell("Nexile | Signup", """
    <div class="card">
      <h1 class="brand">Join <span>Nexile</span></h1>
      <select id="role">
        <option value="pharmacist">Pharmacist</option>
        <option value="owner">Owner</option>
        <option value="manager">Manager</option>
        <option value="patient">Patient</option>
      </select>
      <input id="email" type="email" placeholder="Work email" />
      <input id="name" type="text" placeholder="Your name" />
      <input id="org" type="text" placeholder="Organization (optional)" />
      <input id="password" type="password" placeholder="Password" />
      <button onclick="signup()">Sign up</button>
      <a class="link" href="/login">Back to login</a>
      <small class="hint">Accounts are role-specific. Pharmacist-only features remain restricted.</small>
    </div>
    """)

@app.get("/pharmacist", response_class=HTMLResponse)
def pharmacist_dashboard():
    return page_shell("Nexile | Pharmacist Dashboard", """
    <div class="wrapper">
      <div class="nav">
        <span class="badge">Role: Pharmacist</span>
        <a class="link" href="/">Home</a>
      </div>
      <div class="card card-wide">
        <h1 class="brand">Nexile <span>Pharmacist Portal</span></h1>

        <section>
          <h3>Inventory</h3>
          <button onclick="loadMedicines()">List medicines</button>
          <pre id="meds"></pre>
          <button onclick="loadStock()">List stock</button>
          <pre id="stock"></pre>
        </section>

        <section>
          <h3>AI triage (for review)</h3>
          <textarea id="desc" placeholder="Patient description"></textarea>
          <input id="age" type="number" step="0.1" placeholder="Age (years)" />
          <input id="weight" type="number" step="0.1" placeholder="Weight (kg)" />
          <button onclick="triage()">Suggest options</button>
          <button onclick="approve()">Approve consultation</button>
          <pre id="triage"></pre>
        </section>

        <section>
          <h3>Dose calculator (pharmacist-only)</h3>
          <input id="dose-med" placeholder="Medicine name" />
          <input id="dose-age" type="number" step="0.1" placeholder="Age (years)" />
          <input id="dose-weight" type="number" step="0.1" placeholder="Weight (kg)" />
          <button onclick="dose()">Calculate</button>
          <pre id="dose"></pre>
        </section>
      </div>
    </div>
    """)

@app.get("/owner", response_class=HTMLResponse)
def owner_dashboard():
    return page_shell("Nexile | Owner Dashboard", """
    <div class="wrapper">
      <div class="nav">
        <span class="badge">Role: Owner</span>
        <a class="link" href="/">Home</a>
      </div>
      <div class="card card-wide">
        <h1 class="brand">Nexile <span>Owner Dashboard</span></h1>
        <section>
          <h3>Overview</h3>
          <p>Owners can manage medicine catalog and stock. Use API endpoints under Inventory.</p>
        </section>
      </div>
    </div>
    """)

@app.get("/manager", response_class=HTMLResponse)
def manager_dashboard():
    return page_shell("Nexile | Manager Dashboard", """
    <div class="wrapper">
      <div class="nav">
        <span class="badge">Role: Manager</span>
        <a class="link" href="/">Home</a>
      </div>
      <div class="card card-wide">
        <h1 class="brand">Nexile <span>Manager Dashboard</span></h1>
        <section>
          <h3>Operations</h3>
          <p>Managers can list/add medicines and stock via Inventory API endpoints.</p>
        </section>
      </div>
    </div>
    """)

@app.get("/patient", response_class=HTMLResponse)
def patient_portal():
    return page_shell("Nexile | Patient Portal", """
    <div class="wrapper">
      <div class="nav">
        <span class="badge">Role: Patient</span>
        <a class="link" href="/">Home</a>
      </div>
      <div class="card card-wide">
        <h1 class="brand">Nexile <span>Patient Intake</span></h1>
        <section>
          <h3>Describe your symptoms</h3>
          <textarea id="p-desc" placeholder="Describe what you're experiencing"></textarea>
          <input id="p-age" type="number" step="0.1" placeholder="Age (years)" />
          <input id="p-weight" type="number" step="0.1" placeholder="Weight (kg)" />
          <button onclick="patientSubmit()">Submit for pharmacist review</button>
          <pre id="p-res"></pre>
          <small class="hint">No prescriptions are provided here. A pharmacist will review and advise.</small>
        </section>
      </div>
    </div>
    """)

# -----------------------------
# Root API sanity check
# -----------------------------
@app.get("/api", response_class=JSONResponse)
def api_root():
    return {"message": "Nexile multi-role API running"}
