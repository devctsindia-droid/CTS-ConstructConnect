
import os, secrets, hashlib, hmac, time, json
import requests
import psycopg
from psycopg.rows import dict_row
from contextlib import contextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

BASE=Path(__file__).resolve().parent
DATABASE_URL=os.environ.get("DATABASE_URL","")
SECRET=os.environ.get("CTS_SECRET","development-only-secret-change-me")
RAZORPAY_KEY_ID=os.environ.get("RAZORPAY_KEY_ID","")
RAZORPAY_KEY_SECRET=os.environ.get("RAZORPAY_KEY_SECRET","")
MEMBERSHIP_AMOUNT_PAISE=2000000
app=FastAPI(title="CTS ConstructConnect")
app.add_middleware(SessionMiddleware,secret_key=SECRET,https_only=os.environ.get("CTS_HTTPS","0")=="1",same_site="lax",max_age=86400*7)
CATS=["Cement","Steel & TMT","Hardware & Tools","M-Sand & Aggregates","Ready-Mix Concrete","Bricks & Blocks","Electrical","Plumbing & Sanitary","Paints & Chemicals","Tiles & Flooring","Construction Equipment","Crusher & Plant Spares","Equipment Rental","Contractors & Services","Manpower","Transport & Logistics","Real Estate","Tenders & Projects","Industrial Supplies","Safety Equipment"]
@contextmanager
def conn():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")
    c=psycopg.connect(DATABASE_URL,row_factory=dict_row)
    c.execute("SET search_path TO cts_app")
    try:
        yield c
        c.commit()
    except Exception:
        c.rollback()
        raise
    finally:
        c.close()
def pwdhash(p,salt=None):
    salt=salt or secrets.token_hex(16)
    return salt+":"+hashlib.pbkdf2_hmac("sha256",p.encode(),bytes.fromhex(salt),260000).hex()
def checkpwd(p,h):
    try:salt,_=h.split(":");return hmac.compare_digest(pwdhash(p,salt),h)
    except:return False
def init():
    with conn() as c:
        email=os.environ.get("CTS_ADMIN_EMAIL","").strip().lower()
        password=os.environ.get("CTS_ADMIN_PASSWORD","")
        if email and password and len(password)>=12 and not c.execute("SELECT 1 FROM users WHERE email=%s",(email,)).fetchone():
            c.execute("INSERT INTO users(email,name,role,password_hash,approved,created) VALUES(%s,%s,%s,%s,1,%s)",(email,"CTS Administrator","admin",pwdhash(password),int(time.time())))
init()
class Register(BaseModel):
    name:str=Field(min_length=2,max_length=100)
    email:str=Field(min_length=5,max_length=180)
    phone:str=Field(min_length=10,max_length=20)
    password:str=Field(min_length=10,max_length=200)
    role:str
    city:str=Field(min_length=2,max_length=90)
    district:str=Field(default="",max_length=90)
    pin:str=Field(default="",max_length=6)
    category:str=Field(default="",max_length=80)
    service_areas:str=Field(default="",max_length=250)
class Login(BaseModel):
    email:str;password:str
class Requirement(BaseModel):
    category:str;product:str=Field(min_length=3,max_length=160);quantity:str=Field(min_length=1,max_length=80);city:str=Field(min_length=2,max_length=90);district:str=Field(min_length=2,max_length=90);pin:str=Field(default="",max_length=6);details:str=Field(default="",max_length=1200)
class Quote(BaseModel):
    requirement_id:int;amount:float=Field(gt=0,le=10000000000);notes:str=Field(default="",max_length=600)
class Ad(BaseModel):
    headline:str=Field(min_length=4,max_length=150);category:str;target_city:str=Field(min_length=2,max_length=90);target_district:str=Field(default="",max_length=90)
class PaymentVerify(BaseModel):
    razorpay_order_id:str
    razorpay_payment_id:str
    razorpay_signature:str
def me(request):
    uid=request.session.get("uid")
    if not uid:raise HTTPException(401,"Please log in")
    with conn() as c:
        u=c.execute("SELECT id,email,phone,name,role,city,district,pin,category,service_areas,approved,membership_until FROM users WHERE id=%s",(uid,)).fetchone()
    if not u:raise HTTPException(401,"Session expired")
    return dict(u)
def role(request,r):
    u=me(request)
    if u["role"]!=r:raise HTTPException(403,"This action requires "+r+" access")
    return u
def publicuser(u):
    return {k:u[k] for k in ["id","name","role","city","district","pin","category","service_areas","approved"]}
def matches(req,supplier):
    if req["category"]!=supplier["category"]:return False
    areas=[supplier["city"],supplier["district"],supplier["pin"]]+[a.strip() for a in supplier["service_areas"].split(",")]
    locs=[req["city"],req["district"],req["pin"]]
    return any(a.strip() and b.strip() and a.casefold().strip()==b.casefold().strip() for a in areas for b in locs)
@app.get("/")
def index():return FileResponse(BASE/"static"/"index.html")
@app.get("/manifest.webmanifest")
def manifest():return FileResponse(BASE/"static"/"manifest.webmanifest",media_type="application/manifest+json")
@app.get("/sw.js")
def sw():return FileResponse(BASE/"static"/"sw.js",media_type="text/javascript")
@app.get("/icon.svg")
def icon():return FileResponse(BASE/"static"/"icon.svg",media_type="image/svg+xml")
@app.get("/api/categories")
def categories():return CATS
@app.post("/api/register")
def register(d:Register):
    if d.role not in ("buyer","supplier"):raise HTTPException(400,"Invalid role")
    if d.role=="supplier" and d.category not in CATS:raise HTTPException(400,"Select a supplier category")
    if d.pin and (len(d.pin)!=6 or not d.pin.isdigit()):raise HTTPException(400,"PIN must have 6 digits")
    phone="".join(ch for ch in d.phone if ch.isdigit())
    if len(phone)<10 or len(phone)>15:raise HTTPException(400,"Enter a valid mobile number")
    with conn() as c:
        try:
            c.execute("INSERT INTO users(email,phone,name,role,password_hash,city,district,pin,category,service_areas,approved,created) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",(d.email.strip().lower(),phone,d.name.strip(),d.role,pwdhash(d.password),d.city.strip(),d.district.strip(),d.pin,d.category if d.role=="supplier" else "",d.service_areas.strip() if d.role=="supplier" else "",1 if d.role=="buyer" else 0,int(time.time())))
        except psycopg.IntegrityError:raise HTTPException(409,"Email or mobile number already registered")
    return {"ok":True,"message":"Account created. Supplier listings require CTS approval." if d.role=="supplier" else "Buyer account created. Please sign in."}
@app.post("/api/login")
def login(d:Login,request:Request):
    with conn() as c:u=c.execute("SELECT * FROM users WHERE email=%s",(d.email.strip().lower(),)).fetchone()
    if not u or not checkpwd(d.password,u["password_hash"]):raise HTTPException(401,"Invalid email or password")
    request.session.clear();request.session["uid"]=u["id"]
    return {"ok":True,"role":u["role"]}
@app.post("/api/logout")
def logout(request:Request):request.session.clear();return {"ok":True}
@app.get("/api/me")
def who(request:Request):return me(request)
@app.get("/api/suppliers")
def suppliers(category:str="",city:str=""):
    with conn() as c:rows=[dict(r) for r in c.execute("SELECT id,name,city,district,pin,category,service_areas FROM users WHERE role='supplier' AND approved=1 ORDER BY id DESC LIMIT 300")]
    return [r for r in rows if (not category or r["category"]==category) and (not city or city.casefold() in " ".join([r["city"],r["district"],r["service_areas"]]).casefold())]
@app.post("/api/requirements")
def post_requirement(d:Requirement,request:Request):
    u=role(request,"buyer")
    if d.category not in CATS:raise HTTPException(400,"Invalid category")
    with conn() as c:
        cur=c.execute("INSERT INTO requirements(buyer_id,category,product,quantity,city,district,pin,details,created) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",(u["id"],d.category,d.product,d.quantity,d.city,d.district,d.pin,d.details,int(time.time())))
        return {"ok":True,"id":cur.fetchone()["id"]}
@app.get("/api/requirements")
def requirements(request:Request):
    u=me(request)
    with conn() as c:
        rs=[dict(x) for x in c.execute("SELECT r.*,u.name buyer_name FROM requirements r JOIN users u ON u.id=r.buyer_id ORDER BY r.id DESC LIMIT 300")]
    if u["role"]=="buyer":return [r for r in rs if r["buyer_id"]==u["id"]]
    if u["role"]=="supplier":
        if not u["approved"]:return []
        return [r for r in rs if matches(r,u)]
    return rs
@app.post("/api/quotes")
def post_quote(d:Quote,request:Request):
    u=role(request,"supplier")
    if not u["approved"]:raise HTTPException(403,"CTS approval pending")
    with conn() as c:
        r=c.execute("SELECT * FROM requirements WHERE id=%s",(d.requirement_id,)).fetchone()
        if not r:raise HTTPException(404,"Requirement not found")
        if not matches(dict(r),u):raise HTTPException(403,"Requirement is outside your matching area/category")
        try:c.execute("INSERT INTO quotes(requirement_id,supplier_id,amount,notes,created) VALUES(%s,%s,%s,%s,%s)",(d.requirement_id,u["id"],d.amount,d.notes,int(time.time())))
        except psycopg.IntegrityError:raise HTTPException(409,"You have already quoted for this requirement")
    return {"ok":True}
@app.get("/api/quotes/{reqid}")
def quotes(reqid:int,request:Request):
    u=me(request)
    with conn() as c:
        r=c.execute("SELECT buyer_id FROM requirements WHERE id=%s",(reqid,)).fetchone()
        if not r:raise HTTPException(404,"Requirement not found")
        if u["role"]=="buyer" and r["buyer_id"]!=u["id"]:raise HTTPException(403,"Not your requirement")
        if u["role"]=="supplier":
            q=c.execute("SELECT 1 FROM quotes WHERE requirement_id=%s AND supplier_id=%s",(reqid,u["id"])).fetchone()
            if not q:raise HTTPException(403,"Not your quotation")
        return [dict(x) for x in c.execute("SELECT q.id,q.amount,q.notes,q.created,u.name supplier_name FROM quotes q JOIN users u ON u.id=q.supplier_id WHERE q.requirement_id=%s ORDER BY q.amount",(reqid,))]
@app.post("/api/ads")
def create_ad(d:Ad,request:Request):
    u=role(request,"supplier")
    if d.category not in CATS:raise HTTPException(400,"Invalid category")
    with conn() as c:c.execute("INSERT INTO ads(supplier_id,headline,category,target_city,target_district,created) VALUES(%s,%s,%s,%s,%s,%s)",(u["id"],d.headline,d.category,d.target_city,d.target_district,int(time.time())))
    return {"ok":True,"message":"Advertisement submitted for CTS approval"}
@app.get("/api/ads")
def ads(city:str=""):
    with conn() as c:rows=[dict(x) for x in c.execute("SELECT a.id,a.headline,a.category,a.target_city,a.target_district,u.name supplier_name FROM ads a JOIN users u ON u.id=a.supplier_id WHERE a.approved=1 ORDER BY a.id DESC LIMIT 100")]
    return [x for x in rows if not city or city.casefold() in (x["target_city"]+" "+x["target_district"]).casefold()]
@app.get("/api/membership")
def membership(request:Request):
    u=me(request)
    return {"plan":"Verified Supplier Annual","amount_paise":MEMBERSHIP_AMOUNT_PAISE,"currency":"INR","membership_until":u["membership_until"],"configured":bool(RAZORPAY_KEY_ID and RAZORPAY_KEY_SECRET)}

@app.post("/api/payments/order")
def payment_order(request:Request):
    u=role(request,"supplier")
    if not RAZORPAY_KEY_ID or not RAZORPAY_KEY_SECRET:
        raise HTTPException(503,"Payment gateway setup is being completed")
    receipt=f"cts-{u['id']}-{int(time.time())}"
    try:
        response=requests.post("https://api.razorpay.com/v1/orders",auth=(RAZORPAY_KEY_ID,RAZORPAY_KEY_SECRET),json={"amount":MEMBERSHIP_AMOUNT_PAISE,"currency":"INR","receipt":receipt},timeout=15)
        response.raise_for_status()
        order=response.json()
    except Exception:
        raise HTTPException(502,"Unable to create payment order")
    with conn() as c:
        c.execute("INSERT INTO payments(user_id,provider_order_id,amount_paise,currency,status,created) VALUES(%s,%s,%s,%s,%s,%s)",(u["id"],order["id"],MEMBERSHIP_AMOUNT_PAISE,"INR","created",int(time.time())))
    return {"key":RAZORPAY_KEY_ID,"order_id":order["id"],"amount":MEMBERSHIP_AMOUNT_PAISE,"currency":"INR","name":"CTS ConstructConnect","description":"Verified Supplier Annual Membership","prefill":{"name":u["name"],"email":u["email"],"contact":u["phone"]}}

@app.post("/api/payments/verify")
def payment_verify(d:PaymentVerify,request:Request):
    u=role(request,"supplier")
    if not RAZORPAY_KEY_SECRET:
        raise HTTPException(503,"Payment gateway setup is being completed")
    expected=hmac.new(RAZORPAY_KEY_SECRET.encode(),f"{d.razorpay_order_id}|{d.razorpay_payment_id}".encode(),hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected,d.razorpay_signature):
        raise HTTPException(400,"Payment verification failed")
    now=int(time.time())
    with conn() as c:
        payment=c.execute("SELECT id,status FROM payments WHERE provider_order_id=%s AND user_id=%s",(d.razorpay_order_id,u["id"])).fetchone()
        if not payment: raise HTTPException(404,"Payment order not found")
        if payment["status"]!="paid":
            c.execute("UPDATE payments SET provider_payment_id=%s,status='paid',paid_at=%s WHERE id=%s",(d.razorpay_payment_id,now,payment["id"]))
            c.execute("UPDATE users SET membership_until=GREATEST(membership_until,%s)+%s WHERE id=%s",(now,365*86400,u["id"]))
    return {"ok":True,"message":"Payment verified. Annual supplier membership is active."}

@app.get("/api/admin")
def admin(request:Request):
    role(request,"admin")
    with conn() as c:
        return {"users":[dict(x) for x in c.execute("SELECT id,name,email,phone,role,city,district,category,approved FROM users ORDER BY id DESC LIMIT 300")],"ads":[dict(x) for x in c.execute("SELECT a.id,a.headline,a.target_city,a.approved,u.name supplier_name FROM ads a JOIN users u ON u.id=a.supplier_id ORDER BY a.id DESC LIMIT 300")],"counts":{k:c.execute("SELECT COUNT(*) AS count FROM "+table).fetchone()["count"] for k,table in [("users","users"),("requirements","requirements"),("quotes","quotes"),("ads","ads")]}}
@app.post("/api/admin/approve/{kind}/{itemid}")
def approve(kind:str,itemid:int,request:Request):
    role(request,"admin")
    table={"supplier":"users","ad":"ads"}.get(kind)
    if not table:raise HTTPException(400,"Invalid approval type")
    with conn() as c:
        if kind=="supplier":c.execute("UPDATE users SET approved=1 WHERE id=%s AND role='supplier'",(itemid,))
        else:c.execute("UPDATE ads SET approved=1 WHERE id=%s",(itemid,))
    return {"ok":True}
