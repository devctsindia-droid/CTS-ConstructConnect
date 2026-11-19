
import os, secrets, hashlib, hmac, time, json, base64
import requests
import psycopg
from psycopg.rows import dict_row
from contextlib import contextmanager
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request, Response, UploadFile, File, Form
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.sessions import SessionMiddleware

BASE=Path(__file__).resolve().parent
DATABASE_URL=os.environ.get("DATABASE_URL","")
SECRET=os.environ.get("CTS_SECRET","development-only-secret-change-me")
RAZORPAY_KEY_ID=os.environ.get("RAZORPAY_KEY_ID","")
RAZORPAY_KEY_SECRET=os.environ.get("RAZORPAY_KEY_SECRET","")
MEMBERSHIP_AMOUNT_PAISE=2000000
SUPPLIER_TRIAL_SECONDS=30*86400
app=FastAPI(title="CTS ConstructConnect")
app.add_middleware(SessionMiddleware,secret_key=SECRET,https_only=os.environ.get("CTS_HTTPS","0")=="1",same_site="lax",max_age=86400*7)
app.mount("/static",StaticFiles(directory=BASE/"static"),name="static")
CATS=["Cement","Steel & TMT","Hardware & Tools","M-Sand & Aggregates","Ready-Mix Concrete","Bricks & Blocks","Electrical","Plumbing & Sanitary","Paints & Chemicals","Tiles & Flooring","Construction Equipment","Crusher & Plant Spares","Equipment Rental","Contractors & Services","Manpower","Transport & Logistics","Real Estate","Tenders & Projects","Industrial Supplies","Safety Equipment"]
JOB_ROLES=["Civil Engineer","Project Manager","Construction Manager","Site Engineer","Quantity Surveyor","Billing Engineer","Land Surveyor / Survey Team","Safety Officer","QA / QC Engineer","Planning Engineer","RMC / Batching Plant Operator","Crusher / M-Sand Plant Operator","Mechanical Technician","Electrical Technician","Supervisor / Foreman","Skilled Construction Worker","Other Construction Role"]
MATERIAL_CATS={"Cement","Steel & TMT","Hardware & Tools","M-Sand & Aggregates","Ready-Mix Concrete","Bricks & Blocks","Electrical","Plumbing & Sanitary","Paints & Chemicals","Tiles & Flooring","Industrial Supplies","Safety Equipment"}
MACHINERY_CATS={"Construction Equipment","Crusher & Plant Spares","Equipment Rental"}
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
def reset_admin_password():
    # Recovery is controlled by the operator's private Render environment.
    if os.environ.get("CTS_ADMIN_PASSWORD_RESET", "") != "1":
        return
    email=os.environ.get("CTS_ADMIN_EMAIL", "").strip().lower()
    password=os.environ.get("CTS_ADMIN_PASSWORD", "")
    if not email or len(password)<12:
        raise RuntimeError("Admin recovery requires an email and password of at least 12 characters")
    with conn() as c:
        u=c.execute("SELECT id,password_hash FROM users WHERE email=%s AND role='admin'",(email,)).fetchone()
        if not u:
            raise RuntimeError("Admin recovery account not found")
        if not checkpwd(password,u["password_hash"]):
            c.execute("UPDATE users SET password_hash=%s WHERE id=%s AND role='admin'",(pwdhash(password),u["id"]))
reset_admin_password()
class Register(BaseModel):
    name:str=Field(min_length=2,max_length=100)
    email:str=Field(min_length=5,max_length=180)
    phone:str=Field(min_length=10,max_length=20)
    password:str=Field(min_length=10,max_length=200)
    role:str
    country:str=Field(default="India",min_length=2,max_length=90)
    state_region:str=Field(default="",max_length=100)
    city:str=Field(min_length=2,max_length=90)
    district:str=Field(default="",max_length=90)
    postal_code:str=Field(default="",max_length=20)
    pin:str=Field(default="",max_length=20)
    whatsapp:str=Field(default="",max_length=30)
    website:str=Field(default="",max_length=250)
    company_type:str=Field(default="",max_length=100)
    products_services:str=Field(default="",max_length=1000)
    target_markets:str=Field(default="",max_length=500)
    public_contact:bool=False
    category:str=Field(default="",max_length=80)
    service_areas:str=Field(default="",max_length=500)
class QuickRegister(BaseModel):
    name:str=Field(min_length=2,max_length=100)
    phone:str=Field(min_length=7,max_length=20)
    role:str
    city:str=Field(min_length=2,max_length=90)
    category:str=Field(default="",max_length=80)
class Login(BaseModel):
    email:str;password:str
class Requirement(BaseModel):
    category:str;product:str=Field(min_length=3,max_length=160);quantity:str=Field(min_length=1,max_length=80);city:str=Field(min_length=2,max_length=90);district:str=Field(min_length=2,max_length=90);pin:str=Field(default="",max_length=6);details:str=Field(default="",max_length=1200);target_supplier_id:int|None=None
class GuestRequirement(Requirement):
    name:str=Field(min_length=2,max_length=100)
    phone:str=Field(min_length=7,max_length=20)
class Quote(BaseModel):
    requirement_id:int;amount:float=Field(gt=0,le=10000000000);notes:str=Field(default="",max_length=600)
class Review(BaseModel):
    requirement_id:int
    rating:int=Field(ge=1,le=5)
    comment:str=Field(min_length=2,max_length=800)
class Ad(BaseModel):
    image_base64:str=Field(default="",max_length=2800000)
    image_type:str=Field(default="",max_length=30)
    headline:str=Field(min_length=4,max_length=150);category:str;target_city:str=Field(min_length=2,max_length=90);target_district:str=Field(default="",max_length=90)
class PaymentVerify(BaseModel):
    razorpay_order_id:str
    razorpay_payment_id:str
    razorpay_signature:str
class PublicListingIn(BaseModel):
    name:str=Field(min_length=2,max_length=180)
    phone:str=Field(default="",max_length=30)
    category:str=Field(min_length=2,max_length=80)
    country:str=Field(default="India",min_length=2,max_length=90)
    state_region:str=Field(default="",max_length=100)
    city:str=Field(min_length=2,max_length=90)
    district:str=Field(default="",max_length=90)
    website:str=Field(default="",max_length=300)
    products_services:str=Field(default="",max_length=1000)
    source_name:str=Field(min_length=2,max_length=120)
    source_url:str=Field(min_length=8,max_length=600)
def me(request):
    uid=request.session.get("uid")
    if not uid:raise HTTPException(401,"Please log in")
    with conn() as c:
        u=c.execute("SELECT id,email,phone,name,role,country,state_region,city,district,postal_code,pin,whatsapp,website,company_type,products_services,target_markets,public_contact,category,service_areas,approved,membership_until FROM users WHERE id=%s",(uid,)).fetchone()
    if not u:raise HTTPException(401,"Session expired")
    return dict(u)
def role(request,r):
    u=me(request)
    if u["role"]!=r:raise HTTPException(403,"This action requires "+r+" access")
    return u
def publicuser(u):
    fields=["id","name","role","country","state_region","city","district","postal_code","category","service_areas","website","company_type","products_services","target_markets","approved","review_rating","review_count"]
    out={k:u[k] for k in fields}
    if u.get("public_contact"):
        out["phone"]=u.get("phone","")
        out["whatsapp"]=u.get("whatsapp","")
    return out
def matches(req,supplier):
    if req["category"]!=supplier["category"]:return False
    areas=[supplier["city"],supplier["district"],supplier["pin"]]+[a.strip() for a in supplier["service_areas"].split(",")]
    locs=[req["city"],req["district"],req["pin"]]
    return any(a.strip() and b.strip() and a.casefold().strip()==b.casefold().strip() for a in areas for b in locs)
def supplier_access(u):
    return bool(u["approved"] or u["membership_until"]>int(time.time()))
def requirement_out(row):
    out=dict(row)
    out["enquiry_no"]=f"CTS-REQ-{out['id']:06d}"
    out["source_label"]="Through CTS ConstructConnect"
    return out
@app.get("/")
def index():return FileResponse(BASE/"static"/"index.html",headers={"Cache-Control":"no-cache, no-store, must-revalidate"})
@app.get("/manifest.webmanifest")
def manifest():return FileResponse(BASE/"static"/"manifest.webmanifest",media_type="application/manifest+json")
@app.get("/sw.js")
def sw():return FileResponse(BASE/"static"/"sw.js",media_type="text/javascript",headers={"Cache-Control":"no-cache, no-store, must-revalidate"})
@app.get("/icon.svg")
def icon():return FileResponse(BASE/"static"/"icon.svg",media_type="image/svg+xml")
@app.get("/api/categories")
def categories():return CATS
@app.post("/api/quick-register")
def quick_register(d:QuickRegister):
    if d.role not in ("buyer","supplier","job_seeker","employer"):
        raise HTTPException(400,"Choose supplier, buyer, looking for job, or hiring")
    if d.role=="supplier" and d.category not in CATS:
        raise HTTPException(400,"Choose a supplier category")
    if d.role in ("job_seeker","employer") and d.category not in JOB_ROLES:
        raise HTTPException(400,"Choose a job role")
    phone="".join(ch for ch in d.phone if ch.isdigit())
    if len(phone)<7 or len(phone)>15:
        raise HTTPException(400,"Enter a valid WhatsApp/mobile number")
    email=f"member-{phone}@phone.cts.invalid"
    now=int(time.time())
    with conn() as c:
        existing=c.execute("SELECT id FROM users WHERE phone=%s OR email=%s",(phone,email)).fetchone()
        if existing:
            return {"ok":True,"message":"You are already registered. CTS will contact you shortly.","id":existing["id"]}
        trial_until=now+SUPPLIER_TRIAL_SECONDS if d.role=="supplier" else 0
        stored_category=d.category if d.role in ("supplier","job_seeker","employer") else ""
        approved=1 if d.role in ("buyer","job_seeker","employer") else 0
        cur=c.execute("INSERT INTO users(email,phone,name,role,password_hash,country,state_region,city,district,postal_code,pin,whatsapp,website,company_type,products_services,target_markets,public_contact,category,service_areas,approved,membership_until,created) VALUES(%s,%s,%s,%s,%s,'India','',%s,'','','',%s,'','','','',FALSE,%s,'',%s,%s,%s) RETURNING id",(email,phone,d.name.strip(),d.role,pwdhash(secrets.token_urlsafe(24)),d.city.strip(),phone,stored_category,approved,trial_until,now))
        member_id=cur.fetchone()["id"]
    messages={
        "supplier":"Free registration successful. Suppliers receive 30 days free access to matched CTS enquiries.",
        "buyer":"Buyer registration successful. CTS will contact you shortly.",
        "job_seeker":"Job-seeker registration successful. CTS will contact you when suitable opportunities are available.",
        "employer":"Hiring requirement registered. CTS will contact you to collect the vacancy details."
    }
    return {"ok":True,"id":member_id,"message":messages[d.role]}

@app.post("/api/job-seeker-register")
async def job_seeker_register(
    name:str=Form(...),
    phone:str=Form(...),
    city:str=Form(...),
    category:str=Form(...),
    resume:UploadFile=File(...)
):
    name=name.strip();city=city.strip();category=category.strip()
    if len(name)<2 or len(name)>100: raise HTTPException(400,"Enter your full name")
    if len(city)<2 or len(city)>90: raise HTTPException(400,"Enter your city")
    if category not in JOB_ROLES: raise HTTPException(400,"Choose a job role")
    clean_phone="".join(ch for ch in phone if ch.isdigit())
    if len(clean_phone)<7 or len(clean_phone)>15: raise HTTPException(400,"Enter a valid WhatsApp/mobile number")
    filename=(resume.filename or "").strip()
    ext=Path(filename).suffix.lower()
    allowed_exts={".pdf",".doc",".docx"}
    allowed_types={"application/pdf","application/msword","application/vnd.openxmlformats-officedocument.wordprocessingml.document"}
    if ext not in allowed_exts or resume.content_type not in allowed_types:
        raise HTTPException(400,"Upload résumé as PDF, DOC or DOCX")
    data=await resume.read(5242881)
    if not data: raise HTTPException(400,"The résumé file is empty")
    if len(data)>5242880: raise HTTPException(400,"Résumé must be 5 MB or smaller")
    email=f"member-{clean_phone}@phone.cts.invalid"
    now=int(time.time())
    with conn() as c:
        existing=c.execute("SELECT id,role FROM users WHERE phone=%s OR email=%s ORDER BY id LIMIT 1",(clean_phone,email)).fetchone()
        if existing and existing["role"]!="job_seeker":
            raise HTTPException(409,"This mobile number is already registered in another category. Please contact CTS to update it.")
        if existing:
            member_id=existing["id"]
            c.execute("UPDATE users SET name=%s,city=%s,category=%s,approved=1 WHERE id=%s",(name,city,category,member_id))
        else:
            member_id=c.execute("INSERT INTO users(email,phone,name,role,password_hash,country,state_region,city,district,postal_code,pin,whatsapp,website,company_type,products_services,target_markets,public_contact,category,service_areas,approved,membership_until,created) VALUES(%s,%s,%s,'job_seeker',%s,'India','',%s,'','','',%s,'','','','',FALSE,%s,'',1,0,%s) RETURNING id",(email,clean_phone,name,pwdhash(secrets.token_urlsafe(24)),city,clean_phone,category,now)).fetchone()["id"]
        c.execute("INSERT INTO job_resumes(user_id,filename,content_type,file_data,file_size,created) VALUES(%s,%s,%s,%s,%s,%s) ON CONFLICT(user_id) DO UPDATE SET filename=EXCLUDED.filename,content_type=EXCLUDED.content_type,file_data=EXCLUDED.file_data,file_size=EXCLUDED.file_size,created=EXCLUDED.created",(member_id,filename,resume.content_type,data,len(data),now))
    return {"ok":True,"id":member_id,"message":"Registration and résumé upload completed. CTS will review and send your résumé to suitable companies. If genuine company matches or responses are received, CTS will notify you. The optional ₹100 verified-match access link will be offered only after real matches are recorded."}

@app.get("/api/admin/resumes/{user_id}")
def admin_resume(user_id:int,request:Request):
    role(request,"admin")
    with conn() as c:
        item=c.execute("SELECT filename,content_type,file_data FROM job_resumes WHERE user_id=%s",(user_id,)).fetchone()
    if not item: raise HTTPException(404,"Résumé not found")
    safe_name="".join(ch for ch in item["filename"] if ch.isalnum() or ch in "._- ")[:120] or "resume"
    return Response(bytes(item["file_data"]),media_type=item["content_type"],headers={"Content-Disposition":f'attachment; filename="{safe_name}"',"X-Content-Type-Options":"nosniff","Cache-Control":"private, no-store"})

@app.post("/api/register")
def register(d:Register):
    if d.role not in ("buyer","supplier"):raise HTTPException(400,"Invalid role")
    if d.role=="supplier" and d.category not in CATS:raise HTTPException(400,"Select a supplier category")
    country=d.country.strip()
    postal=(d.postal_code or d.pin).strip()
    if not country:raise HTTPException(400,"Select or enter a country")
    if postal and (len(postal)<3 or len(postal)>20):raise HTTPException(400,"Enter a valid postal / ZIP code")
    phone="".join(ch for ch in d.phone if ch.isdigit())
    whatsapp="".join(ch for ch in d.whatsapp if ch.isdigit())
    if len(phone)<7 or len(phone)>15:raise HTTPException(400,"Enter a valid international phone number with country code")
    if whatsapp and (len(whatsapp)<7 or len(whatsapp)>15):raise HTTPException(400,"Enter a valid WhatsApp number with country code")
    website=d.website.strip()
    if website and not website.lower().startswith(("http://","https://")):website="https://"+website
    with conn() as c:
        try:
            now=int(time.time());trial_until=now+SUPPLIER_TRIAL_SECONDS if d.role=="supplier" else 0
            c.execute("INSERT INTO users(email,phone,name,role,password_hash,country,state_region,city,district,postal_code,pin,whatsapp,website,company_type,products_services,target_markets,public_contact,category,service_areas,approved,membership_until,created) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)",(d.email.strip().lower(),phone,d.name.strip(),d.role,pwdhash(d.password),country,d.state_region.strip(),d.city.strip(),d.district.strip(),postal,postal,whatsapp,website,d.company_type.strip(),d.products_services.strip(),d.target_markets.strip(),d.public_contact,d.category if d.role=="supplier" else "",d.service_areas.strip() if d.role=="supplier" else "",1 if d.role=="buyer" else 0,trial_until,now))
        except psycopg.IntegrityError:raise HTTPException(409,"Email or mobile number already registered")
    return {"ok":True,"message":"Supplier registered with 30 days free access to matched CTS enquiries. Please sign in." if d.role=="supplier" else "Buyer account created successfully. Please sign in to post your requirement."}
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
def suppliers(category:str="",city:str="",country:str="",division:str=""):
    with conn() as c:rows=[dict(r) for r in c.execute("SELECT u.id,u.name,u.role,u.phone,u.country,u.state_region,u.city,u.district,u.postal_code,u.category,u.service_areas,u.whatsapp,u.website,u.company_type,u.products_services,u.target_markets,u.public_contact,u.approved,COALESCE(ROUND(AVG(rv.rating)::numeric,1),0) review_rating,COUNT(rv.id) review_count FROM users u LEFT JOIN reviews rv ON rv.supplier_id=u.id WHERE u.role='supplier' AND u.approved=1 GROUP BY u.id ORDER BY u.id DESC LIMIT 300")]
    allowed=MACHINERY_CATS if division=="machinery" else MATERIAL_CATS if division=="materials" else None
    return [publicuser(r) for r in rows if (not category or r["category"]==category) and (allowed is None or r["category"] in allowed) and (not country or r["country"].casefold()==country.casefold()) and (not city or city.casefold() in " ".join([r["city"],r["district"],r["state_region"],r["country"],r["service_areas"]]).casefold())]
@app.get("/api/public-listings")
def public_listings(category:str="",city:str="",country:str="",division:str=""):
    allowed=MACHINERY_CATS if division=="machinery" else MATERIAL_CATS if division=="materials" else None
    where=[];params=[]
    if category:
        where.append("category=%s");params.append(category)
    elif allowed:
        where.append("category=ANY(%s)");params.append(list(allowed))
    if country:
        where.append("country ILIKE %s");params.append(country)
    if city:
        where.append("CONCAT_WS(' ',city,district,state_region,country) ILIKE %s");params.append("%"+city+"%")
    clause=" WHERE "+" AND ".join(where) if where else ""
    with conn() as c:
        total=c.execute("SELECT COUNT(*) AS count FROM public_listings"+clause,params).fetchone()["count"]
        items=[dict(x) for x in c.execute("SELECT id,name,phone,category,country,state_region,city,district,website,products_services,source_name,source_url,status FROM public_listings"+clause+" ORDER BY id DESC LIMIT 300",params)]
    return {"total":total,"items":items}
@app.post("/api/requirements")
def post_requirement(d:Requirement,request:Request):
    u=role(request,"buyer")
    if d.category not in CATS:raise HTTPException(400,"Invalid category")
    with conn() as c:
        if d.target_supplier_id:
            supplier=c.execute("SELECT id,category FROM users WHERE id=%s AND role='supplier' AND approved=1",(d.target_supplier_id,)).fetchone()
            if not supplier:raise HTTPException(404,"Selected supplier is not available")
            if supplier["category"]!=d.category:raise HTTPException(400,"Requirement category must match the selected supplier")
        cur=c.execute("INSERT INTO requirements(buyer_id,category,product,quantity,city,district,pin,details,target_supplier_id,created) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",(u["id"],d.category,d.product,d.quantity,d.city,d.district,d.pin,d.details,d.target_supplier_id,int(time.time())))
        itemid=cur.fetchone()["id"]
        return {"ok":True,"id":itemid,"enquiry_no":f"CTS-REQ-{itemid:06d}","message":f"Requirement registered as CTS-REQ-{itemid:06d}."}
@app.post("/api/requirements/guest")
def post_guest_requirement(d:GuestRequirement):
    if d.category not in CATS:raise HTTPException(400,"Invalid category")
    phone="".join(ch for ch in d.phone if ch.isdigit())
    if len(phone)<7 or len(phone)>15:raise HTTPException(400,"Enter a valid phone or WhatsApp number with country code")
    now=int(time.time())
    guest_email=f"voice-{phone}@guest.cts.invalid"
    with conn() as c:
        u=c.execute("SELECT id FROM users WHERE phone=%s OR email=%s ORDER BY id LIMIT 1",(phone,guest_email)).fetchone()
        if u:
            buyer_id=u["id"]
        else:
            cur=c.execute("INSERT INTO users(email,phone,name,role,password_hash,country,state_region,city,district,postal_code,pin,whatsapp,website,company_type,products_services,target_markets,public_contact,category,service_areas,approved,created) VALUES(%s,%s,%s,'buyer',%s,'India','',%s,%s,%s,%s,%s,'','','','','','','',1,%s) RETURNING id",(guest_email,phone,d.name.strip(),pwdhash(secrets.token_urlsafe(24)),d.city.strip(),d.district.strip(),d.pin.strip(),d.pin.strip(),phone,now))
            buyer_id=cur.fetchone()["id"]
        if d.target_supplier_id:
            supplier=c.execute("SELECT id,category FROM users WHERE id=%s AND role='supplier' AND approved=1",(d.target_supplier_id,)).fetchone()
            if not supplier:raise HTTPException(404,"Selected supplier is not available")
            if supplier["category"]!=d.category:raise HTTPException(400,"Requirement category must match the selected supplier")
        cur=c.execute("INSERT INTO requirements(buyer_id,category,product,quantity,city,district,pin,details,target_supplier_id,created) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id",(buyer_id,d.category,d.product,d.quantity,d.city,d.district,d.pin,"Voice/guest submission — "+d.details,d.target_supplier_id,now))
        itemid=cur.fetchone()["id"]
    return {"ok":True,"id":itemid,"enquiry_no":f"CTS-REQ-{itemid:06d}","message":f"Requirement registered as CTS-REQ-{itemid:06d} through CTS ConstructConnect."}
@app.get("/api/requirements")
def requirements(request:Request):
    u=me(request)
    with conn() as c:
        rs=[dict(x) for x in c.execute("SELECT r.*,u.name buyer_name FROM requirements r JOIN users u ON u.id=r.buyer_id ORDER BY r.id DESC LIMIT 300")]
    if u["role"]=="buyer":return [requirement_out(r) for r in rs if r["buyer_id"]==u["id"]]
    if u["role"]=="supplier":
        if not supplier_access(u):return []
        return [requirement_out(r) for r in rs if (r.get("target_supplier_id")==u["id"] or (not r.get("target_supplier_id") and matches(r,u)))]
    return [requirement_out(r) for r in rs]
@app.post("/api/quotes")
def post_quote(d:Quote,request:Request):
    u=role(request,"supplier")
    if not supplier_access(u):raise HTTPException(403,"Your free trial has ended. Activate membership to respond to CTS enquiries.")
    with conn() as c:
        r=c.execute("SELECT * FROM requirements WHERE id=%s",(d.requirement_id,)).fetchone()
        if not r:raise HTTPException(404,"Requirement not found")
        if r.get("target_supplier_id") and r["target_supplier_id"]!=u["id"]:raise HTTPException(403,"This enquiry was sent directly to another supplier")
        if not r.get("target_supplier_id") and not matches(dict(r),u):raise HTTPException(403,"Requirement is outside your matching area/category")
        try:
            c.execute("INSERT INTO quotes(requirement_id,supplier_id,amount,notes,created) VALUES(%s,%s,%s,%s,%s)",(d.requirement_id,u["id"],d.amount,d.notes,int(time.time())))
            c.execute("UPDATE requirements SET status='quotation_received' WHERE id=%s AND status IN ('new_requirement','supplier_matched')",(d.requirement_id,))
        except psycopg.IntegrityError:raise HTTPException(409,"You have already quoted for this requirement")
    return {"ok":True,"message":f"Quotation submitted through CTS for CTS-REQ-{d.requirement_id:06d}."}
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
        return [dict(x) for x in c.execute("SELECT q.id,q.supplier_id,q.amount,q.notes,q.created,q.accepted,u.name supplier_name FROM quotes q JOIN users u ON u.id=q.supplier_id WHERE q.requirement_id=%s ORDER BY q.accepted DESC,q.amount",(reqid,))]
@app.post("/api/quotes/{quoteid}/accept")
def accept_quote(quoteid:int,request:Request):
    u=role(request,"buyer")
    with conn() as c:
        q=c.execute("SELECT q.id,q.requirement_id,r.buyer_id FROM quotes q JOIN requirements r ON r.id=q.requirement_id WHERE q.id=%s",(quoteid,)).fetchone()
        if not q:raise HTTPException(404,"Quotation not found")
        if q["buyer_id"]!=u["id"]:raise HTTPException(403,"Not your requirement")
        c.execute("UPDATE quotes SET accepted=CASE WHEN id=%s THEN TRUE ELSE FALSE END WHERE requirement_id=%s",(quoteid,q["requirement_id"]))
        c.execute("UPDATE requirements SET status='order_confirmed' WHERE id=%s",(q["requirement_id"],))
    return {"ok":True,"enquiry_no":f"CTS-REQ-{q['requirement_id']:06d}","message":f"CTS order confirmed for CTS-REQ-{q['requirement_id']:06d}."}
@app.post("/api/reviews")
def create_review(d:Review,request:Request):
    u=role(request,"buyer")
    with conn() as c:
        order=c.execute("SELECT q.supplier_id FROM requirements r JOIN quotes q ON q.requirement_id=r.id AND q.accepted=TRUE WHERE r.id=%s AND r.buyer_id=%s AND r.status='order_confirmed'",(d.requirement_id,u["id"])).fetchone()
        if not order:raise HTTPException(403,"A review can be given only after confirming a supplier quotation")
        try:c.execute("INSERT INTO reviews(requirement_id,buyer_id,supplier_id,rating,comment,created) VALUES(%s,%s,%s,%s,%s,%s)",(d.requirement_id,u["id"],order["supplier_id"],d.rating,d.comment.strip(),int(time.time())))
        except psycopg.IntegrityError:raise HTTPException(409,"You have already reviewed this order")
    return {"ok":True,"message":"Thank you. Your supplier review is now visible."}
@app.get("/api/suppliers/{supplier_id}/reviews")
def supplier_reviews(supplier_id:int):
    with conn() as c:
        return [dict(x) for x in c.execute("SELECT rv.rating,rv.comment,rv.created,u.name buyer_name FROM reviews rv JOIN users u ON u.id=rv.buyer_id WHERE rv.supplier_id=%s ORDER BY rv.id DESC LIMIT 50",(supplier_id,))]
@app.post("/api/ads")
def create_ad(d:Ad,request:Request):
    u=me(request)
    if u["role"] not in ("supplier","admin"):raise HTTPException(403,"This action requires supplier or CTS admin access")
    if d.category not in CATS:raise HTTPException(400,"Invalid category")
    image=None
    if d.image_base64:
        try:image=base64.b64decode(d.image_base64,validate=True)
        except Exception:raise HTTPException(400,"Invalid picture")
        if len(image)>2*1024*1024:raise HTTPException(400,"Picture must be under 2 MB")
        if not ((d.image_type=="image/jpeg" and image[:3]==bytes([255,216,255])) or (d.image_type=="image/png" and image[:8]==bytes([137,80,78,71,13,10,26,10]))):raise HTTPException(400,"Use JPG or PNG")
    supplier_id=u["id"]
    if u["role"]=="admin":
        with conn() as c:
            supplier=c.execute("SELECT id FROM users WHERE role='supplier' AND (LOWER(name) LIKE %s OR LOWER(email)=%s) ORDER BY id LIMIT 1",("%construction therapy%","constructiontherapysolutions@gmail.com")).fetchone()
        if supplier:supplier_id=supplier["id"]
    with conn() as c:c.execute("INSERT INTO ads(supplier_id,headline,category,target_city,target_district,created,image_data,image_type) VALUES(%s,%s,%s,%s,%s,%s,%s,%s)",(supplier_id,d.headline,d.category,d.target_city,d.target_district,int(time.time()),image,d.image_type if image else None))
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
        return {
            "users":[dict(x) for x in c.execute("""
                SELECT id,name,email,phone,whatsapp,role,country,state_region,city,
                       district,postal_code,company_type,products_services,
                       target_markets,category,service_areas,approved,
                       membership_until,created,
                       EXISTS(SELECT 1 FROM job_resumes jr WHERE jr.user_id=users.id) AS has_resume
                FROM users
                ORDER BY id DESC
                LIMIT 1000
            """)],
            "ads":[dict(x) for x in c.execute("SELECT a.id,a.headline,a.target_city,a.approved,u.name supplier_name FROM ads a JOIN users u ON u.id=a.supplier_id ORDER BY a.id DESC LIMIT 300")],
            "counts":{k:c.execute("SELECT COUNT(*) AS count FROM "+table).fetchone()["count"] for k,table in [("users","users"),("public listings","public_listings"),("requirements","requirements"),("quotes","quotes"),("ads","ads")]}
        }
@app.post("/api/admin/public-listings")
def create_public_listing(d:PublicListingIn,request:Request):
    role(request,"admin")
    if d.category not in CATS:raise HTTPException(400,"Select a valid category")
    source=d.source_url.strip()
    if not source.lower().startswith(("http://","https://")):raise HTTPException(400,"Enter the public source URL")
    website=d.website.strip()
    if website and not website.lower().startswith(("http://","https://")):website="https://"+website
    phone="".join(ch for ch in d.phone if ch.isdigit() or ch=='+')
    with conn() as c:
        duplicate=c.execute("SELECT id FROM public_listings WHERE LOWER(name)=LOWER(%s) AND LOWER(city)=LOWER(%s) AND phone=%s",(d.name.strip(),d.city.strip(),phone)).fetchone()
        if duplicate:raise HTTPException(409,"This public business listing already exists")
        item=c.execute("INSERT INTO public_listings(name,phone,category,country,state_region,city,district,website,products_services,source_name,source_url,status,created) VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,'unclaimed',%s) RETURNING id",(d.name.strip(),phone,d.category,d.country.strip(),d.state_region.strip(),d.city.strip(),d.district.strip(),website,d.products_services.strip(),d.source_name.strip(),source,int(time.time()))).fetchone()
    return {"ok":True,"id":item["id"],"message":"Public business listing added as unclaimed"}
@app.post("/api/admin/approve/{kind}/{itemid}")
def approve(kind:str,itemid:int,request:Request):
    role(request,"admin")
    table={"supplier":"users","ad":"ads"}.get(kind)
    if not table:raise HTTPException(400,"Invalid approval type")
    with conn() as c:
        if kind=="supplier":c.execute("UPDATE users SET approved=1 WHERE id=%s AND role='supplier'",(itemid,))
        else:c.execute("UPDATE ads SET approved=1 WHERE id=%s",(itemid,))
    return {"ok":True}

@app.get("/api/ads/{adid}/picture")
def ad_picture(adid:int,request:Request):
    with conn() as c:a=c.execute("SELECT supplier_id,approved,image_data,image_type FROM ads WHERE id=%s",(adid,)).fetchone()
    if not a or not a["image_data"]:raise HTTPException(404,"Picture not found")
    if not a["approved"]:
        u=me(request)
        if u["role"]!="admin" and u["id"]!=a["supplier_id"]:raise HTTPException(403,"Awaiting approval")
    return Response(bytes(a["image_data"]),media_type=a["image_type"],headers={"Cache-Control":"private, no-store","X-Content-Type-Options":"nosniff"})



@app.get("/join",response_class=HTMLResponse)
def quick_join_page():
    options="".join(f'<option value="{x}">{x}</option>' for x in CATS)
    job_options="".join(f'<option value="{x}">{x}</option>' for x in JOB_ROLES)
    return HTMLResponse(f"""<!doctype html><html lang="en"><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Free CTS Registration</title><style>
body{{margin:0;background:#071827;color:#fff;font-family:Arial,sans-serif}}main{{max-width:520px;margin:auto;padding:24px}}.card{{background:#fff;color:#13202b;border-radius:22px;padding:22px;box-shadow:0 18px 55px #0008}}h1{{margin:0 0 8px;color:#ef6c00}}p{{line-height:1.45}}label{{display:block;font-weight:700;margin-top:14px}}input,select,button{{box-sizing:border-box;width:100%;padding:14px;margin-top:6px;border:1px solid #b8c2cc;border-radius:12px;font-size:16px}}button{{background:#ef6c00;color:white;border:0;font-weight:800;margin-top:20px}}.small{{font-size:13px;color:#56616b}}#msg{{font-weight:800;margin-top:16px}}.brand{{text-align:center;margin-bottom:18px}}.free{{display:inline-block;background:#daf5e4;color:#17653a;padding:7px 12px;border-radius:999px;font-weight:800}}</style></head><body><main><div class="brand"><h2>CTS ConstructConnect</h2><span class="free">100% FREE REGISTRATION</span></div><div class="card"><h1>Join in 60 seconds</h1><p>ನಿಮ್ಮ ಭಾಷೆಯಲ್ಲಿ ಮಾತನಾಡಬಹುದು · अपनी भाषा में बोल सकते हैं<br>Buyers, suppliers, job seekers and employers across the construction industry.</p><form id="f"><label>Name / Company</label><input name="name" required minlength="2"><label>WhatsApp / Mobile</label><input name="phone" required inputmode="tel"><label>I am a</label><select name="role" id="role"><option value="supplier">Supplier / Service Provider</option><option value="buyer">Buyer / Contractor</option><option value="job_seeker">Looking for Job</option><option value="employer">Post a Job / Hiring</option></select><label>City</label><input name="city" required><div id="catwrap"><label id="catlabel">Category</label><select name="category" id="category"><option value="">Select category</option>{options}</select></div><div id="resumewrap" style="display:none"><label>Upload Résumé (PDF, DOC or DOCX — max 5 MB)</label><input type="file" name="resume" id="resume" accept=".pdf,.doc,.docx,application/pdf,application/msword,application/vnd.openxmlformats-officedocument.wordprocessingml.document"></div><button>REGISTER FREE</button></form><div id="msg"></div><p class="small">No payment. No password needed. CTS will call to complete your profile. Help: +91 9880137241</p></div></main><script>
const f=document.getElementById('f'),role=document.getElementById('role'),cw=document.getElementById('catwrap'),cat=document.getElementById('category'),catlabel=document.getElementById('catlabel'),rw=document.getElementById('resumewrap'),resume=document.getElementById('resume'),msg=document.getElementById('msg');
const supplierOptions=`<option value="">Select category</option>{options}`;
const jobOptions=`<option value="">Select job role</option>{job_options}`;
function updateRoleFields(){{
  rw.style.display=role.value==='job_seeker'?'block':'none';resume.required=role.value==='job_seeker';
  if(role.value==='buyer'){{cw.style.display='none';cat.innerHTML='<option value=""></option>';return;}}
  cw.style.display='block';
  if(role.value==='supplier'){{catlabel.textContent='Business Category';cat.innerHTML=supplierOptions;}}
  else if(role.value==='job_seeker'){{catlabel.textContent='Job Role / Profession';cat.innerHTML=jobOptions;}}
  else{{catlabel.textContent='Position You Are Hiring For';cat.innerHTML=jobOptions;}}
}}
role.onchange=updateRoleFields;updateRoleFields(); f.onsubmit=async e=>{{e.preventDefault();msg.textContent='Registering...';try{{let r;if(role.value==='job_seeker'){{const fd=new FormData(f);fd.delete('role');r=await fetch('/api/job-seeker-register',{{method:'POST',body:fd}});}}else{{const d=Object.fromEntries(new FormData(f));delete d.resume;r=await fetch('/api/quick-register',{{method:'POST',headers:{{'Content-Type':'application/json'}},body:JSON.stringify(d)}});}}const t=await r.text();let j;try{{j=JSON.parse(t)}}catch{{throw Error('Registration service is temporarily unavailable. Please call CTS: +91 9880137241')}}if(!r.ok)throw Error(j.detail||'Please try again');msg.style.color='#147a3d';msg.textContent='✓ '+j.message;f.reset();updateRoleFields();}}catch(x){{msg.style.color='#b3261e';msg.textContent=x.message;}}}};
</script></body></html>""")

# Keep old bookmarks and shared front-end links working on mobile.
# Unknown API routes still return a proper 404 instead of the app shell.
@app.get("/{full_path:path}", include_in_schema=False)
def frontend_fallback(full_path: str):
    if full_path == "api" or full_path.startswith("api/"):
        raise HTTPException(404, "API endpoint not found")
    return FileResponse(
        BASE/"static"/"index.html",
        headers={"Cache-Control":"no-cache, no-store, must-revalidate"},
    )
