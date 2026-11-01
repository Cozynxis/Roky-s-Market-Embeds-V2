import json, os, re, secrets, sqlite3, time
from pathlib import Path
from urllib.parse import urlencode
import httpx
from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from itsdangerous import URLSafeTimedSerializer, BadSignature
from pydantic import BaseModel, Field

load_dotenv()
CLIENT_ID=os.getenv("DISCORD_CLIENT_ID","")
CLIENT_SECRET=os.getenv("DISCORD_CLIENT_SECRET","")
BOT_TOKEN=os.getenv("DISCORD_BOT_TOKEN","")
SECRET=os.getenv("SESSION_SECRET","")
FRONTEND=os.getenv("FRONTEND_URL","http://localhost:5173").rstrip("/")
BACKEND=os.getenv("BACKEND_URL","http://localhost:8000").rstrip("/")
SECURE=os.getenv("COOKIE_SECURE","true").lower()=="true"
DB=os.getenv("DATABASE_PATH","studio.db")
if len(SECRET)<32: raise RuntimeError("Configure SESSION_SECRET with at least 32 characters")
signer=URLSafeTimedSerializer(SECRET,salt="roky-session")
state_signer=URLSafeTimedSerializer(SECRET,salt="roky-oauth")
app=FastAPI(title="Roky's Market Embed Studio")
app.add_middleware(CORSMiddleware,allow_origins=[FRONTEND],allow_credentials=True,allow_methods=["GET","POST","PATCH","DELETE"],allow_headers=["Content-Type","X-CSRF-Token"])
API="https://discord.com/api/v10"
USERS=Path(__file__).with_name("allowed_users.txt")

def allowed_ids():
    if not USERS.exists(): return set()
    ids=set()
    for line in USERS.read_text(encoding="utf-8").splitlines():
        line=line.split("#",1)[0].strip()
        if not line:continue
        m=re.fullmatch(r"(?:USERID\s*:\s*)?(\d{16,22})",line,re.I)
        if m:ids.add(m.group(1))
    return ids

def database():
    c=sqlite3.connect(DB)
    c.row_factory=sqlite3.Row
    return c
with database() as c:
    c.execute("CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, guild_id TEXT, channel_id TEXT, message_id TEXT, mode TEXT, document TEXT, created_at INTEGER)")
    c.commit()

async def discord(method,path,token=None,body=None):
    auth=("Bearer "+token) if token else ("Bot "+BOT_TOKEN)
    if not token and not BOT_TOKEN:raise HTTPException(503,"Bot token not configured")
    try:
        async with httpx.AsyncClient(timeout=20) as client:
            r=await client.request(method,API+path,headers={"Authorization":auth},json=body)
    except httpx.HTTPError:raise HTTPException(502,"Discord unavailable")
    if r.status_code>=400:
        try:detail=r.json().get("message","Discord rejected request")
        except ValueError:detail="Discord rejected request"
        raise HTTPException(r.status_code,detail)
    return r.json() if r.content else {}

def auth(request:Request,write=False):
    try:u=signer.loads(request.cookies.get("roky_session",""),max_age=7*86400)
    except BadSignature:raise HTTPException(401,"Login required")
    if str(u.get("id")) not in allowed_ids():raise HTTPException(403,"Access denied")
    if write and (request.headers.get("origin")!=FRONTEND or request.headers.get("x-csrf-token")!=u.get("csrf")):
        raise HTTPException(403,"Invalid request security token")
    return u

@app.get("/api/auth/login")
async def login():
    if not CLIENT_ID or not CLIENT_SECRET:raise HTTPException(503,"OAuth not configured")
    state=state_signer.dumps({"nonce":secrets.token_urlsafe(24)})
    q=urlencode({"client_id":CLIENT_ID,"redirect_uri":BACKEND+"/api/auth/callback","response_type":"code","scope":"identify","state":state})
    response=RedirectResponse("https://discord.com/oauth2/authorize?"+q)
    response.set_cookie("roky_oauth",state,max_age=600,httponly=True,secure=SECURE,samesite="lax")
    return response

@app.get("/api/auth/callback")
async def callback(request:Request,code:str,state:str):
    try:state_signer.loads(state,max_age=600)
    except BadSignature:raise HTTPException(400,"Invalid login state")
    if not secrets.compare_digest(request.cookies.get("roky_oauth",""),state):
        raise HTTPException(400,"OAuth state mismatch")
    async with httpx.AsyncClient(timeout=20) as client:
        r=await client.post(API+"/oauth2/token",data={"client_id":CLIENT_ID,"client_secret":CLIENT_SECRET,"grant_type":"authorization_code","code":code,"redirect_uri":BACKEND+"/api/auth/callback"})
    if r.status_code!=200:raise HTTPException(401,"Discord login failed")
    user=await discord("GET","/users/@me",token=r.json()["access_token"])
    if str(user["id"]) not in allowed_ids():return RedirectResponse(FRONTEND+"/?access=denied")
    avatar=user.get("avatar")
    avatar_url=f'https://cdn.discordapp.com/avatars/{user["id"]}/{avatar}.png' if avatar else "https://cdn.discordapp.com/embed/avatars/0.png"
    data={"id":str(user["id"]),"username":user.get("global_name") or user.get("username","Unknown"),"avatar":avatar_url,"csrf":secrets.token_urlsafe(32)}
    response=RedirectResponse(FRONTEND+"/")
    response.set_cookie("roky_session",signer.dumps(data),max_age=7*86400,httponly=True,secure=SECURE,samesite="none" if SECURE else "lax",path="/")
    response.delete_cookie("roky_oauth")
    return response

@app.get("/api/me")
async def me(request:Request):return auth(request)

@app.post("/api/auth/logout")
async def logout(request:Request):
    auth(request,True)
    from fastapi.responses import JSONResponse
    r=JSONResponse({"ok":True})
    r.delete_cookie("roky_session",path="/",secure=SECURE,samesite="none" if SECURE else "lax")
    return r

@app.get("/api/guilds")
async def guilds(request:Request):
    auth(request)
    gs=await discord("GET","/users/@me/guilds")
    return [{"id":g["id"],"name":g["name"]} for g in gs]

@app.get("/api/guilds/{guild_id}/channels")
async def channels(guild_id:str,request:Request):
    auth(request)
    if not guild_id.isdecimal():raise HTTPException(400,"Bad server")
    gs=await discord("GET","/users/@me/guilds")
    if not any(str(g["id"])==guild_id for g in gs):raise HTTPException(403,"Bot is not in this server")
    ch=await discord("GET",f"/guilds/{guild_id}/channels")
    return [{"id":c["id"],"name":c["name"]} for c in ch if c["type"] in (0,5)]

class Document(BaseModel):
    mode:str=Field(pattern="^(embed|components)$")
    title:str=Field(default="",max_length=256)
    description:str=Field(default="",max_length=4000)
    color:str=Field(default="#5865F2",pattern="^#[0-9A-Fa-f]{6}$")
    footer:str=Field(default="",max_length=2048)
    image:str=Field(default="",max_length=2048)
    thumbnail:str=Field(default="",max_length=2048)

class SendBody(BaseModel):
    guild_id:str
    channel_id:str
    document:Document

def build(d:Document):
    for u in (d.image,d.thumbnail):
        if u and not u.startswith("https://"):raise HTTPException(400,"Images must use HTTPS")
    if not (d.title or d.description or d.image):raise HTTPException(400,"Add text or image")
    if d.mode=="embed":
        e={"color":int(d.color[1:],16)}
        if d.title:e["title"]=d.title
        if d.description:e["description"]=d.description
        if d.footer:e["footer"]={"text":d.footer}
        if d.image:e["image"]={"url":d.image}
        if d.thumbnail:e["thumbnail"]={"url":d.thumbnail}
        return {"embeds":[e],"allowed_mentions":{"parse":[]}}
    items=[]
    if d.title:items.append({"type":10,"content":"## "+d.title})
    if d.description:items.append({"type":10,"content":d.description})
    if d.image:items.append({"type":12,"items":[{"media":{"url":d.image}}]})
    return {"flags":32768,"components":[{"type":17,"accent_color":int(d.color[1:],16),"components":items}],"allowed_mentions":{"parse":[]}}

async def verify_channel(guild_id,channel_id):
    if not guild_id.isdecimal() or not channel_id.isdecimal():raise HTTPException(400,"Invalid IDs")
    guild=await discord("GET",f"/guilds/{guild_id}")
    channel=await discord("GET",f"/channels/{channel_id}")
    if str(channel.get("guild_id"))!=str(guild["id"]) or channel["type"] not in (0,5):raise HTTPException(403,"Invalid destination")

@app.post("/api/messages")
async def send(body:SendBody,request:Request):
    auth(request,True)
    await verify_channel(body.guild_id,body.channel_id)
    m=await discord("POST",f"/channels/{body.channel_id}/messages",body=build(body.document))
    with database() as c:
        c.execute("INSERT INTO messages(guild_id,channel_id,message_id,mode,document,created_at) VALUES(?,?,?,?,?,?)",(body.guild_id,body.channel_id,m["id"],body.document.mode,body.document.model_dump_json(),int(time.time())))
        c.commit()
    return {"id":m["id"],"url":f'https://discord.com/channels/{body.guild_id}/{body.channel_id}/{m["id"]}'}

@app.get("/api/messages")
async def history(request:Request):
    auth(request)
    with database() as c: rows=c.execute("SELECT * FROM messages ORDER BY id DESC LIMIT 100").fetchall()
    return [{**dict(r),"document":json.loads(r["document"])} for r in rows]

@app.patch("/api/messages/{record_id}")
async def edit(record_id:int,body:Document,request:Request):
    auth(request,True)
    with database() as c:r=c.execute("SELECT * FROM messages WHERE id=?",(record_id,)).fetchone()
    if r is None:raise HTTPException(404,"Message not found")
    if r["mode"]!=body.mode:raise HTTPException(400,"Message type cannot be changed")
    await verify_channel(r["guild_id"],r["channel_id"])
    await discord("PATCH",f'/channels/{r["channel_id"]}/messages/{r["message_id"]}',body=build(body))
    with database() as c:
        c.execute("UPDATE messages SET document=? WHERE id=?",(body.model_dump_json(),record_id));c.commit()
    return {"ok":True}

@app.delete("/api/messages/{record_id}")
async def delete(record_id:int,request:Request):
    auth(request,True)
    with database() as c:r=c.execute("SELECT * FROM messages WHERE id=?",(record_id,)).fetchone()
    if r is None:raise HTTPException(404,"Message not found")
    await discord("DELETE",f'/channels/{r["channel_id"]}/messages/{r["message_id"]}')
    with database() as c:c.execute("DELETE FROM messages WHERE id=?",(record_id,));c.commit()
    return {"ok":True}
