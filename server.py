"""FastAPI 入口：URL 输入页 + 报告展示 + 沙箱安全访问 + 举报/审核。

启动: python server.py   （或 uvicorn server:app --port 8000）
"""
from __future__ import annotations

import threading
import uuid
from pathlib import Path

import yaml
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from pipeline import analyze_url, load_config
from sandbox.browse_session import SafeBrowseSession

_ROOT = Path(__file__).parent
cfg = load_config()
_DB_PATH = str(_ROOT / cfg["storage"]["db_path"])
_EVIDENCE_DIR = str(_ROOT / cfg["storage"]["evidence_dir"])

app = FastAPI(title="诈骗网站识别 demo")
app.mount("/static", StaticFiles(directory=str(_ROOT / "static")),
          name="static")


# ==================== 沙箱安全访问会话管理 ====================

class _SessionPool:
    """最多同时 3 个安全浏览会话，超出关闭最旧的。"""

    def __init__(self, max_sessions: int = 3):
        self._lock = threading.Lock()
        self._sessions: dict[str, SafeBrowseSession] = {}
        self._max = max_sessions

    def create(self) -> SafeBrowseSession:
        with self._lock:
            while len(self._sessions) >= self._max:
                oldest = next(iter(self._sessions))
                self._pop(oldest)
            sid = uuid.uuid4().hex[:10]
            sess = SafeBrowseSession(cfg, _EVIDENCE_DIR, session_id=sid)
            sess.start()
            self._sessions[sid] = sess
            return sess

    def get(self, sid: str) -> SafeBrowseSession:
        sess = self._sessions.get(sid)
        if not sess:
            raise HTTPException(status_code=404, detail="会话不存在或已关闭")
        return sess

    def close(self, sid: str) -> None:
        with self._lock:
            self._pop(sid)

    def _pop(self, sid: str) -> None:
        sess = self._sessions.pop(sid, None)
        if sess:
            sess.close()


_pool = _SessionPool()


class AnalyzeReq(BaseModel):
    url: str


class GotoReq(BaseModel):
    url: str


class ClickReq(BaseModel):
    x: float  # 视口比例坐标 0-1
    y: float


class ReportReq(BaseModel):
    url: str
    reason: str = "other"
    description: str = ""
    task_id: str | None = None


class ReviewReq(BaseModel):
    id: int
    approve: bool
    note: str | None = None


@app.get("/", response_class=HTMLResponse)
def index() -> str:
    return """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>诈骗网站识别 demo</title>
<style>
 body{font-family:"Microsoft YaHei",sans-serif;background:#f6f7f9;margin:0;
      display:flex;align-items:center;justify-content:center;min-height:100vh}
 .box{background:#fff;border-radius:12px;padding:40px 44px;max-width:560px;
      box-shadow:0 2px 12px rgba(0,0,0,.08);width:90%}
 h1{font-size:22px;margin:0 0 6px;color:#2c3e50}
 p{color:#7f8c8d;font-size:14px;margin:0 0 22px}
 input{width:100%;padding:12px 14px;border:1px solid #dfe3e7;border-radius:8px;
       font-size:15px;outline:none}
 input:focus{border-color:#5b8def}
 button{margin-top:14px;width:100%;padding:12px;border:0;border-radius:8px;
        background:#c0392b;color:#fff;font-size:15px;font-weight:600;cursor:pointer}
 button:disabled{background:#e0b4b0;cursor:wait}
 #status{margin-top:12px;font-size:13px;color:#7f8c8d;min-height:18px}
</style></head><body>
<div class="box">
 <h1>诈骗网站识别 Demo</h1>
 <p>输入目标 URL，系统将在沙箱中取证并由大模型综合研判（约 1-3 分钟）</p>
 <input id="url" placeholder="https://example.com" onkeydown="if(event.key==='Enter')go()">
 <button id="btn" onclick="go()">开始分析</button>
 <div id="status"></div>
 <p style="margin-top:16px;font-size:12px"><a href="/review" style="color:#5b8def">举报审核 / 诈骗网址库管理 →</a></p>
</div>
<script>
async function go(){
  const btn=document.getElementById('btn'),st=document.getElementById('status');
  const url=document.getElementById('url').value.trim();
  if(!url){st.textContent='请输入 URL';return}
  btn.disabled=true;st.textContent='分析中：预检 → 静态预筛 → 沙箱取证 → AI 研判 …';
  try{
    const r=await fetch('/api/analyze',{method:'POST',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({url})});
    const d=await r.json();
    if(r.ok){st.textContent='完成，正在打开报告…';location.href=d.report_url}
    else{st.textContent='失败: '+(d.detail||d.error||'未知错误')}
  }catch(e){st.textContent='请求异常: '+e}
  btn.disabled=false;
}
</script></body></html>"""


@app.post("/api/analyze")
def api_analyze(req: AnalyzeReq):
    result = analyze_url(req.url, cfg)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["error"])
    rel = Path(result["report_path"]).relative_to(_ROOT / "static" / "reports")
    return {"task_id": result["task_id"],
            "report_url": f"/reports/{rel.as_posix()}"}


@app.get("/reports/{path:path}")
def reports(path: str):
    f = _ROOT / "static" / "reports" / path
    if not f.exists():
        raise HTTPException(status_code=404, detail="报告不存在")
    return FileResponse(f)


@app.get("/api/tasks/{task_id}")
def api_task(task_id: str):
    from storage import db
    t = db.get_task(_DB_PATH, task_id)
    if not t:
        raise HTTPException(status_code=404, detail="任务不存在")
    return t


# ==================== 用户举报 + 审核 + 诈骗库 ====================

@app.post("/api/report")
def api_report(req: ReportReq):
    """提交举报 → 自动预审（规则，不耗 token）→ 通过则直接入库。"""
    from analyze.review import auto_review
    from storage import db
    try:
        from precheck.url_guard import guard
        url, domain, _ = guard(req.url)
    except Exception:  # noqa: BLE001
        url, domain = req.url.strip(), req.url.strip()
    rep = db.submit_report(_DB_PATH, url, domain, req.reason,
                           req.description, req.task_id)
    rep = auto_review(_DB_PATH, cfg, rep["id"])
    return {"id": rep["id"], "status": rep["status"],
            "note": rep["review_note"],
            "message": ("已自动审核通过并写入诈骗网址库"
                        if rep["status"] == "approved"
                        else "已提交，等待人工审核")}


@app.get("/review", response_class=HTMLResponse)
def review_page() -> str:
    return _REVIEW_PAGE


@app.get("/api/reports")
def api_reports(status: str | None = None):
    from storage import db
    return db.list_reports(_DB_PATH, status=status)


@app.post("/api/review")
def api_review(req: ReviewReq):
    """人工审核：approve=true 写入诈骗库。"""
    from analyze.review import manual_review
    try:
        rep = manual_review(_DB_PATH, req.id, req.approve, req.note)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    return rep


@app.get("/api/frauddb")
def api_frauddb():
    from storage import db
    return db.list_fraud_db(_DB_PATH)


# ==================== 沙箱安全访问 ====================

@app.get("/safe", response_class=HTMLResponse)
def safe_page(url: str = ""):
    return _SAFE_PAGE.replace("__INIT_URL__", url)


@app.post("/api/safe/start")
def api_safe_start(req: GotoReq):
    sess = _pool.create()
    result = sess.goto(req.url)
    result["session_id"] = sess.session_id
    return result


@app.get("/api/safe/{sid}/state")
def api_safe_state(sid: str):
    return _pool.get(sid).state()


@app.get("/api/safe/{sid}/shot")
def api_safe_shot(sid: str):
    p = _pool.get(sid).shot_path()
    return FileResponse(p, media_type="image/png")


@app.post("/api/safe/{sid}/goto")
def api_safe_goto(sid: str, req: GotoReq):
    try:
        return _pool.get(sid).goto(req.url)
    except Exception as e:  # noqa: BLE001
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/safe/{sid}/click")
def api_safe_click(sid: str, req: ClickReq):
    return _pool.get(sid).click(req.x, req.y)


@app.post("/api/safe/{sid}/back")
def api_safe_back(sid: str):
    return _pool.get(sid).back()


@app.post("/api/safe/{sid}/refresh")
def api_safe_refresh(sid: str):
    return _pool.get(sid).refresh()


@app.post("/api/safe/{sid}/close")
def api_safe_close(sid: str):
    _pool.close(sid)
    return {"ok": True}


# ==================== 页面模板 ====================

_SAFE_PAGE = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>沙箱安全访问</title>
<style>
 body{font-family:"Microsoft YaHei",sans-serif;background:#f6f7f9;margin:0;padding:20px}
 .top{background:#fff;border-radius:10px;padding:14px 18px;margin-bottom:12px;
      box-shadow:0 1px 4px rgba(0,0,0,.08);display:flex;gap:10px;align-items:center;flex-wrap:wrap}
 input{padding:9px 12px;border:1px solid #dfe3e7;border-radius:8px;font-size:14px}
 #u{flex:1;min-width:280px}
 button{padding:9px 16px;border:0;border-radius:8px;cursor:pointer;font-size:14px;font-weight:600}
 .g{background:#5b8def;color:#fff}.n{background:#eef0f2;color:#2c3e50}
 .r{background:#c0392b;color:#fff}
 #shot{width:100%;max-width:1280px;border:1px solid #dfe3e7;border-radius:8px;cursor:crosshair}
 #meta{font-size:13px;color:#7f8c8d;margin:8px 0}
 #links{background:#fff;border-radius:10px;padding:12px 18px;box-shadow:0 1px 4px rgba(0,0,0,.08);
        font-size:13px;line-height:1.9;max-height:200px;overflow:auto}
 #links a{color:#5b8def;text-decoration:none;margin-right:16px;word-break:break-all}
 #msg{font-size:13px;color:#c0392b;min-height:16px}
</style></head><body>
<div class="top">
  <b>🛡️ 沙箱安全访问</b>
  <input id="u" placeholder="输入要访问的网址">
  <button class="g" onclick="doGoto()">前往</button>
  <button class="n" onclick="doBack()">后退</button>
  <button class="n" onclick="doRefresh()">刷新</button>
  <button class="r" onclick="doReport()">举报此网站</button>
  <button class="n" onclick="doClose()">关闭会话</button>
</div>
<div id="meta">隔离级别: -</div>
<img id="shot" onclick="doClick(event)" alt="沙箱页面截图">
<div id="msg"></div>
<div id="links"></div>
<script>
let sid=null, timer=null;
const $=id=>document.getElementById(id);
async function start(){
  try{
    const r=await fetch('/api/safe/start',{method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({url:'__INIT_URL__'||$('u').value||'https://example.com'})});
    const d=await r.json();
    if(!r.ok){$('msg').textContent='启动失败: '+(d.detail||'');return}
    sid=d.session_id; updateMeta(d); poll();
  }catch(e){$('msg').textContent='启动异常: '+e}
}
function updateMeta(d){
  $('meta').textContent='当前: '+(d.url||'')+'  《'+(d.title||'')+'》  隔离级别: '+(d.isolation||'');
}
async function poll(){
  clearInterval(timer);
  timer=setInterval(async()=>{
    if(!sid)return;
    $('shot').src='/api/safe/'+sid+'/shot?ts='+Date.now();
    try{
      const r=await fetch('/api/safe/'+sid+'/state');
      if(r.ok) updateMeta(await r.json());
      const s=await (await fetch('/api/safe/'+sid+'/state')).json();
      $('links').innerHTML=(s.links||[]).map(l=>
        '<a href="javascript:navGo(\\''+encodeURIComponent(l.href)+'\\')">'+l.text+'</a>').join('');
    }catch(e){}
  },2500);
}
async function navGo(enc){
  const r=await fetch('/api/safe/'+sid+'/goto',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({url:decodeURIComponent(enc)})});
  if(r.ok) updateMeta(await r.json()); else $('msg').textContent=(await r.json()).detail;
}
async function doGoto(){
  if(!sid){start();return}
  const r=await fetch('/api/safe/'+sid+'/goto',{method:'POST',
    headers:{'Content-Type':'application/json'},body:JSON.stringify({url:$('u').value})});
  if(r.ok) updateMeta(await r.json()); else $('msg').textContent=(await r.json()).detail;
}
async function doBack(){
  const r=await fetch('/api/safe/'+sid+'/back',{method:'POST'});
  if(r.ok) updateMeta(await r.json());
}
async function doRefresh(){
  const r=await fetch('/api/safe/'+sid+'/refresh',{method:'POST'});
  if(r.ok) updateMeta(await r.json());
}
async function doClick(ev){
  if(!sid)return;
  const rect=ev.target.getBoundingClientRect();
  const r=await fetch('/api/safe/'+sid+'/click',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({x:(ev.clientX-rect.left)/rect.width,y:(ev.clientY-rect.top)/rect.height})});
  if(r.ok) updateMeta(await r.json());
}
async function doReport(){
  const url=decodeURIComponent(($('meta').textContent.match(/当前: (\\S+)/)||[])[1]||'');
  const reason=prompt('举报类型: phishing=钓鱼仿冒 investment=虚假投资 gambling=赌博 porn=色情违法 other=其他','other');
  if(reason===null)return;
  const desc=prompt('补充描述（可空）','')||'';
  const r=await fetch('/api/report',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({url:url||$('u').value,reason,description:desc})});
  const d=await r.json();
  alert(d.message||d.detail||('状态: '+d.status));
}
async function doClose(){
  clearInterval(timer);
  if(sid) await fetch('/api/safe/'+sid+'/close',{method:'POST'});
  document.body.innerHTML='<p style="text-align:center;margin-top:40px">会话已关闭，隔离环境已销毁。</p>';
}
window.onload=start;
</script></body></html>"""

_REVIEW_PAGE = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>举报审核</title>
<style>
 body{font-family:"Microsoft YaHei",sans-serif;background:#f6f7f9;margin:0;padding:20px}
 .box{background:#fff;border-radius:10px;padding:18px 22px;margin-bottom:14px;
      box-shadow:0 1px 4px rgba(0,0,0,.08)}
 h2{font-size:17px;margin:0 0 10px}
 table{width:100%;border-collapse:collapse;font-size:13px}
 th,td{text-align:left;padding:7px 8px;border-bottom:1px solid #eef0f2;word-break:break-all}
 th{color:#7f8c8d}
 button{padding:5px 12px;border:0;border-radius:6px;cursor:pointer;margin-right:6px;font-size:12px}
 .ok{background:#27ae60;color:#fff}.no{background:#95a5a6;color:#fff}
 .tag{padding:1px 8px;border-radius:4px;font-size:12px}
 .pending{background:#fef5e7;color:#b9770e}.approved{background:#eafaf1;color:#1e8449}
 .rejected{background:#f2f3f4;color:#7f8c8d}
</style></head><body>
<div class="box"><h2>📋 举报审核（人工确认后写入诈骗网址库）</h2>
<table id="t"><tr><th>ID</th><th>网址</th><th>类型</th><th>描述</th><th>状态</th><th>操作</th></tr></table>
</div>
<div class="box"><h2>⛔ 诈骗网址库</h2>
<table id="db"><tr><th>ID</th><th>主域</th><th>URL</th><th>来源</th><th>拦截次数</th></tr></table>
</div>
<script>
const REASON={phishing:'钓鱼仿冒',investment:'虚假投资',gambling:'赌博',porn:'色情违法',other:'其他'};
async function load(){
  const reps=await (await fetch('/api/reports')).json();
  const t=document.getElementById('t');
  t.innerHTML='<tr><th>ID</th><th>网址</th><th>类型</th><th>描述</th><th>状态</th><th>操作</th></tr>'+
    reps.map(r=>`<tr><td>${r.id}</td><td>${r.url}</td><td>${REASON[r.reason]||r.reason}</td>`+
      `<td>${r.description||''}</td><td><span class="tag ${r.status}">${r.status}</span></td>`+
      `<td>${r.status==='pending'?`<button class="ok" onclick="rv(${r.id},true)">确认入库</button>`+
      `<button class="no" onclick="rv(${r.id},false)">驳回</button>`:r.review_note||''}</td></tr>`).join('');
  const rows=await (await fetch('/api/frauddb')).json();
  document.getElementById('db').innerHTML=
    '<tr><th>ID</th><th>主域</th><th>URL</th><th>来源</th><th>拦截次数</th></tr>'+
    rows.map(r=>`<tr><td>${r.id}</td><td>${r.domain}</td><td>${r.url||'(整域拦截)'}</td>`+
      `<td>${r.source==='builtin'?'内置':'用户举报'}</td><td>${r.hit_count}</td></tr>`).join('');
}
async function rv(id,approve){
  const r=await fetch('/api/review',{method:'POST',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify({id,approve,note:approve?'人工确认诈骗':'人工驳回'})});
  if(!r.ok) alert((await r.json()).detail);
  load();
}
load();
</script></body></html>"""


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host=cfg["server"]["host"], port=cfg["server"]["port"])
