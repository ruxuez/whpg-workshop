#!/usr/bin/env python3
"""
PGAA Dashboard - Compares Iceberg vs Native WHPG
EDB Postgres AI branded UI — single-file app, no external dashboard.html needed.
Run: python3 pgaa_dashboard_app.py
Access: http://localhost:5000
"""
import psycopg2, time
from flask import Flask, jsonify, Response
app = Flask(__name__)
DB_CONFIG = {'host': 'localhost', 'port': 5432, 'database': 'demo', 'user': 'gpadmin', 'password': ''}
DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>PGAA Analytics Dashboard — EDB Postgres AI</title>
<link href="https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@300;400;500;600;700&family=IBM+Plex+Mono:wght@400;500&display=swap" rel="stylesheet"/>
<style>
:root {
  --teal:        #3DBFBF;
  --teal-dark:   #29A0A0;
  --teal-deeper: #1D8080;
  --teal-light:  #E6F6F6;
  --teal-xlight: #F0FAFA;
  --grad-a:      #4ECDC4;
  --grad-b:      #3DBFBF;
  --grad-c:      #45A89C;
  --charcoal:    #3D3D3D;
  --n50:  #FAFAFA; --n100: #F5F5F5; --n150: #EEEEEE;
  --n200: #E5E5E5; --n300: #CCCCCC; --n500: #8A8A8A;
  --n700: #555555; --n900: #222222;
  --tx:   #222222; --txs: #555555; --txm: #999999;
  --ok:   #27A67A; --ok-l: #E7F6F0;
  --warn: #E8972A; --warn-l: #FEF5E6;
  --err:  #D94040; --err-l: #FDEAEA;
  --surf: #FFFFFF;
  --bdr:  #E2E2E2;
  --sh-s: 0 1px 3px rgba(0,0,0,.06),0 1px 2px rgba(0,0,0,.04);
  --sh-m: 0 4px 14px rgba(0,0,0,.08),0 2px 4px rgba(0,0,0,.04);
  --sh-l: 0 12px 32px rgba(0,0,0,.11),0 4px 8px rgba(0,0,0,.05);
  --r:8px; --rl:12px;
  --font:'IBM Plex Sans',sans-serif;
  --mono:'IBM Plex Mono',monospace;
}
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
html{font-size:15px}
body{font-family:var(--font);background:var(--n100);color:var(--tx);min-height:100vh;line-height:1.55}
/* NAV */
.nav{
  background:#fff;border-bottom:1px solid var(--bdr);
  border-top:3px solid var(--teal);
  height:58px;display:flex;align-items:center;padding:0 28px;gap:0;
  position:sticky;top:0;z-index:100;box-shadow:var(--sh-s);
}
.nav-div{width:1px;height:24px;background:var(--bdr);margin:0 16px}
.nav-title{font-size:13px;font-weight:500;color:var(--txs)}
.nav-sp{flex:1}
.nav-pill{
  display:flex;align-items:center;gap:7px;font-size:12px;color:var(--txs);
  background:var(--n100);border:1px solid var(--bdr);padding:5px 13px;border-radius:20px;
}
.sdot{width:7px;height:7px;border-radius:50%;background:var(--n300);transition:background .3s}
.sdot.on{background:var(--ok);box-shadow:0 0 6px rgba(39,166,122,.5);animation:blink 2.5s infinite}
.sdot.err{background:var(--err)}
@keyframes blink{0%,100%{opacity:1}60%{opacity:.4}}
/* PAGE */
.page{max-width:1340px;margin:0 auto;padding:28px 28px 72px}
.ph{display:flex;align-items:flex-start;justify-content:space-between;gap:20px;margin-bottom:26px}
.ph h1{font-size:21px;font-weight:600;letter-spacing:-.25px}
.ph p{font-size:13.5px;color:var(--txs);margin-top:5px;max-width:560px}
.tags{display:flex;gap:7px;margin-top:11px;flex-wrap:wrap}
.tag{display:inline-flex;align-items:center;gap:5px;font-size:11.5px;font-weight:500;padding:3px 9px;border-radius:20px;border:1px solid}
.t-teal{background:var(--teal-xlight);color:var(--teal-deeper);border-color:rgba(61,191,191,.35)}
.t-grn{background:var(--ok-l);color:#1A7A57;border-color:#A7DFC8}
.t-gray{background:var(--n150);color:var(--n700);border-color:var(--n300)}
/* BUTTONS */
.btn{
  display:inline-flex;align-items:center;gap:7px;
  font-family:var(--font);font-size:13px;font-weight:500;
  padding:8px 16px;border-radius:var(--r);border:1px solid transparent;
  cursor:pointer;transition:all .13s;white-space:nowrap;
}
.bp{background:linear-gradient(135deg,var(--grad-a),var(--grad-c));color:#fff;border-color:var(--teal-dark)}
.bp:hover{filter:brightness(1.08);transform:translateY(-1px);box-shadow:var(--sh-m)}
.bs{background:var(--surf);color:var(--teal-deeper);border-color:var(--teal)}
.bs:hover{background:var(--teal-xlight)}
.bo{background:var(--surf);color:var(--txs);border-color:var(--bdr)}
.bo:hover{border-color:var(--n300);background:var(--n50)}
.btn:disabled{opacity:.5;cursor:not-allowed;transform:none!important;filter:none!important}
.abar{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:24px}
/* STATS */
.stats{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:26px}
@media(max-width:960px){.stats{grid-template-columns:repeat(3,1fr)}}
.sc{
  background:var(--surf);border:1px solid var(--bdr);
  border-top:3px solid var(--teal);border-radius:var(--rl);
  padding:15px 17px;box-shadow:var(--sh-s);
}
.sc-lbl{font-size:10.5px;font-weight:600;text-transform:uppercase;letter-spacing:.7px;color:var(--txm);margin-bottom:7px}
.sc-val{font-size:21px;font-weight:700;font-family:var(--mono);color:var(--tx);letter-spacing:-.5px}
.sc-sub{font-size:11px;color:var(--txm);margin-top:3px}
/* SECTION HEADING */
.sh{display:flex;align-items:center;gap:10px;margin-bottom:16px}
.sh h2{font-size:13.5px;font-weight:600;color:var(--tx);white-space:nowrap}
.shline{flex:1;height:1px;background:var(--bdr)}
/* WINNER */
.winner{
  background:linear-gradient(135deg,#1A5C5C 0%,#1E7070 60%,#236868 100%);
  border-radius:var(--rl);padding:20px 26px;color:#fff;
  display:none;align-items:center;gap:0;flex-wrap:wrap;
  margin-bottom:20px;box-shadow:var(--sh-m);
}
.winner.vis{display:flex}
.wm{padding:0 24px;border-right:1px solid rgba(255,255,255,.15)}
.wm:first-child{padding-left:0}
.wm:last-child{border-right:none}
.wlbl{font-size:10.5px;font-weight:600;letter-spacing:.9px;text-transform:uppercase;opacity:.6;margin-bottom:5px}
.wval{font-size:26px;font-weight:700;font-family:var(--mono);letter-spacing:-1px;line-height:1}
.wsub{font-size:11.5px;opacity:.65;margin-top:4px}
.wchip{
  display:inline-block;background:rgba(255,255,255,.18);
  border:1px solid rgba(255,255,255,.28);border-radius:20px;
  padding:3px 10px;font-size:11px;font-weight:600;letter-spacing:.3px;margin-top:5px;
}
/* BENCH */
.bgrid{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:26px}
@media(max-width:760px){.bgrid{grid-template-columns:1fr}}
.bcard{background:var(--surf);border:1px solid var(--bdr);border-radius:var(--rl);box-shadow:var(--sh-s);overflow:hidden}
.bhead{display:flex;align-items:center;gap:11px;padding:16px 18px;border-bottom:1px solid var(--bdr);background:var(--n50)}
.bicon{width:34px;height:34px;border-radius:8px;display:flex;align-items:center;justify-content:center;flex-shrink:0}
.bi-t{background:var(--teal-xlight)} .bi-g{background:var(--ok-l)}
.bhead h3{font-size:13.5px;font-weight:600;color:var(--tx)}
.bhead p{font-size:11.5px;color:var(--txs);margin-top:1px}
.bbody{padding:4px 18px 16px}
.qt{width:100%;border-collapse:collapse;font-size:12.5px}
.qt th{text-align:left;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;color:var(--txm);padding:10px 0 7px;border-bottom:1px solid var(--bdr)}
.qt td{padding:8px 0;border-bottom:1px solid var(--n150);vertical-align:middle}
.qt tr:last-child td{border-bottom:none}
.qt tfoot td{padding-top:11px;font-size:12px}
.tp{display:inline-block;padding:2px 8px;border-radius:12px;font-family:var(--mono);font-size:11.5px;font-weight:500}
.tf{background:var(--ok-l);color:#1A7A57} .tm{background:var(--warn-l);color:#8A5A10} .ts{background:var(--err-l);color:#A02020} .tn{background:var(--n150);color:var(--n700)}
.bt{height:5px;background:var(--n200);border-radius:3px}
.bf{height:5px;border-radius:3px;transition:width .5s ease}
.bf-t{background:linear-gradient(90deg,var(--grad-a),var(--grad-c))} .bf-g{background:var(--ok)}
/* PILLS */
.pills{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:18px}
.pill{background:var(--surf);border:1px solid var(--bdr);color:var(--txs);font-size:12.5px;font-weight:500;padding:6px 14px;border-radius:20px;cursor:pointer;transition:all .13s}
.pill:hover{border-color:var(--teal);color:var(--teal-deeper)}
.pill.active{background:var(--teal);border-color:var(--teal-dark);color:#fff}
/* RESULT PANEL */
.rp{background:var(--surf);border:1px solid var(--bdr);border-radius:var(--rl);box-shadow:var(--sh-s);overflow:hidden}
.rph{display:flex;align-items:center;justify-content:space-between;padding:14px 18px;border-bottom:1px solid var(--bdr);background:var(--n50);flex-wrap:wrap;gap:10px}
.rpt{font-size:13.5px;font-weight:600;color:var(--tx)}
.rpm{display:flex;align-items:center;gap:14px;flex-wrap:wrap}
.rpmi{font-size:12px;color:var(--txs);display:flex;align-items:center;gap:5px}
.rpmi strong{font-family:var(--mono);font-size:12px;color:var(--tx)}
.spd{font-size:12px;font-weight:600;font-family:var(--mono);padding:3px 10px;border-radius:20px}
.sp+{background:var(--ok-l);color:#1A7A57} .sp-{background:var(--err-l);color:#A02020}
.scols{display:grid;grid-template-columns:1fr 1fr}
@media(max-width:760px){.scols{grid-template-columns:1fr}}
.scol{border-right:1px solid var(--bdr)}
.scol:last-child{border-right:none}
.scolh{display:flex;align-items:center;gap:7px;padding:10px 16px;font-size:12px;font-weight:600;border-bottom:1px solid var(--bdr);color:var(--txs)}
.cd{width:8px;height:8px;border-radius:50%} .cd-t{background:var(--teal)} .cd-g{background:var(--ok)}
.dtw{overflow:auto;max-height:300px}
.dt{width:100%;border-collapse:collapse;font-size:12px}
.dt thead th{background:var(--n50);color:var(--txm);font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.6px;padding:7px 13px;border-bottom:1px solid var(--bdr);position:sticky;top:0;text-align:left;white-space:nowrap}
.dt tbody td{padding:7px 13px;border-bottom:1px solid var(--n150);font-family:var(--mono);white-space:nowrap}
.dt tbody tr:last-child td{border-bottom:none}
.dt tbody tr:hover td{background:var(--teal-xlight)}
.sqlbox{font-family:var(--mono);font-size:11.5px;color:var(--n700);background:#F5FAFA;border-top:1px solid var(--bdr);padding:13px 18px;white-space:pre-wrap;word-break:break-all;max-height:130px;overflow-y:auto;line-height:1.7;display:none}
.sqlbox.open{display:block}
/* MISC */
.empty{text-align:center;padding:44px 24px;color:var(--txm)}
.empty svg{opacity:.22;margin:0 auto 12px;display:block}
.empty p{font-size:13px}
.spin{display:inline-block;width:15px;height:15px;border:2px solid rgba(255,255,255,.3);border-top-color:#fff;border-radius:50%;animation:sp .7s linear infinite}
.spin-t{border-color:rgba(61,191,191,.2);border-top-color:var(--teal)}
@keyframes sp{to{transform:rotate(360deg)}}
.toasts{position:fixed;bottom:22px;right:22px;display:flex;flex-direction:column;gap:8px;z-index:9999}
.toast{background:#1A3A3A;color:#fff;font-size:13px;padding:11px 16px;border-radius:8px;box-shadow:var(--sh-l);max-width:360px;display:flex;align-items:center;gap:9px;animation:tin .2s ease;border-left:3px solid var(--teal)}
.toast.err{border-left-color:var(--err)} .toast.ok{border-left-color:var(--ok)}
@keyframes tin{from{transform:translateX(16px);opacity:0}to{transform:none;opacity:1}}
</style>
</head>
<body>
<nav class="nav">
  <a href="#" style="text-decoration:none;margin-right:18px;display:flex;align-items:baseline;gap:4px">
    <span style="font-size:17px;font-weight:800;letter-spacing:1px;color:#27A67A;font-family:'IBM Plex Sans',sans-serif">EDB</span>
    <span style="font-size:17px;font-weight:700;letter-spacing:.5px;color:#27A67A;font-family:'IBM Plex Sans',sans-serif">WHPG</span>
  </a>
  <div class="nav-div"></div>
  <span class="nav-title">PGAA Analytics Benchmark</span>
  <div class="nav-sp"></div>
  <div class="nav-pill">
    <span class="sdot" id="sdot"></span>
    <span id="stxt">Connecting…</span>
  </div>
</nav>
<div class="page">
  <div class="ph">
    <div>
      <h1>Iceberg vs Native WHPG — Performance Benchmark</h1>
      <p>Live comparison of Apache Iceberg tables via PGAA foreign data wrapper against native WarehousePG MPP AOCO tables across 8 analytical queries.</p>
      <div class="tags">
        <span class="tag t-teal">PGAA / Apache Iceberg</span>
        <span class="tag t-grn">Native WHPG (AOCO)</span>
        <span class="tag t-gray">5 tables · 8 queries</span>
      </div>
    </div>
  </div>
  <div class="stats">
    <div class="sc"><div class="sc-lbl">Customers</div><div class="sc-val" id="st-customers">—</div><div class="sc-sub">rows</div></div>
    <div class="sc"><div class="sc-lbl">Products</div><div class="sc-val" id="st-products">—</div><div class="sc-sub">rows</div></div>
    <div class="sc"><div class="sc-lbl">Orders</div><div class="sc-val" id="st-orders">—</div><div class="sc-sub">rows</div></div>
    <div class="sc"><div class="sc-lbl">Order Items</div><div class="sc-val" id="st-order_items">—</div><div class="sc-sub">rows</div></div>
    <div class="sc"><div class="sc-lbl">Events</div><div class="sc-val" id="st-events">—</div><div class="sc-sub">rows</div></div>
    <div class="sc"><div class="sc-lbl">Queries</div><div class="sc-val">8</div><div class="sc-sub">benchmark queries</div></div>
  </div>
  <div class="abar">
    <button class="btn bp" id="btn-bench" onclick="runParallel()">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"/></svg>
      Run Full Benchmark
    </button>
    <button class="btn bs" onclick="runSerial('iceberg')">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
      Iceberg Sequential
    </button>
    <button class="btn bo" onclick="runSerial('native')">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M5 12h14M12 5l7 7-7 7"/></svg>
      Native Sequential
    </button>
    <button class="btn bo" onclick="loadStats()">
      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15"/></svg>
      Refresh
    </button>
  </div>
  <div class="sh"><h2>Benchmark Results</h2><div class="shline"></div></div>
  <div class="winner" id="winner">
    <div class="wm"><div class="wlbl">Winner</div><div class="wval" id="w-name">—</div><div class="wchip" id="w-chip"></div></div>
    <div class="wm"><div class="wlbl">Native Wall Time</div><div class="wval" id="w-nat">—</div><div class="wsub">parallel</div></div>
    <div class="wm"><div class="wlbl">Iceberg Wall Time</div><div class="wval" id="w-ice">—</div><div class="wsub">parallel</div></div>
    <div class="wm"><div class="wlbl">Speedup</div><div class="wval" id="w-factor">—</div><div class="wsub">faster engine</div></div>
  </div>
  <div class="bgrid">
    <div class="bcard">
      <div class="bhead">
        <div class="bicon bi-g">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--ok)" stroke-width="2"><ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/><path d="M3 12c0 1.66 4.03 3 9 3s9-1.34 9-3"/></svg>
        </div>
        <div><h3>Native WHPG (AOCO)</h3><p>Append-Optimized Column-Oriented (AOCO) tables</p></div>
      </div>
      <div class="bbody">
        <table class="qt">
          <thead><tr><th>Query</th><th>Time</th><th>Rows</th><th style="width:72px">Rel.</th></tr></thead>
          <tbody id="nat-tb"><tr><td colspan="4"><div class="empty" style="padding:20px"><div class="spin spin-t" style="margin:0 auto 8px"></div><p>Awaiting run…</p></div></td></tr></tbody>
          <tfoot id="nat-tf"></tfoot>
        </table>
      </div>
    </div>
    <div class="bcard">
      <div class="bhead">
        <div class="bicon bi-t">
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--teal-dark)" stroke-width="2"><path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5"/></svg>
        </div>
        <div><h3>Apache Iceberg (PGAA)</h3><p>External table via PGAA foreign data wrapper</p></div>
      </div>
      <div class="bbody">
        <table class="qt">
          <thead><tr><th>Query</th><th>Time</th><th>Rows</th><th style="width:72px">Rel.</th></tr></thead>
          <tbody id="ice-tb"><tr><td colspan="4"><div class="empty" style="padding:20px"><div class="spin spin-t" style="margin:0 auto 8px"></div><p>Awaiting run…</p></div></td></tr></tbody>
          <tfoot id="ice-tf"></tfoot>
        </table>
      </div>
    </div>
  </div>
  <div class="sh" style="margin-top:4px"><h2>Query Drill-Down</h2><div class="shline"></div></div>
  <div class="pills" id="pills"></div>
  <div id="cpanel">
    <div class="rp">
      <div class="empty">
        <svg width="38" height="38" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.35-4.35"/></svg>
        <p>Select a query above to compare Iceberg vs Native results side-by-side</p>
      </div>
    </div>
  </div>
</div>
<div class="toasts" id="toasts"></div>
<script>
const fmtMs=ms=>ms<1000?`${Math.round(ms)}ms`:`${(ms/1000).toFixed(2)}s`;
const fmtN=n=>n==null?'—':n>=1e6?`${(n/1e6).toFixed(1)}M`:n>=1e3?`${(n/1e3).toFixed(1)}K`:String(n);
const tcls=ms=>ms<500?'tf':ms<2000?'tm':'ts';
function toast(msg,type='info'){
  const el=document.createElement('div');
  el.className=`toast${type==='error'?' err':type==='success'?' ok':''}`;
  el.textContent=msg;
  document.getElementById('toasts').appendChild(el);
  setTimeout(()=>el.remove(),4200);
}
async function api(url){const r=await fetch(url);if(!r.ok)throw new Error(`HTTP ${r.status}`);return r.json();}
let meta={};
async function init(){
  try{meta=await api('/api/queries');renderPills();}catch(e){toast('Could not load queries: '+e.message,'error');}
  await loadStats();
}
init();
function renderPills(){
  const w=document.getElementById('pills'); w.innerHTML='';
  Object.entries(meta).forEach(([k,v])=>{
    const b=document.createElement('button');
    b.className='pill'; b.textContent=v.name;
    b.onclick=()=>{document.querySelectorAll('.pill').forEach(p=>p.classList.remove('active'));b.classList.add('active');cmp(k,v);};
    w.appendChild(b);
  });
}
async function loadStats(){
  setS('Querying…',null);
  try{
    const d=await api('/api/stats');
    d.rows.forEach(([t,c])=>{const el=document.getElementById(`st-${t}`);if(el)el.textContent=fmtN(c);});
    setS('Connected · WHPG',true);
  }catch(e){setS('DB unavailable',false);}
}
function setS(txt,ok){
  document.getElementById('stxt').textContent=txt;
  const d=document.getElementById('sdot');
  d.className='sdot'+(ok===true?' on':ok===false?' err':'');
}
function renderBench(tbId,tfId,rows,barCls){
  const tb=document.getElementById(tbId),tf=document.getElementById(tfId);
  if(!rows||!rows.length){tb.innerHTML='<tr><td colspan="4" style="padding:16px;color:var(--txm)">No data</td></tr>';return;}
  const mx=Math.max(...rows.map(r=>r.exec_time_ms||0))||1;
  tb.innerHTML=rows.map(r=>{
    const ms=r.exec_time_ms||0,pct=Math.max(4,Math.round(ms/mx*100));
    // r.name is always returned by the API; meta lookup is a bonus
    const nm=r.name||(meta[r.id]&&meta[r.id].name)||r.id||'Query';
    const errCell=r.error?`<td colspan="2" style="color:var(--err);font-size:11px">⚠ ${r.error}</td>`
      :`<td style="font-family:var(--mono);color:var(--txm)">${fmtN(r.row_count)}</td><td><div class="bt"><div class="bf ${barCls}" style="width:${pct}%"></div></div></td>`;
    return `<tr><td>${nm}</td><td><span class="tp ${tcls(ms)}">${fmtMs(ms)}</span></td>${errCell}</tr>`;
  }).join('');
  const tot=rows.reduce((s,r)=>s+(r.exec_time_ms||0),0);
  tf.innerHTML=`<tr><td style="font-weight:600">Total (sum)</td><td colspan="3"><span class="tp tn">${fmtMs(Math.round(tot))}</span></td></tr>`;
}
async function runParallel(){
  const btn=document.getElementById('btn-bench');
  btn.disabled=true; btn.innerHTML='<span class="spin"></span> Running…';
  // ensure meta is loaded before we try to render names
  if(!Object.keys(meta).length){
    try{meta=await api('/api/queries');renderPills();}catch(e){}
  }
  ['nat-tb','ice-tb'].forEach(id=>{document.getElementById(id).innerHTML=`<tr><td colspan="4"><div class="empty" style="padding:20px"><div class="spin spin-t" style="margin:0 auto 8px"></div><p>Executing…</p></div></td></tr>`;});
  toast('Running all queries on both engines in parallel…');
  try{
    const d=await api('/api/run_parallel');
    console.log('run_parallel response:', JSON.stringify(d).slice(0,200));
    if(!d||!d.native||!d.iceberg){throw new Error('Unexpected response shape: '+JSON.stringify(d));}
    renderBench('nat-tb','nat-tf',d.native.queries,'bf-g');
    renderBench('ice-tb','ice-tf',d.iceberg.queries,'bf-t');
    const iw=d.iceberg.wall_time_ms,nw=d.native.wall_time_ms;
    const nf=nw<iw,f=(nf?iw/nw:nw/iw).toFixed(2);
    const wn=nf?'Native AOCO':'Iceberg (PGAA)';
    document.getElementById('w-name').textContent=wn;
    document.getElementById('w-chip').textContent=nf?'AOCO wins':'PGAA wins';
    document.getElementById('w-nat').textContent=fmtMs(nw);
    document.getElementById('w-ice').textContent=fmtMs(iw);
    document.getElementById('w-factor').textContent=`${f}×`;
    document.getElementById('winner').classList.add('vis');
    toast(`Benchmark complete — ${wn} faster by ${f}×`,'success');
  }catch(e){
    console.error('runParallel error:',e);
    toast('Benchmark failed: '+e.message,'error');
    ['nat-tb','ice-tb'].forEach(id=>{document.getElementById(id).innerHTML=`<tr><td colspan="4" style="padding:16px;color:var(--err);font-size:12px">⚠ ${e.message}</td></tr>`;});
  }
  btn.disabled=false;
  btn.innerHTML='<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5"><polygon points="5 3 19 12 5 21 5 3"/></svg> Run Full Benchmark';
}
async function runSerial(mode){
  toast(`Running all queries on ${mode} (sequential)…`);
  try{
    const d=await api(`/api/run_all/${mode}`);
    const it=mode==='iceberg';
    renderBench(it?'ice-tb':'nat-tb',it?'ice-tf':'nat-tf',d.queries,it?'bf-t':'bf-g');
    toast(`${mode} done in ${fmtMs(d.total_time_ms)}`,'success');
  }catch(e){toast(e.message,'error');}
}
async function cmp(qid,qm){
  const panel=document.getElementById('cpanel');
  panel.innerHTML=`<div class="rp"><div class="empty" style="padding:28px"><div class="spin spin-t" style="margin:0 auto 10px"></div><p>Running comparison…</p></div></div>`;
  try{
    const d=await api(`/api/compare/${qid}`);
    const ice=d.iceberg,nat=d.native;
    const ims=ice.exec_time_ms||0,nms=nat.exec_time_ms||0;
    let spd='';
    if(ims>0&&nms>0){
      const nf=nms<ims,f=(nf?ims/nms:nms/ims).toFixed(2);
      spd=`<span class="spd ${nf?'sp+':'sp-'}">AOCO ${nf?f+'× faster':f+'× slower'}</span>`;
    }
    const mkTbl=res=>{
      if(res.error)return`<div style="padding:16px;color:var(--err);font-size:13px">⚠ ${res.error}</div>`;
      if(!res.rows?.length)return`<div style="padding:16px;color:var(--txm);font-size:13px">No rows returned</div>`;
      return`<div class="dtw"><table class="dt"><thead><tr>${res.columns.map(c=>`<th>${c}</th>`).join('')}</tr></thead><tbody>${res.rows.map(r=>`<tr>${r.map(v=>`<td>${v??'NULL'}</td>`).join('')}</tr>`).join('')}</tbody></table></div>`;
    };
    panel.innerHTML=`<div class="rp">
      <div class="rph">
        <span class="rpt">${d.name}</span>
        <div class="rpm">
          ${spd}
          <div class="rpmi"><span class="cd cd-g"></span>AOCO: <strong>${fmtMs(nms)}</strong></div>
          <div class="rpmi"><span class="cd cd-t"></span>Iceberg: <strong>${fmtMs(ims)}</strong></div>
          <button class="btn bo" style="padding:4px 10px;font-size:11.5px" onclick="var b=this.nextElementSibling;b.classList.toggle('open');this.textContent=b.classList.contains('open')?'SQL ▴':'SQL ▾'">SQL ▾</button>
          <div class="sqlbox">${qm.sql||''}</div>
        </div>
      </div>
      <div class="scols">
        <div class="scol"><div class="scolh"><span class="cd cd-g"></span>Native AOCO — ${fmtMs(nms)} · ${fmtN(nat.row_count)} rows</div>${mkTbl(nat)}</div>
        <div class="scol"><div class="scolh"><span class="cd cd-t"></span>Iceberg (PGAA) — ${fmtMs(ims)} · ${fmtN(ice.row_count)} rows</div>${mkTbl(ice)}</div>
      </div>
    </div>`;
  }catch(e){panel.innerHTML=`<div class="rp"><div class="empty"><p>Error: ${e.message}</p></div></div>`;toast('Compare failed: '+e.message,'error');}
}
</script>
</body>
</html>
"""
def query(sql):
    conn = psycopg2.connect(**DB_CONFIG)
    cur = conn.cursor()
    t0 = time.perf_counter()
    cur.execute(sql)
    rows = cur.fetchall()
    ms = round((time.perf_counter() - t0) * 1000, 2)
    cols = [d[0] for d in cur.description] if cur.description else []
    cur.close(); conn.close()
    return {'columns': cols, 'rows': rows, 'row_count': len(rows), 'exec_time_ms': ms}
# ---------------------------------------------------------------------------
# Iceberg queries
# ---------------------------------------------------------------------------
Q_ICE = {
    'count': (
        'Revenue by Category', 
        """SELECT p.category, 
                  COUNT(DISTINCT oi.order_id) as orders, 
                  SUM(oi.quantity) as units_sold, 
                  ROUND(SUM(oi.quantity * oi.unit_price)::numeric, 2) as revenue 
           FROM products_iceberg p 
           JOIN order_items_iceberg oi ON p.product_id = oi.product_id 
           GROUP BY p.category 
           ORDER BY revenue DESC"""
    ),
    'status': (
        'Orders by Status', 
        """SELECT status, 
                  COUNT(*) as cnt, 
                  ROUND(SUM(total_amount)::numeric, 2) as rev 
           FROM orders_iceberg 
           GROUP BY status 
           ORDER BY rev DESC"""
    ),
    'top20': (
        'Top 20 Customers', 
        """SELECT c.customer_id, 
                  c.first_name || ' ' || c.last_name as full_name, 
                  COUNT(o.order_id) as order_count, 
                  ROUND(SUM(o.total_amount)::numeric, 2) as total_spent 
           FROM customers_iceberg c 
           JOIN orders_iceberg o ON c.customer_id = o.customer_id 
           GROUP BY c.customer_id, full_name 
           ORDER BY total_spent DESC 
           LIMIT 20"""
    ),
    'category': (
        'Revenue by Category', 
        """SELECT p.category, 
                  SUM(oi.quantity) as total_qty, 
                  ROUND(SUM(oi.quantity * oi.unit_price)::numeric, 2) as revenue 
           FROM products_iceberg p 
           JOIN order_items_iceberg oi ON p.product_id = oi.product_id 
           GROUP BY p.category 
           ORDER BY revenue DESC"""
    ),
    'funnel': (
        'Conversion Funnel', 
        """WITH f AS (
             SELECT customer_id, 
                    MAX(CASE WHEN event_type = 'page_view' THEN 1 ELSE 0 END) as v, 
                    MAX(CASE WHEN event_type = 'add_to_cart' THEN 1 ELSE 0 END) as c, 
                    MAX(CASE WHEN event_type = 'purchase' THEN 1 ELSE 0 END) as p 
             FROM events_iceberg 
             GROUP BY customer_id
           ) 
           SELECT SUM(v) as total_views, 
                  SUM(c) as total_carts, 
                  SUM(p) as total_purchases, 
                  ROUND(100.0 * SUM(c) / NULLIF(SUM(v), 0), 2) as cart_rate, 
                  ROUND(100.0 * SUM(p) / NULLIF(SUM(c), 0), 2) as purchase_rate 
           FROM f"""
    ),
    'daily': (
        'Daily Dashboard (5 Tables)', 
        """SELECT o.order_date, 
                  COUNT(DISTINCT o.order_id) as orders, 
                  ROUND(SUM(o.total_amount)::numeric, 2) as revenue, 
                  COUNT(DISTINCT o.customer_id) as customers, 
                  SUM(oi.quantity) as items, 
                  COUNT(*) FILTER (WHERE o.status = 'delivered') as delivered, 
                  COUNT(DISTINCT e.session_id) as sessions 
           FROM orders_iceberg o 
           JOIN order_items_iceberg oi ON o.order_id = oi.order_id 
           JOIN products_iceberg p ON oi.product_id = p.product_id 
           JOIN customers_iceberg c ON o.customer_id = c.customer_id 
           LEFT JOIN events_iceberg e ON c.customer_id = e.customer_id AND e.event_date = o.order_date 
           GROUP BY o.order_date 
           ORDER BY o.order_date DESC 
           LIMIT 30"""
    ),
    'cat_funnel': (
        'Funnel by Category (5 Tables)', 
        """WITH ce AS (
             SELECT customer_id, 
                    COUNT(*) FILTER (WHERE event_type = 'page_view') as v, 
                    COUNT(*) FILTER (WHERE event_type = 'purchase') as p 
             FROM events_iceberg 
             GROUP BY customer_id
           ), 
           cp AS (
             SELECT o.customer_id, 
                    p.category, 
                    SUM(oi.quantity * oi.unit_price) as s 
             FROM orders_iceberg o 
             JOIN order_items_iceberg oi ON o.order_id = oi.order_id 
             JOIN products_iceberg p ON oi.product_id = p.product_id 
             GROUP BY o.customer_id, p.category
           ) 
           SELECT cp.category, 
                  COUNT(DISTINCT c.customer_id) as cust_count, 
                  SUM(ce.v) as views, 
                  SUM(ce.p) as purchases, 
                  ROUND(SUM(cp.s)::numeric, 2) as revenue 
           FROM cp 
           JOIN customers_iceberg c ON cp.customer_id = c.customer_id 
           LEFT JOIN ce ON c.customer_id = ce.customer_id 
           GROUP BY cp.category 
           ORDER BY revenue DESC"""
    ),
    'summary': (
        'Executive Summary', 
        """SELECT 
             (SELECT COUNT(*) FROM customers_iceberg) as total_customers, 
             (SELECT COUNT(*) FROM products_iceberg) as total_products, 
             (SELECT COUNT(*) FROM orders_iceberg) as total_orders, 
             (SELECT ROUND(SUM(total_amount)::numeric, 2) FROM orders_iceberg) as total_revenue, 
             (SELECT COUNT(*) FROM order_items_iceberg) as total_items, 
             (SELECT COUNT(*) FROM events_iceberg) as total_events"""
    ),
}
def to_native(sql):
    return (sql
            .replace('customers_iceberg', 'demo.customers')
            .replace('products_iceberg', 'demo.products')
            .replace('orders_iceberg', 'demo.orders')
            .replace('order_items_iceberg', 'demo.order_items')
            .replace('events_iceberg', 'demo.events'))
# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
@app.route('/')
def index():
    return Response(DASHBOARD_HTML, mimetype='text/html')
@app.route('/api/queries')
def list_queries():
    return jsonify({k: {'name': v[0], 'sql': v[1]} for k, v in Q_ICE.items()})
@app.route('/api/query/<qid>')
def run_iceberg(qid):
    if qid not in Q_ICE:
        return jsonify({'error': 'Not found'}), 404
    name, sql = Q_ICE[qid]
    try:
        return jsonify({'name': name, 'type': 'iceberg', 'result': query(sql)})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/api/query/<qid>/native')
def run_native(qid):
    if qid not in Q_ICE:
        return jsonify({'error': 'Not found'}), 404
    name, sql = Q_ICE[qid]
    try:
        return jsonify({'name': name, 'type': 'native', 'result': query(to_native(sql))})
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/api/compare/<qid>')
def compare(qid):
    if qid not in Q_ICE:
        return jsonify({'error': 'Not found'}), 404
    name, sql = Q_ICE[qid]
    try:
        ice = query(sql)
    except Exception as e:
        ice = {'error': str(e), 'exec_time_ms': 0}
    try:
        nat = query(to_native(sql))
    except Exception as e:
        nat = {'error': str(e), 'exec_time_ms': 0}
    total = round(ice.get('exec_time_ms', 0) + nat.get('exec_time_ms', 0), 2)
    return jsonify({'name': name, 'iceberg': ice, 'native': nat, 'total_time_ms': total})
@app.route('/api/stats')
def stats():
    try:
        return jsonify(query(
            "SELECT 'customers', COUNT(*) FROM customers_iceberg "
            "UNION ALL SELECT 'products', COUNT(*) FROM products_iceberg "
            "UNION ALL SELECT 'orders', COUNT(*) FROM orders_iceberg "
            "UNION ALL SELECT 'order_items', COUNT(*) FROM order_items_iceberg "
            "UNION ALL SELECT 'events', COUNT(*) FROM events_iceberg "
            "ORDER BY 2 DESC"
        ))
    except Exception as e:
        return jsonify({'error': str(e)}), 500
@app.route('/api/run_all/<mode>')
def run_all(mode):
    """Run all queries sequentially. mode: iceberg | native"""
    if mode not in ['iceberg', 'native']:
        return jsonify({'error': 'Invalid mode'}), 400
    results = []
    total_time = 0
    for qid, (name, sql) in Q_ICE.items():
        try:
            r = query(to_native(sql) if mode == 'native' else sql)
            results.append({'id': qid, 'name': name, 'exec_time_ms': r['exec_time_ms'], 'row_count': r['row_count']})
            total_time += r['exec_time_ms']
        except Exception as e:
            results.append({'id': qid, 'name': name, 'error': str(e), 'exec_time_ms': 0})
    return jsonify({'mode': mode, 'queries': results, 'total_time_ms': round(total_time, 2), 'query_count': len(results)})
@app.route('/api/run_parallel')
def run_parallel():
    """Run all queries: first all AOCO in parallel, then all Iceberg in parallel.
    Uses a capped thread pool (max 4) to avoid exhausting WHPG connection limits.
    Each thread opens its own psycopg2 connection (thread-safe).
    """
    import concurrent.futures
    MAX_WORKERS = 4  # cap to avoid connection exhaustion on WHPG
    def run_one(qid, name, sql, mode):
        try:
            r = query(to_native(sql) if mode == 'native' else sql)
            return {'id': qid, 'name': name, 'exec_time_ms': r['exec_time_ms'], 'row_count': r['row_count']}
        except Exception as e:
            return {'id': qid, 'name': name, 'error': str(e), 'exec_time_ms': 0}
    order = list(Q_ICE.keys())
    def run_batch(mode):
        items = [(qid, name, sql) for qid, (name, sql) in Q_ICE.items()]
        t0 = time.perf_counter()
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futs = {ex.submit(run_one, qid, name, sql, mode): qid
                    for qid, name, sql in items}
            res = [f.result() for f in concurrent.futures.as_completed(futs)]
        wall = round((time.perf_counter() - t0) * 1000, 2)
        res.sort(key=lambda x: order.index(x['id']))
        return res, wall
    nat_res, nat_wall = run_batch('native')
    ice_res, ice_wall = run_batch('iceberg')
    return jsonify({
        'native':  {'queries': nat_res, 'wall_time_ms': nat_wall,
                    'sum_query_times_ms': round(sum(r['exec_time_ms'] for r in nat_res), 2),
                    'query_count': len(nat_res)},
        'iceberg': {'queries': ice_res, 'wall_time_ms': ice_wall,
                    'sum_query_times_ms': round(sum(r['exec_time_ms'] for r in ice_res), 2),
                    'query_count': len(ice_res)},
        'total_wall_time_ms': round(nat_wall + ice_wall, 2),
    })
if __name__ == '__main__':
    print('\n  EDB PGAA Dashboard: http://localhost:5000\n')
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)

