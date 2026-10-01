// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// No package dependencies. Chromium CDP travels over owned pipes, never a TCP
// debugging listener. This is a browser diagnostic, not agent-browser emulation.
import {spawn} from 'node:child_process';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import path from 'node:path';
import {performance} from 'node:perf_hooks';

const settings = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));
const report = {schema: 1, mode: settings.mode, cases: [], processes: [], unsupported: [
  'agent-browser daemon lifecycle: external dependency is not exercised by this CDP driver',
  'managed Xvnc/noVNC viewer, viewer input arbitration and reconnect: no viewer is launched',
  'TLS interception and production authentication: fixture uses synthetic HTTP only',
  'scanner-only CPU time: use scanner benchmarks separately; request time is not scanner time',
]};
const origin = `http://browser.fixture.example:${settings.port}`;
const proxy = settings.proxy || process.env.HTTP_PROXY;
if (!proxy) throw Error('A mediated proxy route is required');
const pause = ms => new Promise(resolve => setTimeout(resolve, ms));
function check(condition, message) { if (!condition) throw Error(message); }
function ring(text, chunk, max=65536) { return (text+chunk).slice(-max); }
function routeOf(url) {
  try { const u=new URL(url); return u.hostname==='browser.fixture.example' ? u.pathname : 'other-origin'; }
  catch { return 'unknown'; }
}
async function until(fn, timeout=15000) {
  const deadline=performance.now()+timeout;
  while(performance.now()<deadline){
    try{const value=await fn();if(value)return value;}catch(error){
      if(!/Execution context was destroyed|Cannot find context|Cannot find default execution context/.test(error.message))throw error;
    }
    await pause(40);
  }
  throw Error(`condition remained incomplete after ${timeout}ms`);
}
function request(target) {
  return new Promise((resolve,reject)=>{
    const p=new URL(proxy); const start=performance.now();
    const req=http.request({hostname:p.hostname,port:p.port,path:target,method:'GET',headers:{Host:new URL(target).host}},res=>{
      let body='';res.on('data',chunk=>{body=ring(body,chunk.toString(),16384)});
      res.on('end',()=>resolve({status:res.statusCode,elapsed_ms:performance.now()-start,block_reason:res.headers['x-pipelock-block-reason']||null,body}));
      res.on('error',reject);
    });
    req.setTimeout(5000,()=>req.destroy(Error('proxy request timed out')));req.on('error',reject);req.end();
  });
}
async function directProbe() {
  return new Promise(resolve=>{
    const socket=net.connect({host:'127.0.0.1',port:settings.port});
    socket.setTimeout(1500);
    socket.on('connect',()=>{socket.destroy();resolve({outcome:'connected'});});
    socket.on('timeout',()=>{socket.destroy();resolve({outcome:'timeout'});});
    socket.on('error',error=>resolve({outcome:'failed',code:error.code}));
  });
}
class Browser {
  constructor(profile) {
    this.next=1;this.pending=new Map();this.requests=new Map();this.routes=new Map();this.errors=[];this.buffer='';
    this.evidence={stdout_bytes:0,stderr_bytes:0,profile:path.basename(profile)};
    this.logs={stdout:Buffer.alloc(0),stderr:Buffer.alloc(0)};
    this.child=spawn(settings.chromium,['--headless=new','--remote-debugging-pipe',`--user-data-dir=${profile}`,
      `--proxy-server=${proxy}`,'--proxy-bypass-list=<-loopback>','--disable-background-networking',
      '--disable-component-update','--no-first-run','--no-default-browser-check','--window-size=1280,900','about:blank'],
      {stdio:['ignore','pipe','pipe','pipe','pipe']});
    this.exited=false;this.closeObserved=false;this.streamsEnded={stdout:false,stderr:false};
    this.closed=new Promise(resolve=>this.child.once('close',()=>{this.closeObserved=true;resolve();}));
    for(const stream of ['stdout','stderr']){
      this.child[stream].once('end',()=>{this.streamsEnded[stream]=true;});
      this.child[stream].on('error',error=>{this.errors.push(`${stream} read error: ${error.message}`);this.errors=this.errors.slice(-16);});
    }
    this.exit=new Promise(resolve=>{
      this.child.once('exit',(code,signal)=>{this.exited=true;this.evidence.exit_code=code;this.evidence.signal=signal;
        for(const item of this.pending.values()){clearTimeout(item.timer);item.reject(Error('Chromium exited'));}this.pending.clear();resolve();});
      this.child.once('error',error=>{this.exited=true;this.evidence.launch_error=error.message;
        for(const item of this.pending.values()){clearTimeout(item.timer);item.reject(error);}this.pending.clear();resolve();});
    });
    for(const stream of ['stdout','stderr'])this.child[stream].on('data',chunk=>{
      this.evidence[stream+'_bytes']+=chunk.length;this.logs[stream]=Buffer.concat([this.logs[stream],chunk]).subarray(-65536);
    });
    this.child.on('error',error=>{this.evidence.launch_error=error.message;});
    this.child.stdio[4].on('data',chunk=>{
      this.buffer+=chunk.toString();
      if(this.buffer.length>2*1024*1024){this.child.kill('SIGTERM');return;}
      let at;
      while((at=this.buffer.indexOf('\0'))>=0){const raw=this.buffer.slice(0,at);this.buffer=this.buffer.slice(at+1);
        try{this.message(JSON.parse(raw))}catch(error){this.errors.push(error.message);this.errors=this.errors.slice(-16);}}
    });
    this.child.stdio[3].on('error',()=>{});
  }
  message(message) {
    if(message.id){const item=this.pending.get(message.id);if(!item)return;this.pending.delete(message.id);clearTimeout(item.timer);
      if(message.error)item.reject(Error(message.error.message));else item.resolve(message.result);return;}
    const p=message.params||{};
    if(message.method==='Page.frameNavigated'&&!p.frame.parentId)this.mainFrame=p.frame;
    if(message.method==='Network.requestWillBeSent'){
      if(this.requests.size>=256)this.requests.delete(this.requests.keys().next().value);
      this.requests.set(p.requestId,{route:routeOf(p.request.url),phase:this.phase,start:p.timestamp});
    } else if(message.method==='Network.requestServedFromCache'){
      const entry=this.requests.get(p.requestId);if(entry)entry.from_cache=true;
    } else if(message.method==='Network.responseReceived'){
      const entry=this.requests.get(p.requestId);if(entry)Object.assign(entry,{status:p.response.status,
        ttfb_ms:(p.timestamp-entry.start)*1000,from_disk_cache:!!p.response.fromDiskCache,from_service_worker:!!p.response.fromServiceWorker});
    } else if(message.method==='Network.loadingFinished'||message.method==='Network.loadingFailed'){
      const entry=this.requests.get(p.requestId);if(!entry)return;this.requests.delete(p.requestId);
      Object.assign(entry,{duration_ms:(p.timestamp-entry.start)*1000,encoded_bytes:p.encodedDataLength??null,error:p.errorText??null});delete entry.start;
      const key=this.routes.has(entry.route)||this.routes.size<24?entry.route:'other';
      const items=this.routes.get(key)||[];items.push(entry);this.routes.set(key,items.slice(-24));
    } else if(message.method==='Runtime.exceptionThrown'){
      this.errors.push(p.exceptionDetails?.text||'browser exception');this.errors=this.errors.slice(-16);
    }
  }
  call(method,params={},sessionId=this.session) {
    if(this.exited)return Promise.reject(Error('Chromium is not running'));
    const id=this.next++;
    return new Promise((resolve,reject)=>{
      const timer=setTimeout(()=>{this.pending.delete(id);reject(Error(`CDP ${method} timed out`))},12000);
      this.pending.set(id,{resolve,reject,timer});
      this.child.stdio[3].write(JSON.stringify({id,method,params,...(sessionId?{sessionId}:{})})+'\0');
    });
  }
  async init(){
    const target=await this.call('Target.createTarget',{url:'about:blank'},null);
    this.session=(await this.call('Target.attachToTarget',{targetId:target.targetId,flatten:true},null)).sessionId;
    await this.call('Page.enable');await this.call('Network.enable');await this.call('Runtime.enable');
  }
  async evaluate(expression){const r=await this.call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});
    if(r.exceptionDetails)throw Error(r.exceptionDetails.text);return r.result.value;}
  async navigate(route,phase=route){this.phase=phase;await this.evaluate('window.fixture=undefined');const started=performance.now();const result=await this.call('Page.navigate',{url:origin+route});
    check(!result.errorText,result.errorText);
    if(result.loaderId)await until(()=>this.mainFrame?.loaderId===result.loaderId);return started;}
  async state(){return this.evaluate('window.fixture ? JSON.parse(JSON.stringify(window.fixture)) : null');}
  async ready(){return until(async()=>{const value=await this.state();return value?.state==='ready'?value:false;});}
  async click(selector){const box=await this.evaluate(`(()=>{const r=document.querySelector(${JSON.stringify(selector)}).getBoundingClientRect();return {x:r.x+r.width/2,y:r.y+r.height/2}})()`);
    await this.call('Input.dispatchMouseEvent',{type:'mousePressed',...box,button:'left',clickCount:1});
    await this.call('Input.dispatchMouseEvent',{type:'mouseReleased',...box,button:'left',clickCount:1});}
  async type(selector,text){await this.click(selector);await this.call('Input.insertText',{text});}
  async close(){
    if(this.reported)return;
    const wasRunning=!this.exited;let closeError=null;let forced=false;let acknowledged=false;
    try{if(wasRunning){await this.call('Browser.close',{},null);acknowledged=true;}}
    catch(error){closeError=error.message;}
    await Promise.race([this.closed,pause(2000)]);
    if(!this.exited){forced=true;this.child.kill('SIGTERM');await Promise.race([this.closed,pause(1000)]);}
    if(!this.exited){forced=true;this.child.kill('SIGKILL');await Promise.race([this.closed,pause(2000)]);}
    const drained=this.streamsEnded.stdout&&this.streamsEnded.stderr;
    const graceful=wasRunning&&!forced&&this.closeObserved&&drained&&this.evidence.exit_code===0&&
      !this.evidence.signal&&(!closeError||closeError==='Chromium exited');
    for(const item of this.pending.values()){clearTimeout(item.timer);item.reject(Error('browser closed'));}this.pending.clear();
    this.reported=true;
    report.processes.push({...this.evidence,close_acknowledged:acknowledged,close_error:closeError,
      close_observed:this.closeObserved,streams_drained:drained,forced_shutdown:forced,graceful_shutdown:graceful,
      stdout:this.logs.stdout.toString('utf8'),stderr:this.logs.stderr.toString('utf8'),
      retained_bytes:{stdout:this.logs.stdout.length,stderr:this.logs.stderr.length},
      truncated:{stdout:this.evidence.stdout_bytes>this.logs.stdout.length,stderr:this.evidence.stderr_bytes>this.logs.stderr.length},routes:Object.fromEntries(this.routes),browser_errors:this.errors});
    if(!this.closeObserved){
      // Preserve the failed EOF witness; close only our known descriptors so the
      // outer repository supervisor can reap any remaining descendants.
      for(const stream of [this.child.stdout,this.child.stderr,this.child.stdio[3],this.child.stdio[4]])stream.destroy();
    }
  }
}
async function run() {
  report.namespace={net:fs.readlinkSync('/proc/self/ns/net'),user:fs.readlinkSync('/proc/self/ns/user')};
  report.direct_control=await directProbe();
  if(settings.mode==='sandbox'){
    check(report.namespace.net!==settings.parent_net_namespace,'sandbox inherited host network namespace');
    check(report.direct_control.outcome!=='connected','direct own-host endpoint is reachable inside sandbox');
  }
  const positive=await request(origin+'/health');check(positive.status===200,'proxy fixture health failed');
  report.transport_health={status:positive.status,elapsed_ms:positive.elapsed_ms};
  for(const [name,target] of [
    ['forbidden_host',`http://forbidden.fixture.example:${settings.port}/health`],
    ['raw_loopback',`http://127.0.0.1:${settings.port}/health`],
    ['synthetic_canary',origin+'/health?marker='+settings.canary],
    ['synthetic_response_marker',origin+'/response-marker']]){
    const result=await request(target);check(result.status===403,`${name} was not blocked (${result.status})`);
    if(name==='synthetic_canary')check(result.block_reason==='dlp_match'&&result.body.includes('Canary Token (browser-repro)'),'canary block was not attributed to the configured canary');
    if(name==='forbidden_host'||name==='raw_loopback')check(result.body.includes('domain not in allowlist'),'route refusal was not attributed to the strict allowlist');
    if(name==='synthetic_response_marker')check(result.block_reason==='prompt_injection','response block was not attributed to response scanning');
    report.cases.push({name,status:'pass',http_status:result.status,block_reason:result.block_reason,elapsed_ms:result.elapsed_ms});
  }
  let browser=new Browser(settings.profile);
  try{
    await browser.init();await browser.call('Network.clearBrowserCache');
    for(const name of ['cold','warm','reload','delayed']){
      const start=name==='reload'?performance.now():await browser.navigate('/app?scenario='+(name==='delayed'?'delayed':'normal')+'&phase='+name,name);
      if(name==='reload'){browser.phase=name;const oldLoader=browser.mainFrame?.loaderId;await browser.evaluate('window.fixture=undefined');await browser.call('Page.reload',{ignoreCache:false});await until(()=>browser.mainFrame?.loaderId!==oldLoader);}
      await until(async()=>await browser.evaluate('document.readyState')==='complete');
      await browser.ready();
      const readyElapsed=performance.now()-start;
      const state=await until(async()=>{const value=await browser.state();return value?.frames.length>=5?value:false;},3000);
      check(await browser.evaluate("document.getElementById('data').textContent")==='generated data complete','rendered data mismatch');
      const inputStart=performance.now();await browser.click('#count');await until(async()=>(await browser.state())?.count===1);
      await browser.type('#input','synthetic input');
      await browser.call('Input.dispatchKeyEvent',{type:'keyDown',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,nativeVirtualKeyCode:13});
      await browser.call('Input.dispatchKeyEvent',{type:'keyUp',key:'Enter',code:'Enter',windowsVirtualKeyCode:13,nativeVirtualKeyCode:13});
      await until(async()=>{const state=await browser.state();return state?.keys===1&&state?.keyUps===1;});
      check(await browser.evaluate("document.getElementById('input').value")==='synthetic input','input did not arrive');
      const inputElapsed=performance.now()-inputStart;
      const screenshot=await browser.call('Page.captureScreenshot',{format:'png'});
      const png=Buffer.from(screenshot.data,'base64');
      check(png.subarray(0,8).equals(Buffer.from([137,80,78,71,13,10,26,10]))&&png.length>1000,'invalid or empty PNG screenshot');
      const pngWidth=png.readUInt32BE(16),pngHeight=png.readUInt32BE(20);
      check(pngWidth>0&&pngHeight>0,'empty screenshot geometry');
      fs.writeFileSync(path.join(settings.output,`${name}.png`),png,{mode:0o600});
      const bundleRequests=(browser.routes.get('/bundle.js')||[]).filter(item=>item.phase===name);
      const cached=bundleRequests.some(item=>item.from_cache||item.from_disk_cache);
      if(name==='warm')check(cached,'warm navigation did not establish a browser bundle cache hit');
      report.cases.push({name,status:'pass',app_state:state.state,navigation_to_ready_ms:readyElapsed,
        input_roundtrip_ms:inputElapsed,app_ready_ms:state.ready-state.started,
        bundle_cache_hit:cached,screenshot:{width:pngWidth,height:pngHeight,validation:'PNG header and dimensions; inspect pixels separately'},
        dimensions:await browser.evaluate('({innerWidth,innerHeight,screenWidth:screen.width,screenHeight:screen.height,devicePixelRatio})'),
        frame_intervals_ms:state.frames.slice(-60),paint_entries:await browser.evaluate("performance.getEntriesByType('paint').map(({name,startTime})=>({name,startTime}))")});
    }
    for(const scenario of ['error','incomplete','pending']){
      await browser.navigate('/app?scenario='+scenario);
      await until(async()=>!!(await browser.state()));
      if(scenario==='pending'){
        await pause(800);const state=await browser.state();check(state.state==='loading','pending fixture falsely completed');
        report.cases.push({name:scenario,status:'expected_pending',app_state:state.state,observation_ms:800});
      }else{
        const state=await until(async()=>{const value=await browser.state();return value?.state==='error'?value:false;});
        if(scenario==='error')check(state.error==='HTTP 503','error case did not observe intended HTTP 503');
        else check(['Failed to fetch','HTTP 502'].includes(state.error),'incomplete case observed an unrelated error: '+state.error);
        report.cases.push({name:scenario,status:'expected_error',app_state:state.state,error:state.error});
      }
    }
    await browser.navigate('/account');await until(async()=>(await browser.evaluate('location.pathname'))==='/login');
    await browser.type('#user','fixture');await browser.type('#code','fixture-only');await browser.click('#login');await browser.ready();
    check(await browser.evaluate('location.pathname')==='/account','login redirect failed');
    report.cases.push({name:'synthetic_login',status:'pass',app_state:'ready'});
    await browser.evaluate("localStorage.setItem('restart-only-sentinel','synthetic-preserved')");
    await browser.close();browser=new Browser(settings.profile);await browser.init();await browser.navigate('/account');await browser.ready();
    check(await browser.evaluate("localStorage.getItem('restart-only-sentinel')")==='synthetic-preserved','persistent storage lost');
    report.cases.push({name:'profile_restart',status:'pass',app_state:'ready'});
    await browser.call('Network.clearBrowserCookies');await browser.navigate('/account');
    await until(async()=>(await browser.evaluate('location.pathname'))==='/login');
    report.cases.push({name:'cleared_cookie_redirect',status:'pass',app_state:'login_required'});
  }finally{await browser.close();}
}
try{await run();check(report.processes.every(item=>item.browser_errors.length===0&&item.graceful_shutdown),'browser runtime, protocol, shutdown or output-drain failure');report.status='complete';report.assertions='pass';}catch(error){report.status='fail';report.assertions='fail';report.failure=error.message;process.exitCode=1;}
fs.writeFileSync(path.join(settings.output,'browser.json'),JSON.stringify(report,null,2)+'\n',{mode:0o600});
