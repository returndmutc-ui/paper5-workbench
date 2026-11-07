/* Static encrypted resource gateway. Only ciphertext is persisted in CacheStorage. */
const BASE = new URL('./', self.location.href).pathname;
const CACHE = 'paper5-ciphertext-v1';
let key = null, manifest = null, loading = null, requesting = null;
let catalogHash = null, updateHash = null, checkedAt = 0, refreshing = null;
const decode = text => Uint8Array.from(atob(text), c => c.charCodeAt(0));
const mime = {'html':'text/html; charset=utf-8','js':'text/javascript; charset=utf-8','css':'text/css; charset=utf-8','json':'application/json; charset=utf-8','md':'text/plain; charset=utf-8','py':'text/plain; charset=utf-8'};
self.addEventListener('install', event => event.waitUntil(self.skipWaiting()));
self.addEventListener('activate', event => event.waitUntil(self.clients.claim()));
async function decrypt(blob, cryptoKey) {
  const raw = new Uint8Array(blob);
  const clear = await crypto.subtle.decrypt({name:'AES-GCM',iv:raw.slice(0,12)}, cryptoKey, raw.slice(12));
  return new Response(new Blob([clear]).stream().pipeThrough(new DecompressionStream('gzip'))).arrayBuffer();
}
async function cipher(hash) {
  const url = `${BASE}data/${hash}.bin`;
  const cache = await caches.open(CACHE);
  const cached = await cache.match(url);
  if (cached) return cached.arrayBuffer();
  const location = manifest?.packed?.[hash];
  let data;
  if(location) {
    const packUrl=`${BASE}data/${location.pack}.pack`;
    const savedPack=await cache.match(packUrl);
    if(savedPack)data=(await savedPack.arrayBuffer()).slice(location.offset,location.offset+location.length);
    else {
      const response=await fetch(packUrl,{cache:'no-store',headers:{Range:`bytes=${location.offset}-${location.offset+location.length-1}`}});
      if(!response.ok)throw Error('Encrypted pack missing');
      const payload=await response.arrayBuffer();
      if(response.status===206){if(payload.byteLength!==location.length)throw Error('Invalid packed byte range');data=payload;}
      else {
        if(payload.byteLength<location.offset+location.length)throw Error('Truncated encrypted pack');
        await cache.put(packUrl,new Response(payload));data=payload.slice(location.offset,location.offset+location.length);
      }
    }
  } else {
    const response = await fetch(url, {cache:'no-store'});
    if (!response.ok) throw new Error('Encrypted resource missing');
    data = await response.arrayBuffer();
  }
  const digest = [...new Uint8Array(await crypto.subtle.digest('SHA-256', data))].map(x=>x.toString(16).padStart(2,'0')).join('');
  if (digest !== hash) throw Error('Ciphertext digest mismatch');
  await cache.put(url, new Response(data, {headers:{'Content-Type':'application/octet-stream'}}));
  return data;
}
async function initialize(rawKey) {
  const candidate = await crypto.subtle.importKey('raw', decode(rawKey), {name:'AES-GCM'}, false, ['decrypt']);
  const config = await fetch(`${BASE}vault.json?minute=${Math.floor(Date.now()/60000)}`, {cache:'no-store'}).then(r=>r.json());
  const catalog = JSON.parse(new TextDecoder().decode(await decrypt(await cipher(config.catalog), candidate)));
  if (catalog.schema !== 'paper5.encrypted-workbench.v1' || !catalog.entries['index.html']) throw Error('Invalid catalog');
  if(config.update) {
    const update=JSON.parse(new TextDecoder().decode(await decrypt(await cipher(config.update),candidate)));
    if(update.schema !== 'paper5.vault-update.v1')throw Error('Invalid update');
    Object.assign(catalog.entries,update.entries);
  }
  key = candidate; manifest = catalog;
  catalogHash = config.catalog; updateHash = config.update; checkedAt = Date.now();
}
async function refreshCatalog() {
  if (!key || Date.now()-checkedAt < 60000) return;
  if (!refreshing) refreshing = (async()=>{
    const config = await fetch(`${BASE}vault.json?minute=${Math.floor(Date.now()/60000)}`, {cache:'no-store'}).then(r=>{if(!r.ok)throw Error('Catalog unavailable');return r.json();});
    if(config.catalog !== catalogHash) {
      const next = JSON.parse(new TextDecoder().decode(await decrypt(await cipher(config.catalog),key)));
      if(next.schema !== 'paper5.encrypted-workbench.v1' || !next.entries['index.html'])throw Error('Invalid updated catalog');
      manifest=next;catalogHash=config.catalog;updateHash=null;
    }
    if(config.update && config.update !== updateHash) {
      const update=JSON.parse(new TextDecoder().decode(await decrypt(await cipher(config.update),key)));
      if(update.schema !== 'paper5.vault-update.v1')throw Error('Invalid update');
      Object.assign(manifest.entries,update.entries);updateHash=config.update;
    }
    checkedAt=Date.now();
  })().finally(()=>{refreshing=null;});
  await refreshing;
}
self.addEventListener('message', event => {
  if (!event.source?.url?.startsWith(self.location.origin + BASE)) return;
  if (event.data?.type === 'unlock' || event.data?.type === 'provide-key') {
    const task = (async () => {
      try { loading = initialize(event.data.key); await loading; event.ports[0]?.postMessage({ok:true}); }
      catch { event.ports[0]?.postMessage({ok:false}); }
      finally { loading = null; }
    })();
    event.waitUntil(task);
  }
  if (event.data?.type === 'lock') event.waitUntil((async()=>{
    key = null; manifest = null;
    for (const client of await self.clients.matchAll({includeUncontrolled:true})) if(client.url.startsWith(self.location.origin+BASE)) client.postMessage({type:'locked'});
    event.ports[0]?.postMessage({ok:true});
  })());
});
async function ensureKey() {
  if (loading) await loading.catch(()=>{});
  if (key && manifest) return true;
  if (!requesting) requesting = (async()=>{
    const clients = await self.clients.matchAll({type:'window',includeUncontrolled:true});
    for (const client of clients) if(client.url.startsWith(self.location.origin+BASE)) client.postMessage({type:'request-key'});
    for(let i=0;i<25 && !manifest;i++) { await new Promise(r=>setTimeout(r,80)); if(loading) await loading.catch(()=>{}); }
    return !!manifest;
  })().finally(()=>{requesting=null;});
  return requesting;
}
function rewritten(text) {
  // Preserve ordinary relative paths; relocate same-site origin-root links to this project.
  return text.replace(/https?:\/\/117\.72\.204\.61\//g, BASE)
    .replace(/(["'`])\/(?=[A-Za-z0-9_])/g, (all, quote, offset, full) => full.slice(offset+1).startsWith(BASE) ? all : quote+BASE)
    .replace(/((?:href|src|action)\s*=\s*["'])\/(?=["'#?])/gi, '$1'+BASE);
}
function bridge() {
  return `<script>(function(){const k='paper5-vault:${BASE}';navigator.serviceWorker.addEventListener('message',e=>{if(e.data?.type==='request-key'){const s=sessionStorage.getItem(k);if(s)e.source.postMessage({type:'provide-key',key:s})}if(e.data?.type==='locked'){sessionStorage.removeItem(k);location.reload()}});function b(){const el=document.createElement('button');el.textContent='锁定';el.title='锁定加密工作台并清除本次会话密钥';el.style='position:fixed;right:18px;bottom:18px;z-index:2147483647;border:1px solid #cbd5e1;border-radius:7px;background:#fff;color:#203552;padding:8px 14px;cursor:pointer;box-shadow:0 2px 12px #0002';el.onclick=()=>{sessionStorage.removeItem(k);navigator.serviceWorker.controller?.postMessage({type:'lock'});location.reload()};document.body.append(el)}document.readyState==='loading'?document.addEventListener('DOMContentLoaded',b):b()})();</script>`;
}
async function serve(request) {
  const url = new URL(request.url);
  let name = decodeURIComponent(url.pathname.slice(BASE.length));
  if (name === 'sw.js' || name === 'vault-client.js' || name === 'vault.json' || name.startsWith('data/') || name === '.nojekyll' || name === 'README.md') return fetch(request);
  if (!await ensureKey()) {
    if (request.mode === 'navigate') return fetch(`${BASE}index.html`, {cache:'no-store'});
    return new Response('Workbench locked', {status:401,headers:{'Cache-Control':'no-store'}});
  }
  await refreshCatalog();
  if (!name || name.endsWith('/')) name += 'index.html';
  for (const [alias,target] of Object.entries(manifest.aliases)) if(name === alias || name.startsWith(alias+'/')) name = target+name.slice(alias.length);
  if (!manifest.entries[name] && manifest.redirects?.[name]) return Response.redirect(self.location.origin+BASE+manifest.redirects[name]+url.search,302);
  let entry = manifest.entries[name];
  if (!entry && manifest.entries[name+'/index.html']) {
    const redirect = new URL(request.url);redirect.pathname+='/';return Response.redirect(redirect.href,302);
  }
  if (!entry) return new Response('页面或资源不存在', {status:404,headers:{'Content-Type':'text/plain; charset=utf-8','Cache-Control':'no-store'}});
  const activeKey = key;
  const data = await decrypt(await cipher(entry.blob), activeKey);
  const suffix = name.split('.').pop().toLowerCase();
  let body = data;
  if (['html','js','css'].includes(suffix)) {
    body = rewritten(new TextDecoder().decode(data));
    if(suffix === 'html') body = body.replace(/<head(?:\s[^>]*)?>/i, '$&'+bridge());
  }
  return new Response(body, {headers:{'Content-Type':mime[suffix]||entry.mime,'Cache-Control':'no-store','X-Content-Type-Options':'nosniff','Referrer-Policy':'same-origin'}});
}
self.addEventListener('fetch', event => {
  const url = new URL(event.request.url);
  if (url.origin === self.location.origin && url.pathname.startsWith(BASE)) event.respondWith(serve(event.request).catch(()=>new Response('资源解密失败，请重新解锁或刷新。',{status:503,headers:{'Content-Type':'text/plain; charset=utf-8','Cache-Control':'no-store'}})));
});
