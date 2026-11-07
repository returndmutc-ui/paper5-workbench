const base = new URL('./', import.meta.url).pathname;
const storageKey = `paper5-vault:${base}`;
const status = document.getElementById('status');
const button = document.getElementById('submit');
const say = text => { status.textContent = text; };
function call(worker, message) {
  return new Promise((resolve, reject) => {
    const channel = new MessageChannel();
    const timer = setTimeout(() => reject(new Error('初始化超时，请重新加载。')), 60000);
    channel.port1.onmessage = event => { clearTimeout(timer); resolve(event.data); };
    worker.postMessage(message, [channel.port2]);
  });
}
function bytes(base64) { return Uint8Array.from(atob(base64), c => c.charCodeAt(0)); }
function encoded(data) { return btoa(String.fromCharCode(...new Uint8Array(data))); }
async function boot() {
  if (!isSecureContext || !navigator.serviceWorker || !crypto.subtle) throw new Error('请使用支持安全连接的现代浏览器。');
  const registration = await navigator.serviceWorker.register(`${base}sw.js`, {scope: base, updateViaCache: 'none'});
  await navigator.serviceWorker.ready;
  navigator.serviceWorker.addEventListener('message', event => {
    if (event.data?.type === 'request-key') {
      const saved = sessionStorage.getItem(storageKey);
      if (saved) event.source.postMessage({type: 'provide-key', key: saved});
    }
    if (event.data?.type === 'locked') sessionStorage.removeItem(storageKey);
  });
  const config = await fetch(`${base}vault.json?minute=${Math.floor(Date.now()/60000)}`, {cache: 'no-store'}).then(r => { if(!r.ok) throw Error('配置加载失败'); return r.json(); });
  async function unlock(raw) {
    const answer = await call(registration.active, {type: 'unlock', key: encoded(raw)});
    if (!answer.ok) throw new Error('密码不正确，或加密文件未完整加载。');
    sessionStorage.setItem(storageKey, encoded(raw));
    location.replace(location.href);
  }
  document.getElementById('unlock').addEventListener('submit', async event => {
    event.preventDefault(); button.disabled = true; say('正在解锁…');
    try {
      const password = document.getElementById('password').value;
      const material = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
      const raw = await crypto.subtle.deriveBits({name:'PBKDF2',hash:'SHA-256',salt:bytes(config.salt),iterations:config.iterations}, material, 256);
      document.getElementById('password').value = '';
      await unlock(raw);
    } catch (error) { say(error.message); button.disabled = false; }
  });
  const saved = sessionStorage.getItem(storageKey);
  if (saved) {
    button.disabled = true;
    try { await unlock(bytes(saved)); } catch { sessionStorage.removeItem(storageKey); button.disabled = false; }
  }
}
boot().catch(error => {say(error.message);button.disabled=true;});
