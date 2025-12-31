const http = require('http');
const querystring = require('querystring');

function request(opts, body, cb) {
  const req = http.request(opts, (res) => {
    let data = '';
    res.on('data', chunk => data += chunk);
    res.on('end', () => {
      if (cb) cb(null, res, data);
    });
  });
  req.on('error', cb);
  if (body) {
    req.write(body);
  }
  req.end();
}

function extractCsrf(html) {
  const m = html.match(/name="_csrf" value="([^"]+)"/);
  return m ? m[1] : null;
}

function mergeCookies(setCookies, existing) {
  const cookies = existing ? existing.split(';').map(x=>x.trim()).filter(Boolean) : [];
  (setCookies||[]).forEach(sc=>{
    const pair = sc.split(';')[0].trim();
    const name = pair.split('=')[0];
    // remove existing same name
    for (let i = cookies.length-1; i>=0; i--) if (cookies[i].startsWith(name+'=')) cookies.splice(i,1);
    cookies.push(pair);
  });
  return cookies.join('; ');
}

(async ()=>{
  let cookie;

  // Signup: GET /signup to obtain csrf and cookie
  const username = 'smoketest_' + Date.now();
  let badge = Math.floor(Math.random()*90000) + 10000;
  let signupToken;
  await new Promise((resolve, reject)=>{
    request({ hostname: 'localhost', port: 3000, path: '/signup', method: 'GET' }, null, (err, res, data)=>{
      if (err) return reject(err);
      cookie = mergeCookies(res.headers['set-cookie'], cookie);
      signupToken = extractCsrf(data);
      resolve();
    });
  });

  await new Promise((resolve, reject)=>{
    const body = querystring.stringify({ _csrf: signupToken, badge, username, password: 'pass123', role: 'trucker' });
    request({ hostname: 'localhost', port: 3000, path: '/signup', method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } }, body, (err, res, data)=>{
      if (err) return reject(err);
      cookie = mergeCookies(res.headers['set-cookie'], cookie);
      // success or redirect
      if (res.statusCode !== 302 && res.statusCode !== 200) return reject(new Error('Signup failed: ' + res.statusCode));
      resolve();
    });
  });

  // Login: GET / to get login token
  let loginToken;
  await new Promise((resolve, reject)=>{
    request({ hostname: 'localhost', port: 3000, path: '/', method: 'GET' }, null, (err, res, data)=>{
      if (err) return reject(err);
      cookie = mergeCookies(res.headers['set-cookie'], cookie);
      loginToken = extractCsrf(data);
      resolve();
    });
  });

  // POST /login with token
  await new Promise((resolve, reject)=>{
    const body = querystring.stringify({ _csrf: loginToken, username, password: 'pass123' });
    request({ hostname: 'localhost', port: 3000, path: '/login', method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } }, body, (err, res)=>{
      if (err) return reject(err);
      cookie = mergeCookies(res.headers['set-cookie'], cookie);
      if (res.statusCode !== 302) return reject(new Error('Login failed: ' + res.statusCode));
      resolve();
    });
  });

  // Get dashboard to obtain csrf for log submission
  let dashboardToken;
  await new Promise((resolve, reject)=>{
    request({ hostname: 'localhost', port: 3000, path: '/dashboard', method: 'GET', headers: { Cookie: cookie } }, null, (err, res, data)=>{
      if (err) return reject(err);
      dashboardToken = extractCsrf(data);
      if (!data.includes('Welcome')) return reject(new Error('Dashboard did not load'));
      resolve();
    });
  });

  // Submit a log
  await new Promise((resolve, reject)=>{
    const body = querystring.stringify({ _csrf: dashboardToken, vehicle: 'TESTCAR', hours: 5, damage: 'None', fuel: 50, insurance: 'Active' });
    request({ hostname: 'localhost', port: 3000, path: '/log', method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } }, body, (err, res)=>{
      if (err) return reject(err);
      if (res.statusCode !== 302) return reject(new Error('Log submit failed: ' + res.statusCode));
      resolve();
    });
  });

  // Get dashboard, ensure TESTCAR present and capture log id
  const { logId } = await new Promise((resolve, reject)=>{
    request({ hostname: 'localhost', port: 3000, path: '/dashboard', method: 'GET', headers: { Cookie: cookie } }, null, (err, res, data)=>{
      if (err) return reject(err);
      if (res.statusCode !== 200) {
        console.log('\n--- DASHBOARD RESPONSE DEBUG ---');
        console.log('Status:', res.statusCode);
        console.log('Headers:', JSON.stringify(res.headers));
        console.log('Body:', data);
        console.log('--- END DEBUG ---\n');
        return reject(new Error('/dashboard failed'));
      }
      if (!data.includes('TESTCAR')) return reject(new Error('Log not visible in dashboard'));
      // Find data-id attribute for TESTCAR
      const re = /<li data-id="(\d+)">[\s\S]*?TESTCAR/;
      const m = data.match(re);
      if (!m) return reject(new Error('Could not find log id'));
      resolve({ logId: m[1] });
    });
  });

  // Get CSRF token from dashboard before delete
  await new Promise((resolve, reject)=>{
    request({ hostname: 'localhost', port: 3000, path: '/dashboard', method: 'GET', headers: { Cookie: cookie } }, null, (err, res, data)=>{
      if (err) return reject(err);
      dashboardToken = extractCsrf(data);
      resolve();
    });
  });

  // Delete the log
  await new Promise((resolve, reject)=>{
    const body = querystring.stringify({ _csrf: dashboardToken });
    request({ hostname: 'localhost', port: 3000, path: `/logs/${logId}/delete`, method: 'POST', headers: { Cookie: cookie, 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } }, body, (err, res)=>{
      if (err) return reject(err);
      if (res.statusCode !== 302) return reject(new Error('Delete failed: ' + res.statusCode));
      resolve();
    });
  });

  // Confirm log removed
  await new Promise((resolve, reject)=>{
    request({ hostname: 'localhost', port: 3000, path: '/dashboard', method: 'GET', headers: { Cookie: cookie } }, null, (err, res, data)=>{
      if (err) return reject(err);
      if (data.includes('TESTCAR')) return reject(new Error('Log still present after delete'));
      resolve();
    });
  });

  console.log('✅ Full smoke test passed');
  process.exit(0);
})().catch(err=>{ console.error('❌ Smoke test failed:', err); process.exit(2); });