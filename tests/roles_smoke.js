const http = require('http');
const qs = require('querystring');

function request(opts, body, cb) {
  const req = http.request(opts, (res) => {
    let data = '';
    res.on('data', c => data += c);
    res.on('end', () => cb(null, res, data));
  });
  req.on('error', cb);
  if (body) req.write(body);
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
    for (let i = cookies.length-1; i>=0; i--) if (cookies[i].startsWith(name+'=')) cookies.splice(i,1);
    cookies.push(pair);
  });
  return cookies.join('; ');
}

(async ()=>{
  let cookie;

  // Login as admin and create a supervisor
  let loginToken;
  await new Promise((resolve, reject)=>{
    request({ hostname: 'localhost', port: 3000, path: '/login', method: 'GET' }, null, (err, res, data)=>{
      if (err) return reject(err);
      cookie = mergeCookies(res.headers['set-cookie'], cookie);
      loginToken = extractCsrf(data);
      resolve();
    });
  });

  await new Promise((resolve, reject)=>{
    const body = qs.stringify({ _csrf: loginToken, username: 'admin', password: 'admin123' });
    request({ hostname: 'localhost', port: 3000, path: '/login', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body), Cookie: cookie } }, body, (err, res)=>{
      if (err) return reject(err);
      cookie = mergeCookies(res.headers['set-cookie'], cookie);
      if (res.statusCode !== 302) return reject(new Error('Admin login failed'));
      resolve();
    });
  });

  // GET /admin to obtain csrf for creating supervisor
  let adminToken;
  await new Promise((resolve, reject)=>{
    request({ hostname: 'localhost', port: 3000, path: '/admin', method: 'GET', headers: { Cookie: cookie } }, null, (err, res, data)=>{
      if (err) return reject(err);
      adminToken = extractCsrf(data);
      resolve();
    });
  });

  // create supervisor
  await new Promise((resolve, reject)=>{
    const body = qs.stringify({ _csrf: adminToken, badge: 55555, username: 'sup_smoke', password: 'supass', role: 'supervisor' });
    request({ hostname: 'localhost', port: 3000, path: '/admin/users/add', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body), Cookie: cookie } }, body, (err, res, data)=>{
      if (err) return reject(err);
      if (res.statusCode !== 302) return reject(new Error('Failed to create supervisor'));
      // merge any new cookies
      cookie = mergeCookies(res.headers['set-cookie'], cookie);
      resolve();
    });
  });

  // Login as supervisor
  // GET /login to get token
  let supLoginToken;
  await new Promise((resolve, reject)=>{
    request({ hostname: 'localhost', port: 3000, path: '/login', method: 'GET' }, null, (err, res, data)=>{
      if (err) return reject(err);
      // new cookie set
      resolve(extractCsrf(data));
    });
  }).then(t=>supLoginToken=t);

  const supCookie = await new Promise((resolve, reject)=>{
    const body = qs.stringify({ _csrf: supLoginToken, username: 'sup_smoke', password: 'supass' });
    request({ hostname: 'localhost', port: 3000, path: '/login', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } }, body, (err, res)=>{
      if (err) return reject(err);
      const set = res.headers['set-cookie'];
      if (!set) return reject(new Error('sup login no cookie'));
      resolve(set.join(';'));
    });
  });

  // Supervisor attempts to create executive -> should be denied (flash)
  await new Promise((resolve, reject)=>{
    // GET /admin to get csrf for supervisor
    let supAdminToken;
    request({ hostname: 'localhost', port: 3000, path: '/admin', method: 'GET', headers: { Cookie: supCookie } }, null, (err, res, data)=>{
      if (err) return reject(err);
      supAdminToken = extractCsrf(data);
      const body = qs.stringify({ _csrf: supAdminToken, badge: 55556, username: 'tryexec', password: 'x', role: 'executive' });
      request({ hostname: 'localhost', port: 3000, path: '/admin/users/add', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body), Cookie: supCookie } }, body, (err, res, data)=>{
        if (err) return reject(err);
        // Follow redirect to /admin to read flash
        request({ hostname: 'localhost', port: 3000, path: '/admin', method: 'GET', headers: { Cookie: supCookie } }, null, (err2, res2, data2)=>{
          if (err2) return reject(err2);
          if (data2.includes('Only executives can create executive users') || data2.includes('Insufficient privileges to assign that role')) return resolve();
          console.log('\n--- ADMIN PAGE AFTER SUPERVISOR CREATE EXEC ATTEMPT ---\n');
          console.log(data2);
          console.log('\n--- END ADMIN PAGE ---\n');
          return reject(new Error('Supervisor was able to create/promo exec or no error shown'));
        });
      });
    });
  });

  // Admin creates a manager so we can test manager privileges
  await new Promise((resolve, reject)=>{
    const body = qs.stringify({ _csrf: adminToken, badge: 66666, username: 'mgr_smoke', password: 'mpass', role: 'manager' });
    request({ hostname: 'localhost', port: 3000, path: '/admin/users/add', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body), Cookie: cookie } }, body, (err, res, data)=>{
      if (err) return reject(err);
      if (res.statusCode !== 302) return reject(new Error('Failed to create manager'));
      resolve();
    });
  });

  // Login as manager
  let mgrLoginToken;
  await new Promise((resolve, reject)=>{
    request({ hostname: 'localhost', port: 3000, path: '/login', method: 'GET' }, null, (err, res, data)=>{
      if (err) return reject(err);
      mgrLoginToken = extractCsrf(data);
      resolve();
    });
  });

  const mgrCookie = await new Promise((resolve, reject)=>{
    const body = qs.stringify({ _csrf: mgrLoginToken, username: 'mgr_smoke', password: 'mpass' });
    request({ hostname: 'localhost', port: 3000, path: '/login', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } }, body, (err, res)=>{
      if (err) return reject(err);
      const set = res.headers['set-cookie'];
      if (!set) return reject(new Error('mgr login no cookie'));
      resolve(set.join(';'));
    });
  });

  // Manager should be able to create a supervisor
  await new Promise((resolve, reject)=>{
    let mgrToken;
    request({ hostname: 'localhost', port: 3000, path: '/admin', method: 'GET', headers: { Cookie: mgrCookie } }, null, (err, res, data)=>{
      if (err) return reject(err);
      mgrToken = extractCsrf(data);
      const body = qs.stringify({ _csrf: mgrToken, badge: 77778, username: 'mgr_created_sup', password: 'p', role: 'supervisor' });
      request({ hostname: 'localhost', port: 3000, path: '/admin/users/add', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body), Cookie: mgrCookie } }, body, (err, res, data)=>{
        if (err) return reject(err);
        if (res.statusCode !== 302) return reject(new Error('Manager failed to create supervisor'));
        resolve();
      });
    });
  });

  // Manager attempts to create executive or another manager -> should be denied
  await new Promise((resolve, reject)=>{
    let mgrTok;
    request({ hostname: 'localhost', port: 3000, path: '/admin', method: 'GET', headers: { Cookie: mgrCookie } }, null, (err, res, data)=>{
      if (err) return reject(err);
      mgrTok = extractCsrf(data);
      const body = qs.stringify({ _csrf: mgrTok, badge: 77779, username: 'mgr_try_exec', password: 'p', role: 'executive' });
      request({ hostname: 'localhost', port: 3000, path: '/admin/users/add', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body), Cookie: mgrCookie } }, body, (err, res, data)=>{
        if (err) return reject(err);
        // Attempt to login as the would-be created user - if creation succeeded this will work
        request({ hostname: 'localhost', port: 3000, path: '/login', method: 'GET' }, null, (err2, res2, loginPage)=>{
          if (err2) return reject(err2);
          const token = extractCsrf(loginPage);
          const loginBody = qs.stringify({ _csrf: token, username: 'mgr_try_exec', password: 'p' });
          request({ hostname: 'localhost', port: 3000, path: '/login', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(loginBody) } }, loginBody, (err3, res3)=>{
            if (err3) return reject(err3);
            if (res3.statusCode === 302) return reject(new Error('Manager was able to create/promo exec or no error shown'));
            resolve();
          });
        });
      });
    });
  });

  // Public signup should not be able to sign up as executive
  await new Promise((resolve, reject)=>{
    // GET /signup to get CSRF
    let signupToken;
    request({ hostname: 'localhost', port: 3000, path: '/signup', method: 'GET' }, null, (err, res, data)=>{
      if (err) return reject(err);
      signupToken = extractCsrf(data);
      cookie = mergeCookies(res.headers['set-cookie'], cookie);
      const body = qs.stringify({ _csrf: signupToken, badge: 77777, username: 'public_exec', password: 'p', role: 'executive' });
      request({ hostname: 'localhost', port: 3000, path: '/signup', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body), Cookie: cookie } }, body, (err, res)=>{
        if (err) return reject(err);
        // merge cookies if any
        cookie = mergeCookies(res.headers['set-cookie'], cookie);
        resolve();
      });
    });
  });

  // Login as public_exec and verify they are not admin
  // GET /login to get token
  let pubLoginToken;
  await new Promise((resolve, reject)=>{
    request({ hostname: 'localhost', port: 3000, path: '/login', method: 'GET' }, null, (err, res, data)=>{
      if (err) return reject(err);
      pubLoginToken = extractCsrf(data);
      cookie = mergeCookies(res.headers['set-cookie'], cookie);
      resolve();
    });
  });

  const pubCookie = await new Promise((resolve, reject)=>{
    const body = qs.stringify({ _csrf: pubLoginToken, username: 'public_exec', password: 'p' });
    request({ hostname: 'localhost', port: 3000, path: '/login', method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) } }, body, (err, res, data)=>{
      if (err) return reject(err);
      const set = res.headers['set-cookie'];
      if (!set) return reject(new Error('public login no cookie'));
      resolve(set.join(';'));
    });
  });

  await new Promise((resolve, reject)=>{
    request({ hostname: 'localhost', port: 3000, path: '/admin', method: 'GET', headers: { Cookie: pubCookie } }, null, (err, res, data)=>{
      if (err) return reject(err);
      if (data.includes('Access denied') || data.includes('403')) return resolve();
      return reject(new Error('public_exec seems to have admin access'));
    });
  });

  console.log('✅ Roles smoke test passed');
  process.exit(0);
})().catch(err=>{ console.error('❌ Roles smoke test failed:', err.message); process.exit(2); });