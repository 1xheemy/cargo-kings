const http = require('http');

const options = {
  hostname: 'localhost',
  port: 3000,
  path: '/admin',
  method: 'GET',
};

const req = http.request(options, (res) => {
  console.log(`status: ${res.statusCode}`);
  let data = '';
  res.on('data', chunk => data += chunk);
  res.on('end', () => {
    if (res.statusCode === 403) {
      console.log('✅ /admin returned 403 as expected');
      process.exit(0);
    } else {
      console.error(`❌ /admin returned ${res.statusCode}`);
      process.exit(2);
    }
  });
});

req.on('error', (e) => {
  console.error('Request failed:', e.message);
  process.exit(1);
});

req.end();
