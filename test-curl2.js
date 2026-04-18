const https = require('https');
https.get('https://api.github.com/repos/actions/setup-go/releases/latest', { headers: { 'User-Agent': 'node.js' } }, (res) => {
  let data = '';
  res.on('data', (chunk) => data += chunk);
  res.on('end', () => console.log(JSON.parse(data).tag_name));
});
