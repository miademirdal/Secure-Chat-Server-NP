const https = require('https');
const fs = require('fs');
const express = require('express');
const app = express();

// Read the SSL certificate and key files
const options = {
  key: fs.readFileSync('Server/localhost.key'),    // Path to your private key
  cert: fs.readFileSync('Server/server.crt')   // Path to your certificate
};

// Define a simple route
app.get('/', (req, res) => {
    res.send('Hello, HTTPS world!');
});

// Create HTTPS server and listen on port 443
https.createServer(options, app).listen(443, () => {
    console.log('Server is running on https://localhost');
});

// Optional: if you want to redirect HTTP (port 80) to HTTPS
const http = require('http');
http.createServer((req, res) => {
    res.writeHead(301, { 'Location': 'https://' + req.headers['host'] + req.url });
    res.end();
}).listen(80);
