import http from 'k6/http';
import { check, sleep } from 'k6';

// Soaking Test Profile: Target ~500 RPS overall
// This configuration runs forever (or until docker stops it)
export const options = {
  scenarios: {
    // 60% Normal Traffic
    normal_traffic: {
      executor: 'constant-arrival-rate',
      rate: 300,
      timeUnit: '1s',
      duration: '24h',
      preAllocatedVUs: 50,
      maxVUs: 1000,
      exec: 'normal_reqs',
    },
    // 20% Crawlers (Googlebot, Bing)
    crawlers: {
      executor: 'constant-arrival-rate',
      rate: 100,
      timeUnit: '1s',
      duration: '24h',
      preAllocatedVUs: 10,
      maxVUs: 200,
      exec: 'crawler_reqs',
    },
    // 10% Scans / Reconnaissance
    scans: {
      executor: 'constant-arrival-rate',
      rate: 50,
      timeUnit: '1s',
      duration: '24h',
      preAllocatedVUs: 5,
      maxVUs: 100,
      exec: 'scan_reqs',
    },
    // 10% Attacks (SQLi, XSS, Path Traversal)
    attacks: {
      executor: 'constant-arrival-rate',
      rate: 50,
      timeUnit: '1s',
      duration: '24h',
      preAllocatedVUs: 5,
      maxVUs: 100,
      exec: 'attack_reqs',
    },
  },
};

const TARGET_URL = 'http://nginx_router:8080';

export function normal_reqs() {
  const endpoints = ['/', '/about', '/product/123', '/api/users', '/assets/style.css'];
  const url = `${TARGET_URL}${endpoints[Math.floor(Math.random() * endpoints.length)]}`;
  let res = http.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
  check(res, { 'status is 200/404': (r) => r.status === 200 || r.status === 404 });
}

export function crawler_reqs() {
  const url = `${TARGET_URL}/sitemap.xml`;
  let res = http.get(url, { headers: { 'User-Agent': 'Googlebot/2.1 (+http://www.google.com/bot.html)' } });
  check(res, { 'status is 200/404': (r) => r.status === 200 || r.status === 404 });
}

export function scan_reqs() {
  const endpoints = ['/wp-admin', '/.env', '/.git/config', '/phpmyadmin', '/backup.zip'];
  const url = `${TARGET_URL}${endpoints[Math.floor(Math.random() * endpoints.length)]}`;
  let res = http.get(url, { headers: { 'User-Agent': 'python-requests/2.25.1' } });
}

export function attack_reqs() {
  const payloads = [
    "/?id=1' OR 1=1--",
    "/?search=<script>alert(1)</script>",
    "/../../../../etc/passwd",
    "/?cmd=cat%20/etc/passwd",
    "/api/data?q=UNION%20SELECT%20NULL,NULL--"
  ];
  const url = `${TARGET_URL}${payloads[Math.floor(Math.random() * payloads.length)]}`;
  let res = http.get(url, { headers: { 'User-Agent': 'Mozilla/5.0' } });
}
