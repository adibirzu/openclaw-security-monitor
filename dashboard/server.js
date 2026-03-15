#!/usr/bin/env node
'use strict';

// ────────────────────────────────────────────────────────────────────────────
// OpenClaw Security Monitor — Dashboard Server (read-only)
//
// This dashboard is a read-only viewer. It reads scan results from log files
// and displays them in a web UI. It does NOT execute any shell commands,
// child processes, or remediation actions.
//
// To run a scan or remediation, use the CLI scripts directly:
//   ./scripts/scan.sh
//   ./scripts/remediate.sh
// ────────────────────────────────────────────────────────────────────────────

const http = require('http');
const fs = require('fs');
const path = require('path');
const { URL } = require('url');

const PORT = 18800;
const HOST = process.env.DASHBOARD_HOST || '127.0.0.1';
const HOME = process.env.HOME;
const OPENCLAW = path.join(HOME, '.openclaw');
const LOGS = path.join(OPENCLAW, 'logs');
const IOC_DIR = path.resolve(__dirname, '..', 'ioc');
const DASHBOARD_DIR = __dirname;
const startTime = Date.now();

// Security headers
const SEC_HEADERS = {
  'X-Content-Type-Options': 'nosniff',
  'X-Frame-Options': 'DENY',
  'X-XSS-Protection': '1; mode=block',
  'Content-Security-Policy': "default-src 'self' 'unsafe-inline'",
};

function json(res, data, status = 200) {
  res.writeHead(status, { ...SEC_HEADERS, 'Content-Type': 'application/json' });
  res.end(JSON.stringify(data));
}

function readFileSafe(filePath) {
  try {
    return fs.readFileSync(filePath, 'utf-8');
  } catch {
    return null;
  }
}

// ─── Log Parsers ────────────────────────────────────────────────────────────

function parseScanLog(content) {
  const entries = [];
  const scanBlocks = content.split(/OPENCLAW SECURITY SCAN - /);
  for (const block of scanBlocks) {
    const tsMatch = block.match(/^(\d{4}-\d{2}-\d{2}T\S+)/);
    if (!tsMatch) continue;

    const statusMatch = block.match(/STATUS:\s*(\w+)/);
    const summaryMatch = block.match(/SCAN COMPLETE:\s*(\d+)\s*critical,\s*(\d+)\s*warnings?,\s*(\d+)\s*clean/);

    const checks = [];
    let current = null;
    for (const line of block.split('\n')) {
      const checkMatch = line.match(/^\[(\d+)\/(\d+)\]\s+(.+)/);
      if (checkMatch) {
        if (current) checks.push(current);
        current = {
          num: parseInt(checkMatch[1]),
          total: parseInt(checkMatch[2]),
          name: checkMatch[3].replace(/\.\.\.$/, '').trim(),
          status: 'UNKNOWN',
          details: '',
        };
        continue;
      }
      if (current) {
        if (line.startsWith('CLEAN:')) { current.status = 'CLEAN'; current.details = line.substring(7).trim(); }
        else if (line.startsWith('CRITICAL:')) { current.status = 'CRITICAL'; current.details = line.substring(10).trim(); }
        else if (line.startsWith('WARNING:')) { current.status = 'WARNING'; current.details = line.substring(9).trim(); }
        else if (line.startsWith('INFO:')) { current.status = 'INFO'; current.details = line.substring(6).trim(); }
        else if (line.trim() && !line.startsWith('===') && !line.startsWith('SCAN COMPLETE:') && !line.startsWith('STATUS:')) {
          current.details += (current.details ? '\n' : '') + line.trim();
        }
      }
    }
    if (current) checks.push(current);

    entries.push({
      timestamp: tsMatch[1],
      status: statusMatch ? statusMatch[1] : 'UNKNOWN',
      critical: summaryMatch ? parseInt(summaryMatch[1]) : 0,
      warnings: summaryMatch ? parseInt(summaryMatch[2]) : 0,
      clean: summaryMatch ? parseInt(summaryMatch[3]) : 0,
      checks,
    });
  }
  return entries.slice(-50);
}

function parseCronLog(content) {
  return content.split('\n').filter(l => l.trim()).slice(-50).map(line => {
    const tsMatch = line.match(/^(\S+)\s+(.*)/);
    return tsMatch ? { timestamp: tsMatch[1], message: tsMatch[2] } : { timestamp: '', message: line };
  });
}

function getIOCStats() {
  const stats = {};
  const files = ['c2-ips.txt', 'malicious-domains.txt', 'file-hashes.txt', 'malicious-publishers.txt', 'malicious-skill-patterns.txt'];
  for (const file of files) {
    const content = readFileSafe(path.join(IOC_DIR, file));
    const name = file.replace('.txt', '').replace(/-/g, '_');
    stats[name] = content ? content.split('\n').filter(l => l.trim() && !l.startsWith('#')).length : 0;
  }
  const lastUpdate = readFileSafe(path.join(IOC_DIR, '.last-update'));
  stats.last_update = lastUpdate ? lastUpdate.trim() : 'unknown';
  return stats;
}

function getConfigAudit() {
  const results = {};
  const configPath = path.join(OPENCLAW, 'openclaw.json');
  const config = readFileSafe(configPath);
  if (config) {
    try {
      const parsed = JSON.parse(config);
      results.configExists = true;
      results.configPerms = getFilePerms(configPath);
    } catch {
      results.configExists = true;
      results.configParseError = true;
    }
  } else {
    results.configExists = false;
  }
  return results;
}

function getFilePerms(filePath) {
  try {
    const stats = fs.statSync(filePath);
    return '0' + (stats.mode & 0o777).toString(8);
  } catch {
    return null;
  }
}

function getSkillsList() {
  const skillsDir = path.join(OPENCLAW, 'workspace', 'skills');
  try {
    const dirs = fs.readdirSync(skillsDir, { withFileTypes: true });
    return dirs
      .filter(d => d.isDirectory() && !d.name.startsWith('.'))
      .map(d => {
        const skillMd = readFileSafe(path.join(skillsDir, d.name, 'SKILL.md'));
        const versionMatch = skillMd ? skillMd.match(/version:\s*(\S+)/) : null;
        const nameMatch = skillMd ? skillMd.match(/name:\s*(\S+)/) : null;
        return {
          dir: d.name,
          name: nameMatch ? nameMatch[1] : d.name,
          version: versionMatch ? versionMatch[1] : 'unknown',
          hasSkillMd: !!skillMd,
        };
      });
  } catch {
    return [];
  }
}

// ─── Route Handler ──────────────────────────────────────────────────────────

async function handleRequest(req, res) {
  const parsedUrl = new URL(req.url, `http://${req.headers.host}`);
  const route = parsedUrl.pathname;
  const method = req.method;

  // Serve index.html
  if (route === '/' && method === 'GET') {
    try {
      const html = fs.readFileSync(path.join(DASHBOARD_DIR, 'index.html'), 'utf-8');
      res.writeHead(200, { ...SEC_HEADERS, 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    } catch {
      res.writeHead(500, SEC_HEADERS);
      res.end('index.html not found');
    }
    return;
  }

  // API: Latest scan results (from log file)
  if (route === '/api/scan' && method === 'GET') {
    const logContent = readFileSafe(path.join(LOGS, 'security-scan.log'));
    if (logContent) {
      const entries = parseScanLog(logContent);
      const latest = entries.length > 0 ? entries[entries.length - 1] : null;
      json(res, { latest, history: entries });
    } else {
      json(res, {
        latest: null,
        history: [],
        message: 'No scan results found. Run ./scripts/scan.sh to perform a scan.',
      });
    }
    return;
  }

  // API: Scan history
  if (route === '/api/logs/scan' && method === 'GET') {
    const logContent = readFileSafe(path.join(LOGS, 'security-scan.log'));
    if (logContent) {
      const entries = parseScanLog(logContent);
      json(res, { entries });
    } else {
      json(res, { entries: [], message: 'No scan log found.' });
    }
    return;
  }

  // API: Cron logs
  if (route === '/api/logs/cron' && method === 'GET') {
    const logContent = readFileSafe(path.join(LOGS, 'cron.log'));
    if (logContent) {
      const entries = parseCronLog(logContent);
      json(res, { entries });
    } else {
      json(res, { entries: [], message: 'No cron log found.' });
    }
    return;
  }

  // API: IOC database stats
  if (route === '/api/ioc' && method === 'GET') {
    json(res, getIOCStats());
    return;
  }

  // API: Installed skills list
  if (route === '/api/skills' && method === 'GET') {
    json(res, { skills: getSkillsList() });
    return;
  }

  // API: Config audit (read-only)
  if (route === '/api/config' && method === 'GET') {
    json(res, getConfigAudit());
    return;
  }

  // API: Status
  if (route === '/api/status' && method === 'GET') {
    const uptimeMs = Date.now() - startTime;
    const logContent = readFileSafe(path.join(LOGS, 'security-scan.log'));
    const entries = logContent ? parseScanLog(logContent) : [];
    const latest = entries.length > 0 ? entries[entries.length - 1] : null;

    json(res, {
      uptime: uptimeMs,
      uptimeHuman: `${Math.floor(uptimeMs / 3600000)}h ${Math.floor((uptimeMs % 3600000) / 60000)}m`,
      lastScan: latest ? latest.timestamp : null,
      lastScanStatus: latest ? latest.status : null,
      ioc: getIOCStats(),
      skillCount: getSkillsList().length,
      note: 'This dashboard is read-only. Use CLI scripts to run scans and remediation.',
    });
    return;
  }

  // API: Remediation log
  if (route === '/api/logs/remediation' && method === 'GET') {
    const logContent = readFileSafe(path.join(LOGS, 'remediation.log'));
    if (logContent) {
      const entries = logContent.split('\n').filter(l => l.trim()).slice(-100).map(line => {
        const tsMatch = line.match(/^\[(\S+)\]\s+(.*)/);
        return tsMatch ? { timestamp: tsMatch[1], message: tsMatch[2] } : { timestamp: '', message: line };
      });
      json(res, { entries });
    } else {
      json(res, { entries: [], message: 'No remediation log found.' });
    }
    return;
  }

  // API: Help — how to run scan/remediation
  if (route === '/api/help' && method === 'GET') {
    json(res, {
      message: 'This dashboard is a read-only viewer. Use CLI scripts for actions.',
      commands: {
        scan: './scripts/scan.sh',
        remediate: './scripts/remediate.sh',
        'remediate-single': './scripts/remediate.sh --check <N>',
        'remediate-dry-run': './scripts/remediate.sh --dry-run',
        'clawhub-scan': './scripts/clawhub-scan.sh',
        'update-ioc': './scripts/update-ioc.sh',
        'network-check': './scripts/network-check.sh',
      },
    });
    return;
  }

  // 404
  res.writeHead(404, { ...SEC_HEADERS, 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ error: 'Not found' }));
}

const server = http.createServer((req, res) => {
  handleRequest(req, res).catch(err => {
    console.error('Request error:', err);
    res.writeHead(500, SEC_HEADERS);
    res.end(JSON.stringify({ error: 'Internal server error' }));
  });
});

server.listen(PORT, HOST, () => {
  console.log(`Security Dashboard (read-only) running at http://${HOST}:${PORT}`);
  console.log('To run a scan: ./scripts/scan.sh');
  console.log('To remediate: ./scripts/remediate.sh');
});
