const http = require('http');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const PUBLIC_DIR = path.join(__dirname, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const SCOREBOARD_FILE = path.join(DATA_DIR, 'scoreboard.json');

// Ensure data directory exists
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

// MIME types for static files
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

// Flags Database
const CHALLENGES = {
  1: { title: "OSINT & Public Intelligence", flag: "NH{public_osint_leak}", points: 100 },
  2: { title: "Hidden Messages & Decryption", flag: "NH{cipher_stream_decoded}", points: 150 },
  3: { title: "Vulnerable Web Portal", flag: "NH{sql_bypass_prom_auth}", points: 200 },
  4: { title: "Network Traffic & PCAP Forensics", flag: "NH{pcap_exfiltrated_stream}", points: 250 },
  5: { title: "Protected Linux Host Escalation", flag: "NH{privesc_suid_root_access}", points: 300 },
  6: { title: "Prometheus Vault Recovery", flag: "NH{prometheus_core_vault_unlocked}", points: 500 }
};

// Helpers for JSON Scoreboard
function loadScoreboard() {
  if (fs.existsSync(SCOREBOARD_FILE)) {
    try {
      const content = fs.readFileSync(SCOREBOARD_FILE, 'utf-8');
      return JSON.parse(content);
    } catch (e) {
      console.error('[!] Error loading scoreboard JSON:', e);
    }
  }
  return { teams: [] };
}

function saveScoreboard(data) {
  try {
    fs.writeFileSync(SCOREBOARD_FILE, JSON.stringify(data, null, 2), 'utf-8');
  } catch (e) {
    console.error('[!] Error saving scoreboard JSON:', e);
  }
}

// Helper to serve static files
function serveStaticFile(reqPath, res) {
  let safePath = path.normalize(reqPath).replace(/^(\.\.[\/\\])+/, '');
  if (safePath === '/' || safePath === '\\' || safePath === '') {
    safePath = '/index.html';
  }

  let filePath = path.join(PUBLIC_DIR, safePath);

  if (fs.existsSync(filePath) && fs.statSync(filePath).isDirectory()) {
    filePath = path.join(filePath, 'index.html');
  }

  const ext = path.extname(filePath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';

  fs.readFile(filePath, (err, content) => {
    if (err) {
      if (err.code === 'ENOENT') {
        res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('404 Not Found');
      } else {
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end(`Server Error: ${err.code}`);
      }
    } else {
      res.writeHead(200, { 'Content-Type': contentType });
      res.end(content);
    }
  });
}

// Helper to parse JSON body
function parseBody(req, callback) {
  let body = '';
  req.on('data', chunk => { body += chunk.toString(); });
  req.on('end', () => {
    try {
      if (req.headers['content-type'] && req.headers['content-type'].includes('application/json')) {
        callback(null, JSON.parse(body));
      } else {
        const params = new URLSearchParams(body);
        const obj = {};
        for (const [key, val] of params.entries()) obj[key] = val;
        callback(null, obj);
      }
    } catch (err) {
      callback(err, {});
    }
  });
}

// Create HTTP Server
const server = http.createServer((req, res) => {
  const reqUrl = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = reqUrl.pathname;
  const method = req.method.toUpperCase();

  // Set CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (method === 'OPTIONS') {
    res.writeHead(204);
    res.end();
    return;
  }

  // 1. API: Register Team & Start CTF
  if (pathname === '/api/start' && method === 'POST') {
    parseBody(req, (err, payload) => {
      const teamName = (payload.teamName || payload.team_name || '').trim();

      if (!teamName) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, message: 'Team name is required.' }));
        return;
      }

      const scoreboard = loadScoreboard();
      let team = scoreboard.teams.find(t => t.team_name.toLowerCase() === teamName.toLowerCase());

      if (!team) {
        team = {
          team_name: teamName,
          total_score: 0,
          completed_count: 0,
          total_time: '00:00:00',
          total_seconds: 0,
          is_finished: false,
          stage_times: {},
          registered_at: new Date().toISOString(),
          last_updated: new Date().toISOString()
        };
        scoreboard.teams.push(team);
        saveScoreboard(scoreboard);
        console.log(`[+] Node.js: Registered Team "${teamName}" in JSON Scoreboard`);
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({
        success: true,
        message: 'Team registered successfully!',
        teamName: teamName,
        redirectUrl: `/challenge.html?team=${encodeURIComponent(teamName)}`
      }));
    });
    return;
  }

  // 2. API: Verify Flag & Record Submission Timings
  if (pathname === '/api/verify-flag' && method === 'POST') {
    parseBody(req, (err, payload) => {
      const stageId = parseInt(payload.stage, 10);
      const submittedFlag = (payload.flag || '').trim();
      const teamName = (payload.teamName || payload.team_name || 'Anonymous').trim();
      const timeStr = (payload.timeElapsed || payload.time_elapsed || '00:00:00').trim();
      const secCount = payload.secondsElapsed !== undefined ? payload.secondsElapsed : (payload.seconds_elapsed || 0);

      const challenge = CHALLENGES[stageId];
      if (!challenge) {
        res.writeHead(404, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, message: 'Invalid challenge stage.' }));
        return;
      }

      if (submittedFlag === challenge.flag) {
        const scoreboard = loadScoreboard();
        let team = scoreboard.teams.find(t => t.team_name.toLowerCase() === teamName.toLowerCase());

        if (!team) {
          team = {
            team_name: teamName,
            total_score: 0,
            completed_count: 0,
            total_time: '00:00:00',
            total_seconds: 0,
            is_finished: false,
            stage_times: {},
            registered_at: new Date().toISOString(),
            last_updated: new Date().toISOString()
          };
          scoreboard.teams.push(team);
        }

        const stageKey = String(stageId);
        if (!team.stage_times[stageKey]) {
          team.stage_times[stageKey] = timeStr;
          team.total_score += challenge.points;
          team.completed_count += 1;
          team.total_time = timeStr;
          team.total_seconds = secCount;
          team.last_updated = new Date().toISOString();

          if (team.completed_count >= Object.keys(CHALLENGES).length) {
            team.is_finished = true;
          }

          saveScoreboard(scoreboard);
          console.log(`[✓] Node.js: Stage ${stageId} cleared by "${teamName}" at ${timeStr} (Saved to JSON)`);
        }

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: true,
          message: `✓ Correct flag! Stage ${stageId} cleared in ${timeStr}.`,
          stage: stageId,
          next_stage: stageId < 6 ? stageId + 1 : null,
          points_earned: challenge.points,
          total_score: team.total_score,
          time_recorded: timeStr,
          is_completed: team.completed_count >= 6
        }));
      } else {
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: false,
          message: '✕ Incorrect flag. Check your analysis and try again.'
        }));
      }
    });
    return;
  }

  // 3. API: Scoreboard & Teams list
  if ((pathname === '/api/scoreboard' || pathname === '/api/teams') && method === 'GET') {
    const scoreboard = loadScoreboard();
    const sortedTeams = scoreboard.teams.sort((a, b) => {
      if (b.total_score !== a.total_score) {
        return b.total_score - a.total_score;
      }
      return (a.total_seconds || 0) - (b.total_seconds || 0);
    });

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      success: true,
      total_teams: sortedTeams.length,
      scoreboard: sortedTeams
    }));
    return;
  }

  // 4. Serve Static Files (HTML, CSS, JS)
  if (method === 'GET') {
    serveStaticFile(pathname, res);
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('404 Not Found');
});

// Start Server
server.listen(PORT, () => {
  console.log(`===========================================`);
  console.log(`  Operation NightHawk CTF Server Running!  `);
  console.log(`  Access Platform: http://localhost:${PORT} `);
  console.log(`  Scoreboard URL:  http://localhost:${PORT}/scoreboard.html `);
  console.log(`===========================================`);
});
