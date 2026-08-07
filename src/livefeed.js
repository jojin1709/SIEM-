const { WebSocketServer } = require('ws');

let wss = null;
const clients = new Set();

function start(server) {
  if (wss) return;
  wss = new WebSocketServer({ server, path: '/ws/events' });

  wss.on('connection', (ws) => {
    clients.add(ws);
    ws.send(JSON.stringify({ type: 'connected', time: Date.now() }));

    ws.on('close', () => clients.delete(ws));
    ws.on('error', () => clients.delete(ws));
  });

  console.log('  [ws] Live feed listening on /ws/events');
}

function broadcast(event) {
  if (!clients.size) return;
  const msg = JSON.stringify({ type: 'event', data: event });
  for (const ws of clients) {
    if (ws.readyState === ws.OPEN) {
      ws.send(msg);
    }
  }
}

function broadcastAlert(alert) {
  if (!clients.size) return;
  const msg = JSON.stringify({ type: 'alert', data: alert });
  for (const ws of clients) {
    if (ws.readyState === ws.OPEN) {
      ws.send(msg);
    }
  }
}

module.exports = { start, broadcast, broadcastAlert };
