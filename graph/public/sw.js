self.addEventListener('install', (event) => {
  self.skipWaiting();
});

self.addEventListener('activate', (event) => {
  event.waitUntil(self.clients.claim());
});

function parsePayload(event) {
  try {
    if (event.data) {
      return event.data.json();
    }
  } catch (_) {}
  return {};
}

self.addEventListener('push', (event) => {
  const payload = parsePayload(event);
  const title = payload.title || 'Bildirim';
  const options = {
    body: payload.body || '',
    icon: payload.icon || undefined,
    data: payload.data || {},
    badge: payload.badge || undefined
  };
  event.waitUntil(self.registration.showNotification(title, options));
});

self.addEventListener('notificationclick', (event) => {
  event.notification.close();
  const targetUrl = event.notification.data && event.notification.data.url;
  if (!targetUrl) return;
  event.waitUntil(
    self.clients.matchAll({ type: 'window', includeUncontrolled: true }).then((clientList) => {
      for (const client of clientList) {
        if (client.url === targetUrl && 'focus' in client) {
          return client.focus();
        }
      }
      if (self.clients.openWindow) {
        return self.clients.openWindow(targetUrl);
      }
      return null;
    })
  );
});
