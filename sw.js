//sw.js

const CACHE_NAME = 'zappbot-v5'; // Versão atualizada para forçar o cache a recarregar as novas regras de notificação
const ASSETS_TO_CACHE =[
  '/',
  '/index.html',
  '/clients.html',
  '/manifest.json',
  '/icon-192x192.png',
  '/fundowhats.jpg',
  '/icon-512x512.png',
  'https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css',
  'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap',
  'https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&family=Plus+Jakarta+Sans:wght@400;500;600;700;800&display=swap',
  'https://cdn.jsdelivr.net/npm/qrcodejs@1.0.0/qrcode.min.js'
];

// Instalação do Service Worker
self.addEventListener('install', (event) => {
  self.skipWaiting();
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => {
      return cache.addAll(ASSETS_TO_CACHE);
    })
  );
});

// Ativação e limpeza de caches antigos
self.addEventListener('activate', (event) => {
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
  self.clients.claim();
});

// Interceptação de requisições
self.addEventListener('fetch', (event) => {
  // Não cacheia requisições dinâmicas de API ou Socket.io
  if (event.request.url.includes('/api/') || 
      event.request.url.includes('/socket.io/') || 
      event.request.method !== 'GET') {
    return;
  }

  // Para HTML (A interface do painel), usamos a estratégia "Network-First" (Rede Primeiro)
  // Isso garante que se houver internet, ele SEMPRE pega a versão mais nova do servidor.
  // Se estiver sem internet, ele cai no catch e puxa do cache (modo offline).
  if (event.request.mode === 'navigate' || event.request.url.includes('.html')) {
    event.respondWith(
      fetch(event.request).then((networkResponse) => {
        return caches.open(CACHE_NAME).then((cache) => {
          cache.put(event.request, networkResponse.clone());
          return networkResponse;
        });
      }).catch(() => {
        return caches.match(event.request);
      })
    );
    return;
  }

  // Para Imagens, Fontes e Scripts de terceiros, usamos "Cache-First" (Cache Primeiro)
  // Deixa o carregamento super rápido e economiza banda.
  event.respondWith(
    caches.match(event.request).then((cachedResponse) => {
      if (cachedResponse) {
        return cachedResponse;
      }
      return fetch(event.request).then((networkResponse) => {
        if (!networkResponse || networkResponse.status !== 200 || networkResponse.type !== 'basic') {
          return networkResponse;
        }
        const responseToCache = networkResponse.clone();
        caches.open(CACHE_NAME).then((cache) => {
          cache.put(event.request, responseToCache);
        });
        return networkResponse;
      });
    })
  );
});

// Escuta mensagens para forçar atualização (botão "Atualizar Agora")
self.addEventListener('message', (event) => {
  if (event.data && event.data.type === 'SKIP_WAITING') {
    self.skipWaiting();
  }
});

// ============================================================================
// NOVO: Lida com o clique na notificação no celular/desktop
// ============================================================================
self.addEventListener('notificationclick', (event) => {
  event.notification.close(); // Fecha a notificação ao ser tocada
  
  const targetUrl = event.notification.data ? event.notification.data.url : '/';

  event.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then((windowClients) => {
      // Se já tiver uma aba do painel aberta, foca nela e avisa o HTML para abrir o chat
      for (let client of windowClients) {
        if (client.url.includes('/') && 'focus' in client) {
          client.postMessage({ type: 'OPEN_CHAT_FROM_NOTIF', url: targetUrl });
          return client.focus();
        }
      }
      // Se o app estiver fechado, abre o painel direto na URL com os parâmetros
      if (clients.openWindow) {
        return clients.openWindow(targetUrl);
      }
    })
  );
});

// ============================================================================
// NOVO: Escuta as notificações em segundo plano (Web Push)
// ============================================================================
self.addEventListener('push', function(event) {
  if (event.data) {
    const data = event.data.json();
    
    // Monta a URL com os parâmetros exatos do cliente que enviou a mensagem
    let targetUrl = '/';
    if (data.data && data.data.sessionName && data.data.jid) {
        targetUrl = `/?action=open_chat&session=${data.data.sessionName}&jid=${data.data.jid}&name=${encodeURIComponent(data.data.clientName || 'Cliente')}`;
    }

    const options = {
      body: data.body,
      icon: data.icon || '/api/logo/192', // Usa a foto do cliente do WhatsApp ou a logo do painel
      badge: '/api/logo/192',             // Ícone pequeno que fica na barra superior do Android
      tag: data.tag || 'zappbot-msg',     // ID único. Substitui o card antigo dessa pessoa. Fim do Spam!
      renotify: true,                     // Toca o som/vibra novamente mesmo que seja só atualização de texto
      vibrate: data.vibrate || [200, 100, 200],
      data: { url: targetUrl } 
    };
    
    event.waitUntil(
      self.registration.showNotification(data.title, options)
    );
  }
});


