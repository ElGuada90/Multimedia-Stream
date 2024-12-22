// Nombre y versión del caché
const CACHE_NAME = 'my-site-cache-v1';
const urlsToCache = [
  '/', // Agrega la ruta de tu página principal
  '/static/css/site.css',
  '/static/javascripts/main.js',
  '/static/images/icon G2.png', // Agrega las rutas de tus imágenes y otros recursos estáticos
  // Incluye otros recursos que quieres precachear
];

// Evento de instalación: cachea los archivos especificados
self.addEventListener('install', (event) => {
  console.log('Service Worker instalado');
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then((cache) => {
        console.log('Archivos en caché');
        return cache.addAll(urlsToCache);
      })
  );
});

// Evento de activación: limpia el caché de versiones antiguas
self.addEventListener('activate', (event) => {
  console.log('Service Worker activado');
  event.waitUntil(
    caches.keys().then((cacheNames) => {
      return Promise.all(
        cacheNames.map((cacheName) => {
          if (cacheName !== CACHE_NAME) {
            console.log('Borrando caché antiguo:', cacheName);
            return caches.delete(cacheName);
          }
        })
      );
    })
  );
});

// Evento de fetch: responde con caché o realiza una solicitud de red
self.addEventListener('fetch', (event) => {
  event.respondWith(
    caches.match(event.request).then((response) => {
      return response || fetch(event.request);
    })
  );
});

  