# Port a Firefox para Android

## Meta
Llevar la extensión de control parental a Firefox Android (Nightly/Beta) para que funcione en móviles sin crear un navegador contenedor, reutilizando la lógica principal y manteniendo la exportación/importación manual.

## Principales decisiones
1. **Manifest versión:** Firefox (Android + desktop) soporta Manifest V3 parcialmente, pero el canal estable para Android sigue recomendando MV2. Optaremos por un paquete separado MV2 para garantizar compatibilidad inmediata.
2. **Arquitectura:** reaprovechar `service-worker.js` como fondo; en MV2 usaremos `background.js` que encapsula la misma lógica (mismo código con leves adaptaciones) o empaquetarlo como módulo importado.
3. **Permisos:** `webRequest`, `webRequestBlocking`, `storage`, `tabs`, `webNavigation` están soportados en Firefox MV2. No se requiere `host_permissions`; se declararán bajo `permissions`.
4. **UI:** `popup.html`, `options.html`, `blocked.html` funcionan sin cambios (Firefox soporta páginas de acción y opciones). Solo se debe ajustar `browser.*` vs `chrome.*` si deseamos API unificada; usaremos un wrapper sencillo.
5. **Empaquetado:** crear carpeta `src/firefox-extension`. Paso final: ejecutar `zip -r control-parental-firefox.zip .` dentro de la carpeta y renombrar a `.xpi` para instalar en Firefox Android (Nightly/Beta) mediante `about:addons`/ADB.
6. **Instalación en Android:** habilitar complementos personalizados (Nightly), transferir `.xpi` al dispositivo y abrirlo, o alojarlo temporalmente en un servidor local.

## Tareas técnicas
- Crear `browser-api.js` que exponga `const api = chrome || browser` para compatibilidad cruzada.
- Extraer la lógica central del MV3 `service-worker.js` a un archivo compartido `core.js` que pueda ejecutarse tanto en service worker como en background script MV2.
- Escribir `background.js` (MV2) que importe `core.js`, inicialice listeners y exponga `browser.runtime.onMessage`.
- Ajustar el manifest MV2 con secciones `background`, `browser_action`, `options_ui`, `permissions`, `web_accessible_resources`.
- Documentar empaquetado e instalación en este archivo y en `docs/install-firefox-android.md`.

## Instalación resumida (Firefox Android Nightly)
1. Activar ajustes de desarrollador en Firefox Nightly -> `about:config` -> `xpinstall.signatures.required` = false (Nightly ya lo permite) y habilitar `extensions.install_requirements` si aplica.
2. Transferir el `.xpi` al móvil (USB, nube, servidor local).
3. Desde el dispositivo, abrir el `.xpi` con Firefox -> confirmar instalación.
4. Ir a `about:addons`, permitir ejecución en ventanas normales y privadas.
5. Configurar PIN, listas y probar bloqueo.
