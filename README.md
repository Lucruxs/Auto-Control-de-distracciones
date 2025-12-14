# Control Parental Local para Microsoft Edge

Extensión Manifest V3 enfocada en Microsoft Edge/Chromium que aplica control parental sin servicios en la nube. Permite establecer listas de URLs permitidas/bloqueadas, activar el modo "solo permitidos", proteger la configuración con PIN y sincronizar equipos mediante exportación/importación de un archivo JSON.

## Funcionalidades
- Listas de URLs con soporte de patrones (`*.dominio.com`).
- Modo "solo permitidos" con badge "ON" en el icono de la extensión.
- Panel de administración protegido por PIN (hash + salt) y pista opcional.
- Exportación/Importación manual (JSON) para compartir reglas entre dispositivos.
- Página de bloqueo con explicación del motivo (bloqueo directo o modo estricto).

## Instalación
1. Abre `edge://extensions` y activa **Modo desarrollador**.
2. Pulsa **Cargar extensión sin empaquetar** y selecciona la carpeta `src/edge-extension`.
3. En **Detalles** puedes activar "Permitir en InPrivate" si deseas que funcione en modo privado.
4. Haz clic en el icono "Control parental", crea tu PIN y administra las listas.

## Exportar e importar configuración
1. Desde el panel autenticado, usa **Exportar configuración** para descargar un JSON.
2. Copia el archivo al otro equipo (USB, correo, etc.).
3. En el segundo Edge, abre el panel de la extensión → **Importar configuración** → selecciona el archivo. Confirma si aparece advertencia por fecha antigua.
4. Los bloqueados, permitidos, PIN y estado del modo estricto quedarán sincronizados.

## Estructura relevante
```
src/edge-extension/
  manifest.json
  service-worker.js
  popup.html / popup.js
  options.html / options.js
  blocked.html / blocked.js / blocked.css
  styles.css
```

## Desarrollo
- La lógica principal vive en `service-worker.js` (intercepta peticiones, gestiona reglas y PIN, maneja exportación/importación).
- UI construida con HTML/CSS/JS vanilla.
- Sigue el plan de pruebas en `docs/testing.md` para validar bloqueos, PIN y exportaciones.
- Para compartir actualizaciones, comprime la carpeta `src/edge-extension` o publícala como extensión Edge/Chrome empaquetada.
