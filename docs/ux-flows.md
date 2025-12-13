# Flujos de UX

## 1. Inicio y configuración del PIN
1. El usuario instala la extensión y abre el panel.
2. Se solicita creación de un PIN (4–8 dígitos) + pista opcional.
3. El usuario confirma el PIN y se almacena hash + salt.

## 2. Administración de listas
1. El usuario abre el panel y se autentica con el PIN.
2. Selecciona la pestaña "Listas" con dos columnas: Permitidos y Bloqueados.
3. Puede agregar patrones con un formulario rápido (campo de URL + notas opcionales).
4. Las entradas existentes muestran botones de editar/eliminar.
5. Cambios se guardan automáticamente y actualizan `lastUpdated`.

## 3. Modo "solo permitidos"
1. Interruptor visible en la parte superior del panel.
2. Para activarlo, se requiere PIN si no está introducido en la sesión actual.
3. Al activarse, aparece un badge/indicador (p.ej. ícono del escudo en rojo) en la acción de la extensión.
4. El estado persiste hasta que se desactive manualmente.

## 4. Exportar configuración
1. Desde el panel autenticado, se pulsa "Exportar".
2. Se muestra un modal con el resumen (conteo de URLs, fecha).
3. El usuario confirma y el navegador descarga el archivo JSON.
4. Se muestra mensaje de éxito con recordatorio de compartirlo manualmente con otros dispositivos.

## 5. Importar configuración
1. El usuario abre el panel, ingresa el PIN y selecciona "Importar".
2. Elige un archivo JSON desde su equipo.
3. La extensión valida el esquema y compara `lastUpdated`.
4. Si el archivo es más antiguo, se muestra alerta con texto: "El archivo es del DD/MM/AAAA. Tu configuración local es más reciente. ¿Deseas sobrescribir igualmente?" con botones Cancelar/Confirmar.
5. Tras confirmar, se actualiza toda la configuración y se muestra notificación.

## 6. Bloqueo de navegación
1. Cuando el usuario intenta abrir una URL bloqueada, la extensión intercepta.
2. Se cierra/redirige la pestaña a una página interna indicando que el sitio está bloqueado.
3. Se muestra un mensaje amigable y, si el PIN es ingresado, puede abrirlo temporalmente (feature futura, fuera del MVP).

## 7. Indicador visual
- Cuando el modo "solo permitidos" está activo, el icono de la extensión muestra un punto rojo o un fondo distinto para recordar el modo estricto.
- Tooltip del icono actualiza el estado: "Solo permitidos: activo" o "activo desde HH:MM".
