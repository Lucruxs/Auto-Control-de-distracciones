# Plan de pruebas

## 1. Configuración inicial
- Crear PIN y confirmar que el hash/salt se guardan.
- Reiniciar Edge y verificar que el PIN se solicita nuevamente.

## 2. Listas de URLs
- Agregar patrones permitidos/bloqueados y confirmar persistencia tras reiniciar el navegador.
- Verificar precedencia: una URL incluida en ambos listados debería respetar la lista de permitidos.
- Validar soporte de comodines simples (`*`).

## 3. Modo "solo permitidos"
- Activar el modo y abrir una URL permitida → debe cargar.
- Intentar URL no incluida → debe bloquearse aunque no esté en bloqueados.
- Desactivar el modo y confirmar que las URLs fuera de los permitidos vuelven a comportarse normalmente.
- Verificar indicador visual (icono) cambia al activar/desactivar.

## 4. Protección por PIN
- Intentar acceder al panel con PIN incorrecto: mostrar error sin bloqueo permanente.
- Intentar exportar/importar sin PIN → debe solicitarlo.
- Cambiar el PIN importando un archivo nuevo.

## 5. Exportación/Importación
- Exportar y revisar que el JSON siga el esquema (`schemaVersion`, `lastUpdated`).
- Importar el mismo archivo en otro perfil/PC y confirmar que las listas coinciden.
- Modificar la configuración local y luego intentar importar un archivo con fecha anterior → debe aparecer advertencia y requerir confirmación.
- Importar archivos malformados → debe rechazar con mensaje claro.

## 6. Bloqueo de navegación
- Navegar a una URL bloqueada y verificar que se muestra página de bloqueo.
- Abrir múltiples pestañas rápidas apuntando a URLs bloqueadas para revisar que el filtro actúa en cada tab.

## 7. Persistencia y reinicios
- Cerrar Edge, reabrir y confirmar que la configuración (incluyendo modo "solo permitidos") se mantiene.
- Verificar que `lastUpdated` cambia tras modificar listas.

## 8. Compatibilidad multi-equipo
- Exportar desde PC principal, copiar archivo vía USB y importar en laptop.
- Confirmar que el comportamiento es idéntico en ambos dispositivos.
