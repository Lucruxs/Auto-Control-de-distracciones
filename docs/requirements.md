# Control parental para Edge

## Objetivo
Crear una solución de control parental enfocada en Microsoft Edge (u otro navegador Chromium compatible) que permita bloquear o permitir URLs específicas, habilitar un modo "solo permitidos" y compartir la configuración manualmente entre dispositivos mediante exportación/importación de archivos locales.

## Alcance
- El filtrado solo se aplica dentro del navegador objetivo (Edge en la primera versión).
- No se utiliza ningún servicio en la nube ni sincronización automática.
- La administración del sistema está protegida mediante un PIN local.
- La configuración se puede exportar/importar de forma manual para replicarla en otro equipo.

## Funcionalidades clave
1. **Listas de URLs bloqueadas y permitidas**
   - Entradas definidas por el usuario (una URL completa o con comodines simples tipo `*.sitio.com`).
   - Prioridad: el modo "solo permitidos" ignora la lista de bloqueados; fuera de ese modo, las URLs permitidas tienen precedencia sobre las bloqueadas.
2. **Modo "solo permitidos"**
   - Interruptor explícito en la UI que obliga a navegar únicamente por la lista de permitidos.
   - Indicador visual simple (badge/icono) que señala cuándo el modo está activo.
3. **Protección por PIN**
   - El acceso al panel administrativo requiere un PIN definido durante la configuración inicial.
   - El PIN se almacena localmente (hash + salt) y puede resetearse exportando/importando un archivo que incluya los valores nuevos.
4. **Exportación/Importación local**
   - Exporta toda la configuración (bloqueados, permitidos, estado del modo, metadatos y PIN) a un archivo JSON plano.
   - Al importar, se detecta si el archivo es más antiguo que la configuración local y se solicita confirmación antes de sobrescribir.
5. **Registro local opcional**
   - Historial básico de eventos (URL bloqueada/permitida, timestamp) conservado localmente y no exportado por defecto (opcional para builds futuras).

## Comportamiento deseado
- Las reglas se aplican a las peticiones de navegación, pestañas nuevas y redireccionamientos.
- Se muestra mensaje de bloqueo amigable cuando una URL está bloqueada.
- El usuario debe poder añadir o eliminar URLs rápidamente desde la UI protegida por PIN.
- El modo "solo permitidos" debe mantenerse hasta que el usuario lo desactive explícitamente.

## Requisitos no funcionales
- Funcionamiento offline: la extensión no debe depender de conectividad.
- Formato de archivo exportado legible para facilitar auditoría manual.
- Código y documentación en español.

## Suposiciones
- El usuario está dispuesto a copiar manualmente el archivo de configuración entre dispositivos (USB, correo, etc.).
- Solo se necesita soportar Windows (PC y laptop del usuario).
- No se requieren categorías ni cifrado del archivo exportado.

## Riesgos y mitigaciones
- **Pérdida de PIN:** permitir restablecimiento mediante importación de archivo exportado previamente.
- **Archivos desactualizados:** incluir metadatos de versión/fecha y mostrar advertencia con confirmación al importar.
- **Evasión mediante otros navegadores:** fuera de alcance; se documenta claramente que solo Edge está protegido.
