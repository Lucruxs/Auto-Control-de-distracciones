# Formato de exportación

La configuración se intercambia mediante un archivo JSON plano (`.json`). El objetivo es que el usuario pueda copiar el archivo entre dispositivos de forma manual y que el sistema detecte versiones antiguas antes de sobrescribir.

## Estructura
```json
{
  "schemaVersion": 1,
  "lastUpdated": "2025-12-13T12:00:00Z",
  "adminPin": {
    "hash": "base64",
    "salt": "base64",
    "hint": "opcional"
  },
  "rules": {
    "allowedUrls": [
      { "pattern": "https://www.ejemplo.edu/*", "notes": "Tareas", "createdAt": "2025-12-12T09:00:00Z" }
    ],
    "blockedUrls": [
      { "pattern": "https://*.juegos.com", "createdAt": "2025-12-10T21:00:00Z" }
    ]
  },
  "allowOnlyMode": {
    "enabled": true,
    "toggledAt": "2025-12-13T11:59:00Z"
  }
}
```

## Reglas de validación
1. `schemaVersion` debe coincidir con la versión soportada; si es superior, se rechaza la importación.
2. `lastUpdated` se compara con la fecha local; si el archivo es más antiguo se muestra advertencia y se solicita confirmación.
3. Los arreglos `allowedUrls` y `blockedUrls` no pueden contener patrones duplicados exactos.
4. Debe existir al menos un patrón en cualquiera de las listas antes de activar el modo "solo permitidos".

## Flujo de exportación
1. El usuario abre el panel administrativo (se solicita PIN).
2. Selecciona "Exportar configuración" y el sistema genera el JSON con la estructura anterior.
3. Se descarga un archivo (`control-parental-config-YYYYMMDD.json`).

## Flujo de importación
1. El usuario ingresa al panel administrativo y elige "Importar configuración".
2. Se carga el archivo JSON y se valida contra el esquema.
3. Si `lastUpdated` es anterior a la configuración actual, se muestra advertencia: "Este archivo parece antiguo. ¿Deseas sobrescribir?" con botones Confirmar/Cancelar.
4. Al confirmar, se reemplaza la configuración local completa.

## Consideraciones
- No se cifra el archivo; el usuario debe protegerlo manualmente.
- Para restaurar el PIN, basta con importar un archivo exportado previamente con el PIN deseado.
- Futuras versiones pueden añadir campos; incluir `schemaVersion` permite manejar migraciones.
