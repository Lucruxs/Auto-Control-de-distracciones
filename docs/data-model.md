# Modelo de datos

El sistema utiliza un almacén local dentro de la extensión (IndexedDB/Storage) y permite exportar la configuración completa en JSON. Los objetos clave son los siguientes:

## Configuración principal (`ParentalConfig`)
- `schemaVersion: number` – versión del formato para futuras migraciones.
- `lastUpdated: string` – fecha ISO 8601 de la última modificación.
- `adminPin` – objeto protegido descrito abajo.
- `rules: RuleSet` – colección de listas.
- `allowOnlyMode: AllowOnlyState` – estado del modo "solo permitidos".

## PIN administrativo (`AdminPin`)
- `hash: string` – hash del PIN (p.ej. PBKDF2 + SHA-256) en base64.
- `salt: string` – salt aleatoria en base64.
- `hint?: string` – pista opcional guardada en claro.

## Conjunto de reglas (`RuleSet`)
- `allowedUrls: UrlRule[]` – URLs explícitamente permitidas.
- `blockedUrls: UrlRule[]` – URLs explícitamente bloqueadas.

## Regla de URL (`UrlRule`)
- `pattern: string` – URL o patrón con comodines simples (`*`).
- `notes?: string` – comentario opcional para recordar el motivo.
- `createdAt: string` – fecha ISO de creación.

## Estado del modo estricto (`AllowOnlyState`)
- `enabled: boolean` – indica si el modo está activo.
- `toggledAt?: string` – fecha ISO del último cambio.

## Registro de eventos (`AuditEvent`)
> Opcional en la primera versión, pero se deja estructurado.
- `id: string` – identificador único.
- `timestamp: string` – fecha/hora ISO.
- `url: string` – URL solicitada.
- `action: "allowed" | "blocked"` – resultado aplicado.
- `reason: "allowlist" | "blocklist" | "allowOnly"` – fuente de la decisión.

## Consideraciones de almacenamiento
- Almacenamiento local primario: `browser.storage.local` o IndexedDB.
- Exportación/importación: serialización/deserialización completa de `ParentalConfig`.
- Validaciones: verificar `schemaVersion`, fecha y estructura antes de aceptar una importación.
