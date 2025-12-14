# Instalación en Firefox de escritorio

La extensión ubicada en `src/firefox-extension` es compatible con Firefox para Windows, macOS y Linux. Puedes usarla como complemento temporal durante el desarrollo o empaquetarla en un `.xpi` firmado para uso permanente.

## Opción 1: Carga temporal (ideal para depurar)
1. Abre Firefox Desktop.
2. Ve a `about:debugging#/runtime/this-firefox`.
3. Haz clic en **Cargar complemento temporal**.
4. Selecciona el archivo `manifest.json` dentro de `src/firefox-extension`.
5. La extensión se registrará hasta que cierres Firefox. Verás el icono en la barra de herramientas; desde allí puedes configurar PIN, listas, exportar e importar igual que en Edge.

## Opción 2: Empaquetar y firmar para uso permanente
1. Desde la raíz del proyecto crea el paquete `.zip/.xpi`:
   ```powershell
   cd "src/firefox-extension"
   powershell -Command "Compress-Archive -Path * -DestinationPath ..\..\build\control-parental-firefox.zip -Force"
   Rename-Item ..\..\build\control-parental-firefox.zip control-parental-firefox.xpi
   ```
2. **Uso personal (Nightly/Beta):** en Firefox Nightly/Beta puedes instalar el `.xpi` sin firmar desde `about:addons` → **Instalar complemento desde archivo…** y seleccionar el `.xpi`.
3. **Uso en Firefox estable:** Mozilla exige firma. Debes:
   - Crear una cuenta en [addons.mozilla.org](https://addons.mozilla.org/developers/).
   - Subir el `.xpi` a AMO como complemento no listado.
   - Descargar el archivo firmado que genera AMO e instalarlo (o publicarlo si deseas compartirlo).

## Uso posterior
- Tras instalarlo, abre el icono “Control Parental” desde la barra de herramientas, crea el PIN y gestiona las listas.
- Para mantener varios dispositivos sincronizados (Edge, Firefox escritorio, Firefox Android), exporta la configuración desde uno y expórtala/importarla en los demás.
