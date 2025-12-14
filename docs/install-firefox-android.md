# Instalación en Firefox Android

## Requisitos
- Dispositivo Android con Firefox Nightly o Beta (Nightly recomendado para permitir complementos sin firmar).
- PC con ADB opcionalmente para transferir archivos más fácil.
- Carpeta del proyecto con `src/firefox-extension` actualizada.

## Empaquetado (.xpi)
1. Abre una terminal en la raíz del proyecto.
2. Ejecuta:
   ```powershell
   cd "src/firefox-extension"
   powershell -Command "Compress-Archive -Path * -DestinationPath ..\..\build\control-parental-firefox.zip -Force"
   ```
   (En Linux/macOS usa `zip -r ../../build/control-parental-firefox.zip .`)
3. Renombra el archivo a `.xpi`:
   ```powershell
   Rename-Item ..\..\build\control-parental-firefox.zip control-parental-firefox.xpi
   ```
4. Copia `build/control-parental-firefox.xpi` al teléfono (USB, nube o servidor local).

## Instalación en Firefox Nightly (Android)
1. En el teléfono abre Firefox Nightly y ve a `about:config`.
2. Asegúrate de que `xpinstall.signatures.required` esté en `false` (Nightly lo permite por defecto).
3. En el mismo menú habilita `extensions.install_from_file` si está disponible.
4. Abre Gestor de archivos → toca el `.xpi` → elige Firefox → confirma instalación.
   - Alternativa vía ADB: `adb push control-parental-firefox.xpi /sdcard/Download/` y luego ábrelo desde el teléfono.
5. Después de instalarlo, ve a `about:addons`, localiza "Control Parental Firefox" y activa las opciones "Permitir en navegación privada" si lo deseas.
6. Pulsa el icono de la extensión, crea tu PIN y gestiona listas igual que en escritorio.

## Actualizaciones
- Repite el proceso de compresión y vuelve a instalar el `.xpi`. Firefox reemplazará la versión previa conservando la configuración local del dispositivo.
- Si quieres distribuirlo públicamente, súbelo a AMO siguiendo las guías de Mozilla y habilita la compatibilidad Android durante el envío.
