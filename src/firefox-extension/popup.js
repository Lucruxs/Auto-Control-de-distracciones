const api = typeof browser !== "undefined" ? browser : chrome;
const statusText = document.getElementById("statusText");
const pinInput = document.getElementById("pinInput");
const toggleButton = document.getElementById("toggleButton");
const feedback = document.getElementById("feedback");
const openOptions = document.getElementById("openOptions");

let meta = null;

init();

function init() {
  openOptions.addEventListener("click", () => api.runtime.openOptionsPage());
  toggleButton.addEventListener("click", onToggle);
  loadMeta();
}

async function loadMeta() {
  const response = await send({ type: "getMeta" });
  if (!response.success) {
    statusText.textContent = "Error al cargar estado";
    return;
  }
  meta = response.data;
  render();
}

function render() {
  if (!meta) {
    statusText.textContent = "Sin datos";
    return;
  }
  const active = meta.allowOnlyMode;
  statusText.textContent = active ? "Modo solo permitidos: ACTIVO" : "Modo solo permitidos: inactivo";
  toggleButton.textContent = active ? "Desactivar modo" : "Activar solo permitidos";
}

async function onToggle() {
  if (!meta) {
    return;
  }
  const pin = pinInput.value.trim();
  if (!pin) {
    setFeedback("Ingresa el PIN para continuar.", true);
    return;
  }
  const nextState = !meta.allowOnlyMode;
  const response = await send({
    type: "toggleAllowOnly",
    pin,
    enabled: nextState
  });
  if (!response.success) {
    setFeedback(response.error || "No se pudo actualizar.", true);
    return;
  }
  meta.allowOnlyMode = response.data.allowOnlyMode.enabled;
  render();
  setFeedback("Modo actualizado correctamente.");
}

function setFeedback(message, isError = false) {
  feedback.textContent = message;
  feedback.classList.toggle("error", isError);
}

function send(payload) {
  return new Promise(resolve => {
    api.runtime.sendMessage(payload, resolve);
  });
}
