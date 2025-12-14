const api = typeof browser !== "undefined" ? browser : chrome;

const setupSection = document.getElementById("setupSection");
const loginSection = document.getElementById("loginSection");
const appSection = document.getElementById("appSection");

const setupPinInput = document.getElementById("setupPin");
const setupPinConfirmInput = document.getElementById("setupPinConfirm");
const setupHintInput = document.getElementById("setupHint");
const setupPinButton = document.getElementById("setupPinButton");
const setupFeedback = document.getElementById("setupFeedback");

const loginPinInput = document.getElementById("loginPin");
const loginButton = document.getElementById("loginButton");
const loginFeedback = document.getElementById("loginFeedback");

const statusBadge = document.getElementById("statusBadge");
const lastUpdatedLabel = document.getElementById("lastUpdated");
const toggleAllowOnlyButton = document.getElementById("toggleAllowOnly");
const allowedCountLabel = document.getElementById("allowedCount");
const blockedCountLabel = document.getElementById("blockedCount");

const allowedForm = document.getElementById("allowedForm");
const allowedPatternInput = document.getElementById("allowedPattern");
const allowedNotesInput = document.getElementById("allowedNotes");
const allowedList = document.getElementById("allowedList");

const blockedForm = document.getElementById("blockedForm");
const blockedPatternInput = document.getElementById("blockedPattern");
const blockedNotesInput = document.getElementById("blockedNotes");
const blockedList = document.getElementById("blockedList");

const exportButton = document.getElementById("exportButton");
const exportFeedback = document.getElementById("exportFeedback");
const importInput = document.getElementById("importInput");
const importButton = document.getElementById("importButton");
const importFeedback = document.getElementById("importFeedback");

const state = {
  meta: null,
  pin: null,
  rules: null
};

init();

function init() {
  setupPinButton.addEventListener("click", onSetupPin);
  loginButton.addEventListener("click", onLogin);
  toggleAllowOnlyButton.addEventListener("click", onToggleAllowOnly);
  allowedForm.addEventListener("submit", onAddAllowed);
  blockedForm.addEventListener("submit", onAddBlocked);
  exportButton.addEventListener("click", onExport);
  importButton.addEventListener("click", onImport);
  loadMeta();
}

async function loadMeta() {
  const response = await send({ type: "getMeta" });
  if (!response.success) {
    loginFeedback.textContent = response.error || "Error al cargar estado";
    return;
  }
  state.meta = response.data;
  updateSections();
}

function updateSections() {
  const hasPin = state.meta?.hasPin;
  setupSection.hidden = Boolean(hasPin);
  loginSection.hidden = !hasPin || Boolean(state.pin);
  appSection.hidden = !state.pin;
  if (state.pin) {
    renderMeta();
    loadRules();
  }
}

async function onSetupPin() {
  const pin = setupPinInput.value.trim();
  const confirmPin = setupPinConfirmInput.value.trim();
  const hint = setupHintInput.value.trim();
  if (pin.length < 4 || pin.length > 8) {
    setupFeedback.textContent = "El PIN debe tener entre 4 y 8 dígitos.";
    return;
  }
  if (pin !== confirmPin) {
    setupFeedback.textContent = "Los PIN no coinciden.";
    return;
  }
  const response = await send({ type: "setupPin", pin, hint });
  if (!response.success) {
    setupFeedback.textContent = response.error || "No se pudo guardar el PIN.";
    return;
  }
  state.meta = response.data;
  state.pin = pin;
  setupFeedback.textContent = "PIN configurado. Continúa administrando las listas.";
  updateSections();
}

async function onLogin() {
  const pin = loginPinInput.value.trim();
  if (!pin) {
    loginFeedback.textContent = "Ingresa tu PIN.";
    return;
  }
  const response = await send({ type: "verifyPin", pin });
  if (!response.success || !response.data.valid) {
    loginFeedback.textContent = "PIN incorrecto.";
    return;
  }
  state.pin = pin;
  loginFeedback.textContent = "Acceso concedido.";
  updateSections();
}

async function loadRules() {
  const response = await send({ type: "listRules", pin: state.pin });
  if (!response.success) {
    console.error(response.error);
    return;
  }
  state.rules = response.data.rules;
  renderRules();
}

function renderMeta() {
  if (!state.meta) {
    return;
  }
  const active = state.meta.allowOnlyMode;
  statusBadge.textContent = active ? "Modo solo permitidos activo" : "Modo solo permitidos inactivo";
  statusBadge.classList.toggle("active", active);
  statusBadge.classList.toggle("idle", !active);
  lastUpdatedLabel.textContent = state.meta.lastUpdated ? new Date(state.meta.lastUpdated).toLocaleString() : "--";
  allowedCountLabel.textContent = state.meta.allowedCount;
  blockedCountLabel.textContent = state.meta.blockedCount;
  toggleAllowOnlyButton.textContent = active ? "Desactivar" : "Activar";
}

function renderRules() {
  renderRuleList(allowedList, state.rules?.allowedUrls || [], "allowed");
  renderRuleList(blockedList, state.rules?.blockedUrls || [], "blocked");
}

function renderRuleList(container, rules, listType) {
  container.innerHTML = "";
  if (!rules.length) {
    const empty = document.createElement("li");
    empty.textContent = "Sin datos";
    container.appendChild(empty);
    return;
  }
  rules.forEach(rule => {
    const li = document.createElement("li");
    const info = document.createElement("div");
    info.innerHTML = `<strong>${rule.pattern}</strong><br/><span class="muted">${rule.notes || "Sin notas"}</span>`;
    const button = document.createElement("button");
    button.textContent = "Eliminar";
    button.addEventListener("click", () => removeRule(listType, rule.pattern));
    li.appendChild(info);
    li.appendChild(button);
    container.appendChild(li);
  });
}

async function onAddAllowed(event) {
  event.preventDefault();
  await addRule("allowed", allowedPatternInput.value, allowedNotesInput.value);
  allowedForm.reset();
}

async function onAddBlocked(event) {
  event.preventDefault();
  await addRule("blocked", blockedPatternInput.value, blockedNotesInput.value);
  blockedForm.reset();
}

async function addRule(listType, pattern, notes) {
  if (!pattern) {
    return;
  }
  const response = await send({
    type: "addRule",
    listType,
    pattern,
    notes,
    pin: state.pin
  });
  if (!response.success) {
    alert(response.error || "No se pudo agregar la regla.");
    return;
  }
  state.rules = response.data.rules;
  await loadMeta();
  renderRules();
}

async function removeRule(listType, pattern) {
  if (!confirm(`¿Eliminar ${pattern}?`)) {
    return;
  }
  const response = await send({
    type: "removeRule",
    listType,
    pattern,
    pin: state.pin
  });
  if (!response.success) {
    alert(response.error || "No se pudo eliminar.");
    return;
  }
  state.rules = response.data.rules;
  await loadMeta();
  renderRules();
}

async function onToggleAllowOnly() {
  const next = !state.meta?.allowOnlyMode;
  const response = await send({
    type: "toggleAllowOnly",
    enabled: next,
    pin: state.pin
  });
  if (!response.success) {
    alert(response.error || "No se pudo actualizar el modo.");
    return;
  }
  state.meta.allowOnlyMode = response.data.allowOnlyMode.enabled;
  renderMeta();
}

async function onExport() {
  const response = await send({ type: "exportConfig", pin: state.pin });
  if (!response.success) {
    exportFeedback.textContent = response.error || "No se pudo exportar.";
    return;
  }
  const payload = JSON.stringify(response.data, null, 2);
  const blob = new Blob([payload], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  const date = new Date().toISOString().replace(/[:.]/g, "-");
  link.download = `control-parental-${date}.json`;
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
  exportFeedback.textContent = "Archivo exportado. Copia el JSON al otro equipo.";
}

async function onImport() {
  const file = importInput.files?.[0];
  if (!file) {
    importFeedback.textContent = "Selecciona un archivo.";
    return;
  }
  const text = await file.text();
  const response = await send({ type: "importConfig", payload: text, pin: state.pin });
  if (!response.success) {
    importFeedback.textContent = response.error || "Error al importar.";
    return;
  }
  if (response.data?.stale) {
    const confirmOverwrite = window.confirm(
      `El archivo es más antiguo (${response.data.lastUpdated}). ¿Deseas sobrescribir igualmente?`
    );
    if (!confirmOverwrite) {
      importFeedback.textContent = "Importación cancelada.";
      return;
    }
    const forced = await send({ type: "importConfig", payload: text, force: true, pin: state.pin });
    if (!forced.success) {
      importFeedback.textContent = forced.error || "No se pudo sobrescribir.";
      return;
    }
  }
  importFeedback.textContent = "Configuración importada.";
  await loadMeta();
  await loadRules();
}

loginPinInput?.addEventListener("keypress", event => {
  if (event.key === "Enter") {
    event.preventDefault();
    onLogin();
  }
});

function send(payload) {
  return new Promise(resolve => {
    api.runtime.sendMessage(payload, resolve);
  });
}
