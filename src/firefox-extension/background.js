const api = typeof browser !== "undefined" ? browser : chrome;
const actionApi = api.action || api.browserAction;
const STORAGE_KEY = "parentalConfig";
const SCHEMA_VERSION = 1;
const ALLOWED_PROTOCOLS = ["http:", "https:"];

let cachedConfig = null;
let initializing = false;

const DEFAULT_CONFIG = Object.freeze({
  schemaVersion: SCHEMA_VERSION,
  lastUpdated: nowIso(),
  adminPin: null,
  rules: {
    allowedUrls: [],
    blockedUrls: []
  },
  allowOnlyMode: {
    enabled: false,
    toggledAt: null
  }
});

init();

function init() {
  ensureConfig();
  api.webRequest.onBeforeRequest.addListener(
    details => handleRequest(details),
    { urls: ["http://*/*", "https://*/*"], types: ["main_frame", "sub_frame"] },
    ["blocking"]
  );
  if (api.webNavigation?.onBeforeNavigate) {
    api.webNavigation.onBeforeNavigate.addListener(
      details => handleNavigation(details),
      { url: [{ schemes: ["http", "https"] }] }
    );
  }
  api.runtime.onMessage.addListener((message, sender, sendResponse) => {
    handleMessage(message)
      .then(response => sendResponse(response))
      .catch(error => {
        console.error("Message error", error);
        sendResponse({ success: false, error: error.message || String(error) });
      });
    return true;
  });
}

async function ensureConfig() {
  if (cachedConfig || initializing) {
    return cachedConfig;
  }
  initializing = true;
  const stored = await storageGet(STORAGE_KEY);
  if (stored && stored[STORAGE_KEY]) {
    cachedConfig = migrateConfig(stored[STORAGE_KEY]);
  } else {
    cachedConfig = clone(DEFAULT_CONFIG);
    await storageSet({ [STORAGE_KEY]: cachedConfig });
  }
  initializing = false;
  await refreshBadge();
  return cachedConfig;
}

function migrateConfig(raw) {
  const config = Object.assign(clone(DEFAULT_CONFIG), raw);
  config.schemaVersion = SCHEMA_VERSION;
  if (!config.rules) {
    config.rules = { allowedUrls: [], blockedUrls: [] };
  }
  if (!config.allowOnlyMode) {
    config.allowOnlyMode = { enabled: false, toggledAt: null };
  }
  return config;
}

async function saveConfig(nextConfig) {
  cachedConfig = nextConfig;
  await storageSet({ [STORAGE_KEY]: nextConfig });
  await refreshBadge();
}

async function refreshBadge() {
  if (!actionApi) {
    return;
  }
  if (!cachedConfig || !cachedConfig.allowOnlyMode?.enabled) {
    await setBadgeText("");
    return;
  }
  await setBadgeText("ON");
  await setBadgeColor("#d93025");
}

function setBadgeText(text) {
  if (!actionApi?.setBadgeText) {
    return Promise.resolve();
  }
  return new Promise(resolve => {
    actionApi.setBadgeText({ text }, () => resolve());
  });
}

function setBadgeColor(color) {
  if (!actionApi.setBadgeBackgroundColor) {
    return Promise.resolve();
  }
  return new Promise(resolve => {
    actionApi.setBadgeBackgroundColor({ color }, () => resolve());
  });
}

function matchesPattern(pattern, urlString) {
  let url;
  try {
    url = new URL(urlString);
    if (!ALLOWED_PROTOCOLS.includes(url.protocol)) {
      return false;
    }
  } catch (_) {
    return false;
  }
  const trimmedPattern = pattern.trim();
  if (!trimmedPattern.includes("://")) {
    return hostMatchesPattern(trimmedPattern, url.host);
  }
  const regex = patternToRegex(trimmedPattern);
  return regex.test(urlString);
}

function hostMatchesPattern(pattern, host) {
  const hostLower = host.toLowerCase();
  const patternLower = pattern.toLowerCase();
  if (patternLower.startsWith("*.") && !patternLower.includes("://")) {
    const suffix = patternLower.slice(2);
    return hostLower === suffix || hostLower.endsWith(`.${suffix}`);
  }
  if (!patternLower.includes("*")) {
    return hostLower === patternLower || hostLower.endsWith(`.${patternLower}`);
  }
  const regex = patternToRegex(patternLower);
  return regex.test(hostLower);
}

function patternToRegex(pattern) {
  const segments = pattern.split("*").map(segment => segment.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  const rebuilt = segments.join(".*");
  return new RegExp(`^${rebuilt}$`, "i");
}

function decideAccess(url) {
  if (!cachedConfig) {
    return { block: false };
  }
  const allowedList = cachedConfig.rules.allowedUrls || [];
  const blockedList = cachedConfig.rules.blockedUrls || [];
  const allowMatch = allowedList.some(rule => matchesPattern(rule.pattern, url));
  const blockMatch = blockedList.some(rule => matchesPattern(rule.pattern, url));

  if (cachedConfig.allowOnlyMode?.enabled) {
    return allowMatch ? { block: false } : { block: true, reason: "allowOnly" };
  }
  if (allowMatch) {
    return { block: false };
  }
  if (blockMatch) {
    return { block: true, reason: "blocklist" };
  }
  return { block: false };
}

function handleRequest(details) {
  if (!cachedConfig) {
    return {};
  }
  const decision = decideAccess(details.url);
  if (!decision.block) {
    return {};
  }
  const redirectUrl = api.runtime.getURL(
    `blocked.html?reason=${encodeURIComponent(decision.reason)}&target=${encodeURIComponent(details.url)}`
  );
  return { redirectUrl };
}

function handleNavigation(details) {
  if (details.frameId !== 0) {
    return;
  }
  if (details.url.startsWith(api.runtime.getURL(""))) {
    return;
  }
  ensureConfig().then(() => {
    if (!cachedConfig) {
      return;
    }
    const decision = decideAccess(details.url);
    if (!decision.block) {
      return;
    }
    const redirectUrl = api.runtime.getURL(
      `blocked.html?reason=${encodeURIComponent(decision.reason)}&target=${encodeURIComponent(details.url)}`
    );
    api.tabs.update(details.tabId, { url: redirectUrl });
  });
}

async function handleMessage(message) {
  await ensureConfig();
  const type = message?.type;
  switch (type) {
    case "getMeta":
      return { success: true, data: buildMeta() };
    case "setupPin":
      return { success: true, data: await setupPin(message.pin, message.hint) };
    case "verifyPin":
      return { success: true, data: await verifyPin(message.pin) };
    case "listRules":
      await ensureAuthorized(message.pin);
      return { success: true, data: { rules: cachedConfig.rules } };
    case "addRule":
      await ensureAuthorized(message.pin);
      return { success: true, data: await addRule(message.listType, message.pattern, message.notes) };
    case "removeRule":
      await ensureAuthorized(message.pin);
      return { success: true, data: await removeRule(message.listType, message.pattern) };
    case "toggleAllowOnly":
      await ensureAuthorized(message.pin);
      return { success: true, data: await toggleAllowOnly(message.enabled) };
    case "exportConfig":
      await ensureAuthorized(message.pin);
      return { success: true, data: exportConfig() };
    case "importConfig":
      await ensureAuthorized(message.pin);
      return { success: true, data: await importConfig(message.payload, message.force) };
    default:
      return { success: false, error: "Operación no soportada" };
  }
}

function buildMeta() {
  return {
    hasPin: Boolean(cachedConfig?.adminPin?.hash),
    allowOnlyMode: cachedConfig?.allowOnlyMode?.enabled || false,
    lastUpdated: cachedConfig?.lastUpdated,
    allowedCount: cachedConfig?.rules?.allowedUrls?.length || 0,
    blockedCount: cachedConfig?.rules?.blockedUrls?.length || 0
  };
}

async function setupPin(pin, hint) {
  if (!pin || pin.length < 4) {
    throw new Error("El PIN debe tener al menos 4 dígitos.");
  }
  if (cachedConfig?.adminPin?.hash) {
    throw new Error("El PIN ya está configurado.");
  }
  const salt = generateSalt();
  const hash = await hashPin(pin, salt);
  const next = clone(cachedConfig);
  next.adminPin = { hash, salt, hint: hint || null };
  next.lastUpdated = nowIso();
  await saveConfig(next);
  return buildMeta();
}

async function verifyPin(pin) {
  if (!cachedConfig?.adminPin?.hash) {
    return { valid: true, needsPin: false };
  }
  const valid = await comparePin(pin);
  return { valid, needsPin: true };
}

async function ensureAuthorized(pin) {
  if (!cachedConfig?.adminPin?.hash) {
    return;
  }
  const ok = await comparePin(pin);
  if (!ok) {
    throw new Error("PIN incorrecto.");
  }
}

async function comparePin(pin) {
  if (!pin) {
    return false;
  }
  const { hash, salt } = cachedConfig.adminPin;
  const computed = await hashPin(pin, salt);
  return computed === hash;
}

async function addRule(listType, rawPattern, notes) {
  const pattern = sanitizePattern(rawPattern);
  const targetList = getListByType(listType);
  if (targetList.some(entry => entry.pattern === pattern)) {
    throw new Error("El patrón ya existe en la lista.");
  }
  targetList.push({ pattern, notes: notes || null, createdAt: nowIso() });
  await persistCurrent();
  return { rules: cachedConfig.rules };
}

async function removeRule(listType, rawPattern) {
  const pattern = sanitizePattern(rawPattern);
  const targetList = getListByType(listType);
  const nextList = targetList.filter(entry => entry.pattern !== pattern);
  if (nextList.length === targetList.length) {
    throw new Error("Patrón no encontrado.");
  }
  if (listType === "allowed") {
    cachedConfig.rules.allowedUrls = nextList;
  } else {
    cachedConfig.rules.blockedUrls = nextList;
  }
  await persistCurrent();
  return { rules: cachedConfig.rules };
}

async function toggleAllowOnly(enabled) {
  const next = !!enabled;
  cachedConfig.allowOnlyMode = { enabled: next, toggledAt: nowIso() };
  await persistCurrent();
  return { allowOnlyMode: cachedConfig.allowOnlyMode };
}

function exportConfig() {
  return clone(cachedConfig);
}

async function importConfig(payload, force) {
  if (!payload) {
    throw new Error("Archivo vacío.");
  }
  let parsed;
  try {
    parsed = typeof payload === "string" ? JSON.parse(payload) : payload;
  } catch (_) {
    throw new Error("El archivo no es JSON válido.");
  }
  if (parsed.schemaVersion !== SCHEMA_VERSION) {
    throw new Error("Versión de esquema incompatible.");
  }
  const incomingDate = Date.parse(parsed.lastUpdated || "");
  const currentDate = Date.parse(cachedConfig.lastUpdated || "");
  if (!force && currentDate && incomingDate && incomingDate < currentDate) {
    return { stale: true, lastUpdated: parsed.lastUpdated };
  }
  const next = migrateConfig(parsed);
  next.lastUpdated = nowIso();
  await saveConfig(next);
  return { replaced: true };
}

function sanitizePattern(pattern) {
  if (!pattern) {
    throw new Error("El patrón no puede estar vacío.");
  }
  return pattern.trim();
}

function getListByType(listType) {
  if (listType === "allowed") {
    return cachedConfig.rules.allowedUrls;
  }
  if (listType === "blocked") {
    return cachedConfig.rules.blockedUrls;
  }
  throw new Error("Tipo de lista no válido.");
}

async function persistCurrent() {
  cachedConfig.lastUpdated = nowIso();
  await saveConfig(cachedConfig);
}

function generateSalt() {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToBase64(bytes);
}

async function hashPin(pin, saltBase64) {
  const salt = base64ToBytes(saltBase64);
  const pinBytes = new TextEncoder().encode(pin);
  const combined = new Uint8Array(salt.length + pinBytes.length);
  combined.set(salt, 0);
  combined.set(pinBytes, salt.length);
  const digest = await crypto.subtle.digest("SHA-256", combined);
  return bytesToBase64(new Uint8Array(digest));
}

function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach(b => {
    binary += String.fromCharCode(b);
  });
  return btoa(binary);
}

function base64ToBytes(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function nowIso() {
  return new Date().toISOString();
}

function clone(source) {
  if (typeof structuredClone === "function") {
    return structuredClone(source);
  }
  return JSON.parse(JSON.stringify(source));
}

function storageGet(key) {
  try {
    const maybePromise = api.storage.local.get(key);
    if (maybePromise && typeof maybePromise.then === "function") {
      return maybePromise;
    }
  } catch (_) {
    // fallback to callback style below
  }
  return new Promise((resolve, reject) => {
    api.storage.local.get(key, result => {
      const error = api.runtime?.lastError;
      if (error) {
        reject(new Error(error.message));
      } else {
        resolve(result);
      }
    });
  });
}

function storageSet(payload) {
  try {
    const maybePromise = api.storage.local.set(payload);
    if (maybePromise && typeof maybePromise.then === "function") {
      return maybePromise;
    }
  } catch (_) {
    // fallback
  }
  return new Promise((resolve, reject) => {
    api.storage.local.set(payload, () => {
      const error = api.runtime?.lastError;
      if (error) {
        reject(new Error(error.message));
      } else {
        resolve();
      }
    });
  });
}
