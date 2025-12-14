const params = new URLSearchParams(window.location.search);
const reason = params.get("reason") || "blocklist";
const target = params.get("target") || "";

const reasonText = document.getElementById("reasonText");
const urlText = document.getElementById("urlText");

const reasonMap = {
  allowOnly: "El modo solo permitidos está activo y esta URL no figura en la lista.",
  blocklist: "Esta URL está bloqueada por las reglas configuradas."
};

reasonText.textContent = reasonMap[reason] || reasonMap.blocklist;
urlText.textContent = decodeURIComponent(target);
