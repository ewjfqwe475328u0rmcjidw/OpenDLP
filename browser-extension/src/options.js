// Leakwarden browser extension - options page - GPL-3.0-only
async function refresh() {
  const s = await chrome.runtime.sendMessage({ type: "status" });
  const c = s.config || {};
  document.getElementById("managed").hidden = !c.managed;
  for (const id of ["serverUrl", "enrollmentCode"]) {
    const el = document.getElementById(id);
    el.value = id === "serverUrl" ? c.serverUrl || "" : c.enrollmentCode ? "********" : "";
    el.disabled = !!c.managed;
  }
  document.getElementById("save").disabled = !!c.managed;
  const pv = s.policy ? " · policy v" + s.policy.version + " · mode " + ((s.policy.browser || {}).mode || "audit") : "";
  document.getElementById("status").textContent = (s.status || "Not connected") + pv + " · id " + (c.agentId || "");
}
document.getElementById("save").addEventListener("click", async () => {
  const serverUrl = document.getElementById("serverUrl").value.trim();
  const code = document.getElementById("enrollmentCode").value;
  const set = { serverUrl };
  if (code && code !== "********") set.enrollmentCode = code;
  await chrome.storage.local.set(set);
  await chrome.runtime.sendMessage({ type: "sync" });
  refresh();
});
refresh();
