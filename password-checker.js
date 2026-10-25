const $ = (id) => document.getElementById(id);
const form = $("passwordForm"), passwordInput = $("password"), showButton = $("showButton");
const checkButton = $("checkButton"), clearButton = $("clearButton"), meterFill = $("meterFill");
const strengthLabel = $("strengthLabel"), strengthMessage = $("strengthMessage"), resultBox = $("result");
const intelForm = $("intelForm"), indicatorInput = $("indicator"), lookupButton = $("lookupButton");
const intelResult = $("intelResult"), historyList = $("historyList");
const history = [];

document.querySelectorAll(".tab").forEach(button => button.addEventListener("click", () => {
  document.querySelectorAll(".tab").forEach(tab => tab.classList.toggle("active", tab === button));
  document.querySelectorAll(".panel").forEach(panel => panel.classList.toggle("hidden", panel.id !== button.dataset.tab));
}));

showButton.addEventListener("click", () => {
  const hidden = passwordInput.type === "password";
  passwordInput.type = hidden ? "text" : "password";
  showButton.textContent = hidden ? "Hide" : "Show";
});
passwordInput.addEventListener("input", () => { showStrength(passwordInput.value); hideResult(); });

function showStrength(password) {
  if (!password) return updateMeter(0, "Waiting", "Type a password to start the local strength check.");
  let score = 0;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  if (/password|qwerty|123456|admin|welcome|letmein/i.test(password)) score = Math.min(score, 1);
  const label = score <= 1 ? "Weak" : score <= 2 ? "Fair" : score <= 3 ? "Good" : "Strong";
  const message = score <= 1 ? "Try a longer, unique passphrase; avoid common words and patterns." :
    score <= 2 ? "Add length and avoid predictable substitutions or personal information." :
    score <= 3 ? "A reasonable estimate, but check breach exposure and uniqueness." :
    "Good estimated strength. Length and uniqueness still matter.";
  updateMeter(score, label, message);
}
function updateMeter(score, label, message) {
  const widths = ["0%", "20%", "40%", "60%", "80%", "100%"];
  const colors = ["transparent", "#ff7888", "#ffc56b", "#74a7ff", "#63e6d0", "#63e6d0"];
  meterFill.style.width = widths[score]; meterFill.style.backgroundColor = colors[score];
  strengthLabel.textContent = label; strengthMessage.textContent = message;
}
form.addEventListener("submit", async event => {
  event.preventDefault();
  const original = passwordInput.value;
  if (!original) return showResult("error", "Enter a password first.");
  checkButton.disabled = true; checkButton.textContent = "Checking…"; hideResult();
  try {
    const hash = await createSha1(original);
    const prefix = hash.slice(0, 5), suffix = hash.slice(5);
    // Clear the password field after the hash is computed; the raw password is never sent.
    passwordInput.value = "";
    showStrength("");
    const response = await fetch("https://api.pwnedpasswords.com/range/" + prefix, {headers: {"Add-Padding":"true"}});
    if (!response.ok) throw new Error("Breach service unavailable");
    const lines = (await response.text()).split(/\r?\n/);
    let count = 0;
    for (const line of lines) {
      const [candidate, occurrences] = line.trim().split(":");
      if (candidate === suffix) { count = Number(occurrences) || 0; break; }
    }
    showResult(count > 0 ? "found" : "safe", count > 0
      ? `This password hash appears ${count.toLocaleString("en-IN")} times in known breach data. Do not use it.`
      : "No match was found in this dataset. This does not guarantee the password is secure or unique.");
  } catch {
    passwordInput.value = "";
    showResult("error", "Could not reach the breach service. Try again later.");
  } finally {
    checkButton.disabled = false; checkButton.textContent = "Check breach exposure";
  }
});
async function createSha1(value) {
  const bytes = new TextEncoder().encode(value);
  const digest = await crypto.subtle.digest("SHA-1", bytes);
  bytes.fill(0);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2,"0")).join("").toUpperCase();
}
clearButton.addEventListener("click", () => {
  passwordInput.value = ""; passwordInput.type = "password"; showButton.textContent = "Show";
  updateMeter(0, "Waiting", "Type a password to start the local strength check."); hideResult(); passwordInput.focus();
});
function showResult(type, message) { resultBox.className = "result show " + type; resultBox.textContent = message; }
function hideResult() { resultBox.className = "result"; resultBox.textContent = ""; }

intelForm.addEventListener("submit", async event => {
  event.preventDefault();
  const indicator = indicatorInput.value.trim();
  if (!indicator) return;
  lookupButton.disabled = true; lookupButton.textContent = "Investigating…";
  intelResult.innerHTML = '<div class="intel-card"><p class="muted">Querying configured providers. This can take a few seconds…</p></div>';
  try {
    const response = await fetch("http://127.0.0.1:8000/api/lookup", {
      method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({indicator})
    });
    const data = await response.json().catch(() => ({}));
    if (!response.ok) throw new Error(data.detail || "Lookup failed. Is the backend running?");
    renderIntel(data);
    addHistory({indicator:data.indicator, type:data.type, risk:data.risk, time:new Date().toLocaleTimeString()});
  } catch (error) {
    intelResult.innerHTML = "";
    const card = document.createElement("div"); card.className = "intel-card";
    const title = document.createElement("h3"); title.textContent = "Lookup unavailable";
    const p = document.createElement("p"); p.className = "notice";
    p.textContent = error.message + " Start the backend and configure provider API keys in backend/.env. No sample detection has been substituted.";
    card.append(title,p); intelResult.append(card);
  } finally { lookupButton.disabled = false; lookupButton.textContent = "Investigate"; }
});

function renderIntel(data) {
  intelResult.innerHTML = "";
  const card = document.createElement("div"); card.className = "intel-card";
  const top = document.createElement("div"); top.className = "intel-top";
  const titleBox = document.createElement("div");
  const title = document.createElement("h3"); title.textContent = data.indicator;
  const type = document.createElement("div"); type.className = "type-label"; type.textContent = `${data.type} · ${data.sources.length} source(s)`;
  titleBox.append(title,type);
  const risk = document.createElement("span"); risk.className = "risk " + (data.risk || "unknown").toLowerCase(); risk.textContent = `${data.risk || "UNKNOWN"} RISK`;
  top.append(titleBox,risk); card.append(top);
  const grid = document.createElement("div"); grid.className = "source-grid";
  data.sources.forEach(source => {
    const box = document.createElement("div"); box.className = "source-card";
    const h = document.createElement("h4"); h.textContent = source.name + " · " + source.status;
    const p = document.createElement("p"); p.textContent = source.summary || "No provider summary returned.";
    box.append(h,p); grid.append(box);
  });
  card.append(grid);
  const evidenceTitle = document.createElement("div"); evidenceTitle.className = "evidence-title"; evidenceTitle.textContent = "Evidence & interpretation";
  card.append(evidenceTitle);
  const list = document.createElement("ul"); list.className = "evidence";
  (data.evidence || []).forEach(item => { const li = document.createElement("li"); li.textContent = item; list.append(li); });
  if (!list.children.length) { const li = document.createElement("li"); li.textContent = "No usable evidence returned. Risk is unknown, not confirmed safe."; list.append(li); }
  card.append(list);
  const note = document.createElement("p"); note.className = "notice"; note.textContent = data.note || "Results reflect the providers and time of this lookup. A clean result is not a guarantee of safety.";
  card.append(note); intelResult.append(card);
}
function addHistory(item) {
  history.unshift(item); history.splice(10);
  historyList.innerHTML = "";
  history.forEach(entry => {
    const row = document.createElement("div"); row.className = "history-item";
    const name = document.createElement("strong"); name.textContent = entry.indicator;
    const meta = document.createElement("span"); meta.textContent = `${entry.type} · ${entry.risk} · ${entry.time}`;
    row.append(name,meta); historyList.append(row);
  });
}
$("clearHistory").addEventListener("click", () => { history.length = 0; historyList.innerHTML = '<p class="muted">Your recent lookups will appear here during this session.</p>'; });
