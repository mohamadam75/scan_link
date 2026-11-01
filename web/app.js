const RAW = "https://raw.githubusercontent.com/mohamadam75/scan_link/main";
const OPERATORS = {
  "hamrah-aval": { label: "همراه اول", file: "hamrah-aval.txt", aliases: ["hamrah aval","hamrahe aval","mci","mobile communication company of iran","tci mobile","همراه اول"] },
  "irancell": { label: "ایرانسل", file: "irancell.txt", aliases: ["irancell","mtn irancell","mtn","ایرانسل"] },
  "mokhaberat": { label: "مخابرات", file: "mokhaberat.txt", aliases: ["mokhaberat","telecommunication company of iran","telecommunications company of iran","tci","مخابرات"] }
};
let selected = "hamrah-aval";
let currentConfigs = [];
let toastTimer;
const $ = id => document.getElementById(id);
function notify(message) {
  const el = $("toast"); el.textContent = message; el.classList.add("show");
  clearTimeout(toastTimer); toastTimer = setTimeout(() => el.classList.remove("show"), 2300);
}
function setSelected(id) {
  if (!OPERATORS[id]) return;
  selected = id;
  document.querySelectorAll(".operator-button").forEach(btn => btn.classList.toggle("active", btn.dataset.operator === id));
  $("list-title").textContent = "کانفیگ‌های " + OPERATORS[id].label;
  loadConfigs();
}
function matchOperator(isp) {
  const normalized = String(isp || "").toLowerCase();
  for (const [id, item] of Object.entries(OPERATORS)) {
    if (item.aliases.some(alias => normalized.includes(alias))) return id;
  }
  return null;
}
async function detectOperator() {
  $("detected-name").textContent = "در حال بررسی شبکه…";
  $("detect-detail").textContent = "در حال دریافت نام ارائه‌دهنده اینترنت";
  $("retry-detect").disabled = true;
  try {
    const response = await fetch("https://ipwho.is/?fields=success,connection", { cache: "no-store", signal: AbortSignal.timeout(7000) });
    if (!response.ok) throw new Error("lookup failed");
    const data = await response.json();
    if (!data.success) throw new Error("lookup unavailable");
    const isp = data.connection?.isp || data.connection?.org || "";
    const found = matchOperator(isp);
    if (found) {
      $("detected-name").textContent = OPERATORS[found].label;
      $("detect-detail").textContent = "بر اساس نام ISP: " + isp;
      setSelected(found);
    } else {
      $("detected-name").textContent = "اپراتور به‌طور قطعی شناسایی نشد";
      $("detect-detail").textContent = isp ? "ارائه‌دهنده گزارش‌شده: " + isp + " — لطفاً دستی انتخاب کن." : "لطفاً اپراتورت را دستی انتخاب کن.";
    }
  } catch (_) {
    $("detected-name").textContent = "تشخیص خودکار در دسترس نیست";
    $("detect-detail").textContent = "ممکن است سرویس تشخیص پاسخ ندهد یا VPN فعال باشد؛ اپراتور را دستی انتخاب کن.";
  } finally { $("retry-detect").disabled = false; }
}
function parseConfigs(text) {
  return text.split(/\r?\n/).map(line => line.trim()).filter(line => line && !line.startsWith("#"));
}
function protocolOf(config) {
  const scheme = config.split("://", 1)[0].toUpperCase();
  return ["VLESS","VMESS","TROJAN","SS","SOCKS","HTTP"].includes(scheme) ? scheme : "CONFIG";
}
async function loadConfigs() {
  $("loading").hidden = false; $("loading").textContent = "در حال دریافت فهرست…";
  $("config-list").replaceChildren();
  $("config-count").textContent = "…";
  $("copy-all").disabled = true; $("download-all").disabled = true;
  try {
    const response = await fetch(RAW + "/configs/" + OPERATORS[selected].file, { cache: "no-store" });
    if (!response.ok) throw new Error("config file unavailable");
    currentConfigs = parseConfigs(await response.text());
    $("config-count").textContent = currentConfigs.length + " کانفیگ";
    $("loading").hidden = currentConfigs.length > 0;
    if (!currentConfigs.length) $("loading").textContent = "فعلاً کانفیگی برای نمایش وجود ندارد.";
    currentConfigs.forEach((config, index) => {
      const card = document.createElement("article"); card.className = "config-card";
      const top = document.createElement("div"); top.className = "config-top";
      const type = document.createElement("span"); type.className = "config-type"; type.textContent = protocolOf(config);
      const number = document.createElement("span"); number.className = "config-index"; number.textContent = "شماره " + (index + 1);
      top.append(type, number);
      const value = document.createElement("div"); value.className = "config-value"; value.textContent = config;
      const bottom = document.createElement("div"); bottom.className = "config-bottom";
      const note = document.createElement("small"); note.textContent = "کانفیگ عمومی · تست اپراتوری نشده";
      const copy = document.createElement("button"); copy.className = "copy-one"; copy.type = "button"; copy.textContent = "کپی کانفیگ";
      copy.addEventListener("click", () => copyText(config));
      bottom.append(note, copy); card.append(top, value, bottom); $("config-list").append(card);
    });
    $("copy-all").disabled = !currentConfigs.length; $("download-all").disabled = !currentConfigs.length;
  } catch (_) {
    currentConfigs = []; $("loading").hidden = false;
    $("loading").textContent = "دریافت فایل ناموفق بود. اتصال اینترنت را بررسی و دوباره تلاش کن.";
    $("config-count").textContent = "۰ کانفیگ";
  }
}
async function copyText(value) {
  try {
    await navigator.clipboard.writeText(value);
    notify("کانفیگ کپی شد");
  } catch (_) {
    const area = document.createElement("textarea"); area.value = value;
    document.body.append(area); area.select();
    const ok = document.execCommand("copy"); area.remove();
    notify(ok ? "کپی شد" : "کپی خودکار ممکن نشد");
  }
}
function downloadConfigs() {
  const blob = new Blob([currentConfigs.join("\n") + "\n"], {type:"text/plain;charset=utf-8"});
  const url = URL.createObjectURL(blob); const link = document.createElement("a");
  link.href = url; link.download = "scan-link-" + selected + ".txt"; link.click(); URL.revokeObjectURL(url);
}
async function loadStats() {
  try {
    const response = await fetch(RAW + "/reports/latest.json", {cache:"no-store"});
    if (!response.ok) throw new Error("report unavailable");
    const data = await response.json();
    $("stat-total").textContent = Number(data.unique_configs_found || 0).toLocaleString("fa-IR");
    $("stat-tested").textContent = Number(data.candidate_configs_tested || 0).toLocaleString("fa-IR");
    $("stat-working").textContent = Number(data.tunnel_success_count || 0).toLocaleString("fa-IR");
    $("stat-updated").textContent = data.generated_at_utc ? new Date(data.generated_at_utc).toLocaleString("fa-IR",{dateStyle:"short",timeStyle:"short",timeZone:"Asia/Tehran"}) : "—";
  } catch (_) { /* dashboard remains usable when report is unavailable */ }
}
document.querySelectorAll(".operator-button").forEach(btn => btn.addEventListener("click", () => setSelected(btn.dataset.operator)));
$("retry-detect").addEventListener("click", detectOperator);
$("copy-all").addEventListener("click", () => copyText(currentConfigs.join("\n")));
$("download-all").addEventListener("click", downloadConfigs);
setSelected(selected);
loadStats();
detectOperator();