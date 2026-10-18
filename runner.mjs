import { createRequire as __cr } from 'node:module'; const require = __cr(import.meta.url);
var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __esm = (fn, res) => function __init() {
  return fn && (res = (0, fn[__getOwnPropNames(fn)[0]])(fn = 0)), res;
};
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};

// src/ssrf.js
import dns from "node:dns/promises";
import net from "node:net";
function isPrivateIp(ip) {
  const version = net.isIP(ip);
  if (version === 4) {
    const [a, b] = ip.split(".").map(Number);
    return a === 0 || a === 10 || a === 127 || a === 169 && b === 254 || a === 172 && b >= 16 && b <= 31 || a === 192 && b === 168 || a === 100 && b >= 64 && b <= 127 || a >= 224;
  }
  if (version === 6) {
    const normalized = ip.toLowerCase().split("%")[0];
    if (normalized.startsWith("::ffff:")) return isPrivateIp(normalized.slice(7));
    return normalized === "::" || normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd") || /^fe[89ab]/.test(normalized);
  }
  return true;
}
async function assertPublicUrl(input, { allowLocal = false, lookup = dns.lookup } = {}) {
  let url;
  try {
    url = new URL(input);
  } catch {
    throw ssrfError("URL invalide");
  }
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw ssrfError("URL non autoris\xE9e");
  if (allowLocal && ["localhost", "127.0.0.1", "::1", "[::1]"].includes(url.hostname)) return url;
  if (net.isIP(url.hostname) && isPrivateIp(url.hostname)) throw ssrfError();
  let addresses;
  try {
    addresses = net.isIP(url.hostname) ? [{ address: url.hostname }] : await lookup(url.hostname, { all: true, verbatim: true });
  } catch {
    throw ssrfError("R\xE9solution DNS impossible");
  }
  if (!addresses.length || addresses.some(({ address }) => isPrivateIp(address))) throw ssrfError();
  return url;
}
async function guardPageRequests(page, options = {}) {
  await page.route("**/*", async (route) => {
    try {
      await assertPublicUrl(route.request().url(), options);
      await route.continue();
    } catch {
      await route.abort("blockedbyclient").catch(() => {
      });
    }
  });
}
function ssrfError(message = "Adresse r\xE9seau priv\xE9e refus\xE9e") {
  return Object.assign(new Error(message), { code: "ssrf" });
}
var init_ssrf = __esm({
  "src/ssrf.js"() {
  }
});

// src/log.js
function createLogger({ write = (line) => process.stdout.write(`${line}
`), now = () => /* @__PURE__ */ new Date() } = {}) {
  return Object.freeze({
    log(level, event, fields = {}) {
      if (!LEVELS.has(level)) throw new TypeError("Niveau de journal invalide");
      if (typeof event !== "string" || !/^[a-z][a-z0-9_.-]{0,63}$/.test(event)) {
        throw new TypeError("\xC9v\xE9nement de journal invalide");
      }
      const record = { timestamp: now().toISOString(), level, event };
      for (const [key, value] of Object.entries(fields)) {
        if (!SAFE_FIELDS.has(key)) continue;
        if (key === "region" && (value === "fr" || value === "us")) record[key] = value;
        else if (key === "status" && ["done", "failed", "refused"].includes(value)) record[key] = value;
        else if (key === "errorCode" && typeof value === "string" && /^[a-z0-9_-]{1,40}$/i.test(value)) record[key] = value;
        else if (["durationMs", "attempt"].includes(key) && typeof value === "number" && Number.isFinite(value) && value >= 0) record[key] = value;
      }
      write(JSON.stringify(record));
    }
  });
}
var SAFE_FIELDS, LEVELS, logger;
var init_log = __esm({
  "src/log.js"() {
    SAFE_FIELDS = /* @__PURE__ */ new Set(["status", "region", "durationMs", "attempt", "errorCode"]);
    LEVELS = /* @__PURE__ */ new Set(["info", "warn", "error"]);
    logger = createLogger();
  }
});

// src/fc-worker.js
var fc_worker_exports = {};
__export(fc_worker_exports, {
  collectFc: () => collectFc,
  createFcClient: () => createFcClient,
  runFcWorker: () => runFcWorker
});
import { createHash as createHash2 } from "node:crypto";
async function collectFc(browser, url, { allowLocal = false } = {}) {
  await assertPublicUrl(url, { allowLocal });
  const context = await browser.newContext(US ? { locale: "en-US", timezoneId: "America/New_York" } : { locale: "fr-FR", timezoneId: "Europe/Paris" });
  try {
    const page = await context.newPage();
    await guardPageRequests(page, { allowLocal });
    const hosts = {};
    let requests = 0;
    page.on("request", (request) => {
      requests++;
      try {
        const h = new URL(request.url()).hostname.toLowerCase();
        if (h) hosts[h] = (hosts[h] || 0) + 1;
      } catch {
      }
    });
    await page.goto(url, { waitUntil: "load", timeout: 45e3 });
    await page.waitForTimeout(WAIT_MS);
    const storage = await page.evaluate(() => {
      try {
        return { local: localStorage.length, session: sessionStorage.length };
      } catch {
        return { local: 0, session: 0 };
      }
    }).catch(() => ({ local: 0, session: 0 }));
    const cookies = (await context.cookies()).map((c) => ({ name: c.name, domain: c.domain, expires: c.expires, httpOnly: c.httpOnly, secure: c.secure, sameSite: c.sameSite }));
    return { url, finalUrl: page.url(), region: REGION2, cookies, hosts, requests, storage };
  } finally {
    await context.close().catch(() => {
    });
  }
}
function createFcClient({ baseUrl = process.env.FC_BASE_URL || "https://f-cookies.org", key = process.env.FC_INGEST_KEY || "", fetchImpl = fetch, auth = process.env.FC_AUTH || "key" } = {}) {
  const oidc = auth === "oidc";
  const endpoint = new URL(oidc ? "/ingest" : "/ingest.php", baseUrl).href;
  let token = null, tokenAt = 0;
  const oidcToken = async () => {
    if (token && Date.now() - tokenAt < 24e4) return token;
    const response = await fetchImpl(`${process.env.ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${encodeURIComponent(new URL(baseUrl).origin)}`, { headers: { Authorization: `Bearer ${process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` }, signal: AbortSignal.timeout(2e4) });
    if (!response.ok) throw new Error(`OIDC HTTP ${response.status}`);
    token = (await response.json()).value;
    tokenAt = Date.now();
    return token;
  };
  const call = async (url, init = {}) => {
    const headers = oidc ? { "X-OC-OIDC": await oidcToken() } : { "X-FC-Key": key };
    const response = await fetchImpl(url, { ...init, headers: { ...headers, ...init.headers }, signal: AbortSignal.timeout(2e4) });
    if (!response.ok && response.status !== 422) throw new Error(`F-Cookies HTTP ${response.status}`);
    return response.json();
  };
  const putChunks = async (payload) => {
    const encoded = b64url2(Buffer.from(JSON.stringify(payload))), id = createHash2("sha256").update(String(payload.url)).digest("hex").slice(0, 24), parts = [];
    for (let i = 0; i < encoded.length; i += 4e3) parts.push(encoded.slice(i, i + 4e3));
    let last = null;
    for (let i = 0; i < parts.length; i++) {
      for (let attempt = 0; ; attempt++) {
        try {
          last = await call(`${endpoint}?put=1&id=${id}&i=${i}&n=${parts.length}&d=${parts[i]}`);
          break;
        } catch (error) {
          if (attempt >= 3) throw error;
          await new Promise((r) => setTimeout(r, 500 * (attempt + 1)));
        }
      }
    }
    return last;
  };
  return {
    async queue() {
      const data = await call(`${endpoint}?queue=${US ? "us" : "fr"}`);
      return data?.ok ? data.urls || [] : [];
    },
    submit(payload) {
      return oidc ? putChunks(payload) : call(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
    }
  };
}
async function runFcWorker({ browser, signal, logger: logger2 = logger, client: client2 = createFcClient(), pollMs = 5e3, collect: collect2 = collectFc } = {}) {
  const wait = (ms) => new Promise((resolve2) => {
    const t = setTimeout(resolve2, ms);
    signal?.addEventListener("abort", () => {
      clearTimeout(t);
      resolve2();
    }, { once: true });
  });
  while (!signal?.aborted) {
    try {
      const urls = await client2.queue();
      for (const url of urls.slice(0, 3)) {
        if (signal?.aborted) break;
        let payload;
        try {
          payload = await collect2(browser, url);
        } catch (error) {
          payload = { url, region: REGION2, error: error?.code === "ssrf" ? "URL refus\xE9e" : "\xC9chec du chargement de la page" };
        }
        await client2.submit(payload).then(() => logger2.log("info", "fc.submitted", { error: !!payload.error }), () => logger2.log("warn", "fc.submit_failed"));
      }
    } catch {
      logger2.log("warn", "fc.poll_failed");
    }
    await wait(pollMs);
  }
}
var US, REGION2, WAIT_MS, b64url2;
var init_fc_worker = __esm({
  "src/fc-worker.js"() {
    init_ssrf();
    init_log();
    US = process.env.FC_REGION === "us";
    REGION2 = US ? "United States (GitHub Actions), US" : "France (Dunkerque), FR";
    WAIT_MS = 7e3;
    b64url2 = (buf) => Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }
});

// src/config.js
var positiveInt = (value, fallback) => {
  const n = Number(value);
  return Number.isInteger(n) && n > 0 ? n : fallback;
};
var region = process.env.OC_REGION || "fr";
if (region !== "fr" && region !== "us") {
  throw new Error("OC_REGION doit \xEAtre \xAB fr \xBB ou \xAB us \xBB");
}
var config = Object.freeze({
  baseUrl: process.env.OC_BASE_URL || "https://opencookies.com",
  ingestKey: process.env.OC_INGEST_KEY || "",
  region,
  concurrency: 2,
  pollMs: positiveInt(process.env.OC_POLL_MS, 3e3),
  requestTimeoutMs: positiveInt(process.env.OC_REQUEST_TIMEOUT_MS, 15e3),
  scanTimeoutMs: 11e4,
  maxBodyBytes: 7e6
});

// src/ingest-client.js
var ingest_client_exports = {};
__export(ingest_client_exports, {
  claim: () => claim,
  createIngestClient: () => createIngestClient,
  submit: () => submit
});
var CHUNK = 4e3;
var b64url = (buf) => Buffer.from(buf).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
function createIngestClient({ baseUrl = config.baseUrl, key = config.ingestKey, region: region2 = config.region, fetchImpl = fetch, auth = process.env.OC_AUTH || "key" } = {}) {
  const oidc = auth === "oidc";
  const endpoint = new URL(oidc ? "/ingest" : "/ingest.php", baseUrl).href;
  let token = null, tokenAt = 0;
  async function oidcToken() {
    if (token && Date.now() - tokenAt < 24e4) return token;
    const url = `${process.env.ACTIONS_ID_TOKEN_REQUEST_URL}&audience=${encodeURIComponent(new URL(baseUrl).origin)}`;
    const response = await fetchImpl(url, { headers: { Authorization: `Bearer ${process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN}` }, signal: AbortSignal.timeout(config.requestTimeoutMs) });
    if (!response.ok) throw new Error(`OIDC HTTP ${response.status}`);
    token = (await response.json()).value;
    tokenAt = Date.now();
    return token;
  }
  async function request(url, init) {
    const headers = oidc ? { "X-OC-OIDC": await oidcToken() } : { "X-OC-Key": key };
    const response = await fetchImpl(url, { ...init, headers: { ...headers, ...init.headers }, signal: AbortSignal.timeout(config.requestTimeoutMs) });
    if (!response.ok) throw new Error(`Ingest HTTP ${response.status}`);
    return response.json();
  }
  async function putChunks(payload) {
    const raw = Buffer.from(JSON.stringify(payload));
    if (raw.length > config.maxBodyBytes) throw new Error("Corps ingest trop volumineux");
    const encoded = b64url(raw), parts = [];
    for (let i = 0; i < encoded.length; i += CHUNK) parts.push(encoded.slice(i, i + CHUNK));
    let next = 0, last = null;
    const send = async (index) => {
      for (let attempt = 0; ; attempt++) {
        try {
          return await request(`${endpoint}?put=1&id=${payload.id}&i=${index}&n=${parts.length}&d=${parts[index]}`, { method: "GET" });
        } catch (error) {
          if (attempt >= 3) throw error;
          await new Promise((r) => setTimeout(r, 500 * (attempt + 1)));
        }
      }
    };
    await Promise.all(Array.from({ length: Math.min(6, parts.length) }, async () => {
      while (next < parts.length) {
        const r = await send(next++);
        last = r;
      }
    }));
    return last;
  }
  return {
    async claim() {
      const data = await request(`${endpoint}?claim=1&region=${encodeURIComponent(region2)}`, { method: "GET" });
      return data?.ok ? data.job || null : null;
    },
    async submit(payload) {
      if (oidc) return putChunks(payload);
      const body = JSON.stringify(payload);
      if (Buffer.byteLength(body) > config.maxBodyBytes) throw new Error("Corps ingest trop volumineux");
      return request(endpoint, { method: "POST", headers: { "Content-Type": "application/json" }, body });
    }
  };
}
var client = createIngestClient();
var claim = (...args) => client.claim(...args);
var submit = (...args) => client.submit(...args);

// src/scan.js
init_ssrf();

// src/robots.js
init_ssrf();
async function isAllowed(input, ua = "*", opts = {}) {
  try {
    const url = await assertPublicUrl(input, opts);
    const robotsUrl = new URL("/robots.txt", url);
    const response = await fetchRobots(robotsUrl, opts);
    if (!response.ok) return true;
    const text2 = await response.text();
    let applies = false;
    for (const raw of text2.split(/\r?\n/)) {
      const line = raw.split("#", 1)[0].trim();
      const match = line.match(/^(user-agent|allow|disallow)\s*:\s*(.*)$/i);
      if (!match) continue;
      const [, key, value] = match;
      if (key.toLowerCase() === "user-agent") applies = value === "*" || ua.toLowerCase().includes(value.toLowerCase());
      else if (applies && key.toLowerCase() === "disallow" && value && url.pathname.startsWith(value)) return false;
    }
    return true;
  } catch {
    return true;
  }
}
async function fetchRobots(initialUrl, opts) {
  let url = initialUrl;
  for (let redirects = 0; redirects <= 5; redirects++) {
    await assertPublicUrl(url, opts);
    const response = await fetch(url, {
      signal: AbortSignal.timeout(opts.timeoutMs || 5e3),
      redirect: "manual"
    });
    if (![301, 302, 303, 307, 308].includes(response.status)) return response;
    const location2 = response.headers.get("location");
    if (!location2 || redirects === 5) return response;
    url = new URL(location2, url);
  }
}

// src/collect.js
init_ssrf();
import { createHash } from "node:crypto";

// src/banner-detect.js
var REJECT_SRC = String.raw`refus|rejet|reject|decline|deny|disagree|non merci|continuer sans|sans consentement|sans accepter|n['’]accepte (rien|pas)|ne pas accepter|je ne veux pas|pas d['’]accord|tout refuser|only (necessary|essential|required)|necessary only|essential only|uniquement (les )?(cookies )?(nécessaires|essentiels|obligatoires)|seulement (les )?(cookies )?(nécessaires|essentiels)|nur (notwendige|erforderliche|technisch)|ablehn|nicht zustimmen|rechaz|solo (necesarias|esenciales)|rifiut|solo necessari|recus|apenas (necessários|essenciais)|weiger|alleen (noodzakelijke|essentiële)|odrzu|tylko niezb|avvis|endast nödvändiga|afvis|kun nødvendige|refuz|doar necesare|απόρριψη|απορρίπτω|μόνο τα απαραίτητα|رفض|الضرورية فقط`;
var ACCEPT_SRC = String.raw`accept|j['’]accepte|ok pour moi|autoriser|agree|allow|akzept|zustimm|einverstanden|alle erlauben|aceptar|acepto|accett|acconsent|aceitar|concordo|aceito|accepteren|akkoord|zaakceptuj|zgadzam|akceptuj|godkänn|tillåt|tillad|godkend|sunt de acord|permit|αποδοχή|αποδέχομαι|συμφωνώ|موافق|قبول|got it|consent to all|allow all`;
var SETTINGS_SRC = String.raw`param[eèé]tr|personnali[sz]|customi[sz]e|manage|preference|options|choisi|gérer|gerer|configur|réglage|détails|details|einstellung|auswahl|anpassen|ajustes|gestionar|impostazioni|gestisci|personalizza|definições|gerir|instellingen|beheren|ustawienia|zarządzaj|inställningar|indstillinger|setări|ρυθμίσεις|διαχείριση|إعدادات|تخصيص|settings|vælg|se valgte|se alle|learn more|en savoir plus`;
var CMP_CATALOG = [
  { n: "axeptio", box: ["#axeptio_overlay"], acc: ["#axeptio_btn_acceptAll"], rej: ["#axeptio_btn_dismiss"], set: ["#axeptio_btn_configure"] },
  { n: "didomi", box: ["#didomi-host", "#didomi-popup", ".didomi-popup-container", "#didomi-notice"], acc: ["#didomi-notice-agree-button", ".didomi-components-button--agree"], rej: ["#didomi-notice-disagree-button", ".didomi-continue-without-agreeing", ".didomi-components-button--disagree"], set: ["#didomi-notice-learn-more-button"] },
  { n: "onetrust", box: ["#onetrust-banner-sdk", "#onetrust-consent-sdk"], acc: ["#onetrust-accept-btn-handler"], rej: ["#onetrust-reject-all-handler", ".ot-pc-refuse-all-handler"], set: ["#onetrust-pc-btn-handler"] },
  { n: "cookiebot", box: ["#CybotCookiebotDialog"], acc: ["#CybotCookiebotDialogBodyLevelButtonLevelOptinAllowAll", "#CybotCookiebotDialogBodyButtonAccept", "#CybotCookiebotDialogBodyLevelButtonAccept"], rej: ["#CybotCookiebotDialogBodyButtonDecline", "#CybotCookiebotDialogBodyLevelButtonLevelOptinDeclineAll"], set: ["#CybotCookiebotDialogBodyLevelButtonCustomize", "#CybotCookiebotDialogBodyButtonDetails"] },
  { n: "usercentrics", box: ["#usercentrics-root", "#usercentrics-cmp-ui"], acc: ['[data-testid="uc-accept-all-button"]'], rej: ['[data-testid="uc-deny-all-button"]'], set: ['[data-testid="uc-more-button"]'] },
  { n: "sourcepoint", box: ['div[id^="sp_message_container"]', 'iframe[id^="sp_message_iframe"]'], acc: ["button.sp_choice_type_11"], rej: ["button.sp_choice_type_13"], set: ["button.sp_choice_type_12"] },
  { n: "trustarc", box: ["#truste-consent-track", "#consent_blackbar", "#teconsent"], acc: ["#truste-consent-button"], rej: ["#truste-consent-required"], set: ["#truste-show-consent"] },
  { n: "iubenda", box: ["#iubenda-cs-banner"], acc: [".iubenda-cs-accept-btn"], rej: [".iubenda-cs-reject-btn"], set: [".iubenda-cs-customize-btn"] },
  { n: "termly", box: ["#termly-code-snippet-support", '[data-tid="banner"]'], acc: ['[data-tid="banner-accept"]', ".t-acceptAllButton"], rej: ['[data-tid="banner-decline"]', ".t-declineButton"], set: ['[data-tid="banner-preferences"]', ".t-preference-button"] },
  { n: "cookieyes", box: [".cky-consent-container", ".cky-consent-bar"], acc: [".cky-btn-accept"], rej: [".cky-btn-reject"], set: [".cky-btn-customize"] },
  { n: "complianz", box: ["#cmplz-cookiebanner-container", ".cmplz-cookiebanner"], acc: [".cmplz-accept"], rej: [".cmplz-deny"], set: [".cmplz-view-preferences"] },
  { n: "osano", box: [".osano-cm-window", ".osano-cm-dialog"], acc: [".osano-cm-accept-all"], rej: [".osano-cm-deny", ".osano-cm-denyAll"], set: [".osano-cm-manage"] },
  { n: "klaro", box: [".klaro .cookie-notice", ".klaro"], acc: [".cm-btn-accept-all", ".cm-btn-success"], rej: [".cm-btn-decline"], set: [".cm-btn-learn-more", ".cm-link.learn-more"] },
  { n: "tarteaucitron", box: ["#tarteaucitronAlertBig"], acc: ["#tarteaucitronPersonalize2", ".tarteaucitronAllow"], rej: ["#tarteaucitronAllDenied2", ".tarteaucitronDeny"], set: ["#tarteaucitronCloseAlert"] },
  { n: "consentmanager", box: ["#cmpbox"], acc: [".cmpboxbtnyes"], rej: [".cmpboxbtnno"], set: [".cmpboxbtncustom"] },
  { n: "cookiescript", box: ["#cookiescript_injected"], acc: ["#cookiescript_accept"], rej: ["#cookiescript_reject"], set: ["#cookiescript_setup"] },
  { n: "borlabs", box: ["#BorlabsCookieBox", ".borlabs-cookie"], acc: ["._brlbs-btn-accept-all"], rej: ["._brlbs-refuse-btn"], set: ["._brlbs-btn-cookie-preference"] },
  { n: "cookiefirst", box: ["[data-cookiefirst-widget]", "#cookiefirst-root"], acc: ['[data-cookiefirst-action="accept"]'], rej: ['[data-cookiefirst-action="reject"]'], set: ['[data-cookiefirst-action="adjust"]'] },
  { n: "cookiehub", box: [".ch2-container"], acc: [".ch2-allow-all-btn"], rej: [".ch2-deny-all-btn"], set: [".ch2-open-settings-btn"] },
  { n: "civic", box: ["#ccc"], acc: ["#ccc-notify-accept"], rej: ["#ccc-notify-reject"], set: ["#ccc-notify-settings"] },
  { n: "piwik", box: [".ppms_cm_popup_overlay", "#ppms_cm_consent_popup"], acc: [".ppms_cm_agree-to-all"], rej: [".ppms_cm_reject-all"], set: [".ppms_cm_settings"] },
  { n: "cookieconsent", box: ["#cc-main", "#cc_div"], acc: ['[data-role="all"]'], rej: ['[data-role="necessary"]'], set: ['[data-role="show"]'] },
  { n: "cookie-notice", box: ["#cookie-notice"], acc: ["#cn-accept-cookie"], rej: ["#cn-refuse-cookie"], set: ["#cn-more-info"] },
  { n: "cookie-law-info", box: ["#cookie-law-info-bar", ".cli-modal-dialog"], acc: ["#wt-cli-accept-all-btn", "#cookie_action_close_header"], rej: ["#wt-cli-reject-btn", "#cookie_action_close_header_reject"], set: [".cli_settings_button"] },
  { n: "fundingchoices", box: [".fc-consent-root", ".fc-dialog-container"], acc: [".fc-cta-consent"], rej: [".fc-cta-do-not-consent"], set: [".fc-cta-manage-options"] }
];
var rx = (src2) => new RegExp(src2, "i");
var ACCEPT = rx(ACCEPT_SRC);
var REJECT = rx(REJECT_SRC);
var SETTINGS = rx(SETTINGS_SRC);
function classifyButton(text2 = "") {
  const value = String(text2).trim();
  if (REJECT.test(value)) return "reject";
  if (ACCEPT.test(value)) return "accept";
  if (SETTINGS.test(value)) return "settings";
  return "other";
}
var FIND_BANNER_SRC = String.raw`function () {
  const CAT = __CATALOG__;
  const REJ = new RegExp(__REJ__, 'i'), ACC = new RegExp(__ACC__, 'i'), SET = new RegExp(__SET__, 'i');
  const all = [], walk = root => { try { for (const el of root.querySelectorAll('*')) { all.push(el); if (el.shadowRoot) walk(el.shadowRoot); } } catch (e) {} };
  walk(document);
  const parentOf = n => { const p = n.parentNode || n.host || null; return p && p.nodeType === 11 ? (p.host || null) : p; };   // un shadow DOM : on saute la racine d'ombre pour rejoindre son hôte
  const visible = el => { const r = el.getBoundingClientRect(), s = getComputedStyle(el); return r.width > 0 && r.height > 0 && s.visibility !== 'hidden' && s.display !== 'none'; };
  const isBtn = e => /^(BUTTON|A|INPUT)$/.test(e.tagName) || e.getAttribute('role') === 'button' || e.hasAttribute('onclick') || (e.children.length === 0 && !e.closest('button,a,[role="button"],input') && (e.innerText || '').trim().length > 0 && (e.innerText || '').trim().length <= 45 && getComputedStyle(e).cursor === 'pointer');
  const label = el => (el.innerText || el.value || el.getAttribute('aria-label') || el.getAttribute('title') || '').trim().replace(/\s+/g, ' ');
  const textKind = t => REJ.test(t) ? 'reject' : ACC.test(t) ? 'accept' : SET.test(t) ? 'settings' : 'other';
  const kinds = new WeakMap(); let vendor = null;
  const nameRe = /cookie|consent|privacy|gdpr|rgpd|didomi|onetrust|axeptio|tarteaucitron|cookiebot|usercentrics|sourcepoint|trustarc|iubenda|complianz|osano|cybot|termly|borlabs|cookieyes|quantcast|consentmanager/i;
  const overlay = el => { const p = getComputedStyle(el).position; return p === 'fixed' || p === 'sticky' || /^(alert)?dialog$/.test(el.getAttribute('role') || '') || el.getAttribute('aria-modal') === 'true' || el.tagName === 'DIALOG'; };
  const rootLike = el => overlay(el) || nameRe.test((el.id || '') + ' ' + (typeof el.className === 'string' ? el.className : '') + ' ' + (el.getAttribute('aria-label') || ''));
  const within = (e, root) => { for (let n = e; n; n = parentOf(n)) if (n === root) return true; return false; };
  const sizeOk = el => { const r = el.getBoundingClientRect(); return r.width >= 120 && r.height >= 30; };
  const q = (root, sel) => all.filter(e => { try { return e.matches(sel); } catch (x) { return false; } });   // traverse aussi les shadow DOM

  // 1. fournisseur connu : on cherche d'abord les boutons par leurs sélecteurs (quelle que soit la langue du libellé)
  let best = null, bestScore = -1;
  for (const c of CAT) {
    const found = { accept: [], reject: [], settings: [] };
    for (const [k, list] of [['accept', c.acc], ['reject', c.rej], ['settings', c.set]]) for (const sel of list) for (const el of q(document, sel)) if (visible(el)) found[k].push(el);
    // un cadre Sourcepoint ou similaire : les boutons sont alors dans le document du cadre (cette fonction y est aussi exécutée)
    const n = found.accept.length + found.reject.length;
    if (!n) continue;
    for (const k of ['accept', 'reject', 'settings']) for (const el of found[k]) kinds.set(el, k);
    let box = null;
    for (const sel of c.box) { const el = q(document, sel).find(visible); if (el) { box = el; break; } }
    const first = found.accept[0] || found.reject[0];
    if (!box || !within(first, box) && !box.shadowRoot) { box = null; for (let a = parentOf(first); a && a !== document.body && a !== document.documentElement && a.nodeType === 1; a = parentOf(a)) { if (sizeOk(a) && rootLike(a)) box = a; } }
    if (!box) box = first.parentNode && first.parentNode.nodeType === 1 ? first.parentNode : first;
    const score = found.accept.length + found.reject.length + found.settings.length;
    if (score > bestScore) { best = box; bestScore = score; vendor = c.n; }
  }
  if (best) {
    // les autres boutons du bandeau reçoivent leur rôle d'après leur libellé
    for (const el of all) if (isBtn(el) && within(el, best) && visible(el) && !kinds.has(el)) { const k = textKind(label(el)); if (k !== 'other') kinds.set(el, k); }
    for (const el of all) if (kinds.has(el) && within(el, best)) el.setAttribute('data-oc-kind', kinds.get(el));
    window.__ocKinds = kinds; window.__ocVendor = vendor; window.__ocBanner = best; return true;
  }

  // 2. repli : boutons de choix (libellé), regroupement puis boîte du bandeau
  const choices = [];
  for (const el of all) {
    if (!isBtn(el) || !visible(el)) continue;
    const t = label(el);
    if (!t || t.length > 45) continue;
    const k = textKind(t); if (k !== 'other') { choices.push({ el, k }); kinds.set(el, k); }
  }
  const countBtn = root => all.filter(e => isBtn(e) && within(e, root)).length;
  const sizeOf = root => all.filter(e => within(e, root)).length;
  let bestBox = null, bestKinds = -1, bestSize = Infinity;
  for (const seed of choices) {
    if (seed.k === 'settings') continue;   // un lien « Gérer mes cookies » seul, c'est le pied de page, pas le bandeau
    let group = null;
    for (let a = parentOf(seed.el); a && a !== document.body && a !== document.documentElement && a.nodeType === 1; a = parentOf(a)) {
      const ks = new Set(choices.filter(c => within(c.el, a)).map(c => c.k));
      if (ks.has('accept') && (ks.has('reject') || ks.has('settings'))) { group = { el: a, n: ks.size }; break; }
      if (ks.size >= 2) { group = { el: a, n: ks.size }; break; }
    }
    let box = group ? group.el : null, n = group ? group.n : 1;
    const base = box || seed.el, baseCount = countBtn(base);
    let top = null;
    for (let a = box ? parentOf(box) : parentOf(seed.el); a && a !== document.body && a !== document.documentElement && a.nodeType === 1; a = parentOf(a)) {
      if (countBtn(a) > baseCount + 30) break;
      if (rootLike(a) && sizeOk(a)) top = a;   // un conteneur fixe de hauteur nulle (Axeptio) n'est pas la boîte du bandeau
    }
    if (top) box = top;
    if (!box || !sizeOk(box)) continue;
    const size = sizeOf(box);
    if (n > bestKinds || (n === bestKinds && size < bestSize)) { bestBox = box; bestKinds = n; bestSize = size; }
  }
  if (!bestBox) {
    const cands = all.filter(el => visible(el) && el.getBoundingClientRect().width > 180 && el !== document.body && el !== document.documentElement
      && overlay(el) && nameRe.test((el.id || '') + ' ' + (typeof el.className === 'string' ? el.className : '') + ' ' + (el.getAttribute('aria-label') || '')) && countBtn(el) >= 2 && countBtn(el) <= 150);
    for (const c of cands) { const n = countBtn(c); if (n > bestKinds) { bestKinds = n; bestBox = c; } }
  }
  // Dans un cadre (CMP en iframe), tout le document est le bandeau : le lien de refus se trouve souvent hors du groupe de boutons.
  if (window.top !== window && choices.some(c => c.k === 'accept' || c.k === 'reject')) bestBox = document.body;
  if (bestBox) for (const el of all) if (kinds.has(el) && within(el, bestBox)) el.setAttribute('data-oc-kind', kinds.get(el));
  window.__ocKinds = kinds; window.__ocVendor = null; window.__ocBanner = bestBox || null;
  return !!bestBox;
}`;
var src = FIND_BANNER_SRC.replace("__CATALOG__", JSON.stringify(CMP_CATALOG)).replace("__REJ__", JSON.stringify(REJECT_SRC)).replace("__ACC__", JSON.stringify(ACCEPT_SRC)).replace("__SET__", JSON.stringify(SETTINGS_SRC));
var findBanner = (0, eval)("(" + src + ")");

// src/collect.js
var CMP = /didomi|onetrust|axeptio|cookiebot|tarteaucitron|usercentrics|sourcepoint|quantcast|trustarc|iubenda|complianz|consentmanager|cookiebanner|cookie-?consent|consent|privacy-?center|privacy-mgmt|sp_message|sp-prod|cmp./i;
var isKnownCmpFrame = (frame) => CMP.test(frame.url()) || /^about:(srcdoc|blank)/.test(frame.url());
function classifyRejectKind({ clicked = false, inSettings = false, available = false } = {}) {
  if (clicked) return inSettings ? "parametres" : "direct";
  return available ? "conditionnel" : "absent";
}
function collectionWaitMs(value) {
  return Math.max(6e3, Math.min(Number.isFinite(Number(value)) ? Number(value) : 7e3, 15e3));
}
var bounded = (promise, ms, fallback = null) => Promise.race([promise, new Promise((resolve2) => setTimeout(() => resolve2(fallback), ms))]);
var sleep = (ms) => new Promise((resolve2) => setTimeout(resolve2, ms));
var ordinaryUserAgent = (version) => `Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/${String(version || "130.0.0.0")} Safari/537.36`;
async function inspect(page, label, limits) {
  try {
    await bounded(page.evaluate(findBanner), 2500).catch(() => null);
    const result = await bounded(page.evaluate(() => {
      const allElements = () => {
        const found = [], seen = /* @__PURE__ */ new Set();
        const walk = (root) => {
          try {
            for (const el of root.querySelectorAll("*")) {
              if (!seen.has(el)) {
                seen.add(el);
                found.push(el);
              }
              if (el.shadowRoot) walk(el.shadowRoot);
            }
          } catch {
          }
        };
        walk(document);
        return found;
      };
      const nodes = allElements();
      const visible = (el) => {
        const r = el.getBoundingClientRect(), s = getComputedStyle(el);
        return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none";
      };
      const banner = window.__ocBanner || null;
      const inBanner = (el) => {
        for (let node = el; node; node = node.parentNode || node.host) if (node === banner) return true;
        return false;
      };
      const buttons = banner ? nodes.filter((el) => /^(BUTTON|A|INPUT)$/.test(el.tagName) || el.getAttribute("role") === "button" || el.hasAttribute("data-oc-kind")).filter((el) => inBanner(el) && visible(el)).map((el) => {
        const text2 = (el.innerText || el.value || el.getAttribute("aria-label") || "").trim().replace(/\s+/g, " ").slice(0, 180);
        if (!text2) return null;
        const s = getComputedStyle(el), r = el.getBoundingClientRect();
        return { text: text2, kind: window.__ocKinds && window.__ocKinds.get(el) || null, layer: 1, w: Math.round(r.width), h: Math.round(r.height), fontSize: parseFloat(s.fontSize) || null, bg: s.backgroundColor, color: s.color, _tag: el.tagName, _selector: el.id ? `#${CSS.escape(el.id)}` : null };
      }).filter(Boolean) : [];
      const cookies = document.cookie.split(";").map((x) => x.trim().split("=")[0]).filter(Boolean).map((name) => ({ name, domain: location.hostname, days: null, firstParty: true }));
      let gcs = null;
      try {
        for (const item of window.dataLayer || []) {
          if (!item) continue;
          const command = Array.isArray(item) || typeof item.length === "number" ? Array.from(item) : null;
          if (command?.[0] === "consent" && (command[1] === "default" || command[1] === "update") && command[2] && typeof command[2] === "object") gcs = Object.entries(command[2]).map(([k, v]) => `${k}=${v}`).join(",");
          else if (typeof item.gcs === "string") gcs = item.gcs;
        }
      } catch {
      }
      const cmpNames = [...new Set(nodes.map((el) => `${el.id} ${typeof el.className === "string" ? el.className : ""} ${el.getAttribute("aria-label") || ""}`).join(" ").match(/didomi|onetrust|axeptio|tarteaucitron|cookiebot|usercentrics|sourcepoint|quantcast|trustarc|iubenda|complianz/ig) || [])];
      const tcf = typeof window.__tcfapi === "function";
      return { nodeCount: nodes.length, pageTitle: document.title.slice(0, 80), textLen: (document.body ? document.body.innerText : "").length, buttons, bannerPresent: !!banner || buttons.some((b) => /cookie|consent/i.test(b.text)), cookies, storageKeys: (() => {
        try {
          return localStorage.length;
        } catch {
          return 0;
        }
      })(), tcf, gcs, cmpNames };
    }), 3500);
    if (!result) {
      limits.push(`${label}: inspection timeout`);
      return null;
    }
    for (const frame of page.frames()) {
      if (frame === page.mainFrame() || !isKnownCmpFrame(frame)) continue;
      try {
        await bounded(frame.evaluate(findBanner), 1200).catch(() => null);
        const data = await bounded(frame.evaluate(() => {
          const all = [], walk = (root) => {
            try {
              for (const el of root.querySelectorAll("*")) {
                all.push(el);
                if (el.shadowRoot) walk(el.shadowRoot);
              }
            } catch {
            }
          };
          walk(document);
          const visible = (el) => {
            const r = el.getBoundingClientRect(), s = getComputedStyle(el);
            return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none";
          };
          const banner = window.__ocBanner || null;
          const inside = (el) => {
            for (let n = el; n; n = n.parentNode || n.host) if (n === banner) return true;
            return false;
          };
          const buttons = banner ? all.filter((el) => inside(el) && (/^(BUTTON|A|INPUT)$/.test(el.tagName) || el.getAttribute("role") === "button") && visible(el)).map((el) => {
            const r = el.getBoundingClientRect(), s = getComputedStyle(el);
            return { text: (el.innerText || el.value || el.getAttribute("aria-label") || "").trim().replace(/\s+/g, " ").slice(0, 180), kind: window.__ocKinds && window.__ocKinds.get(el) || null, layer: 1, w: Math.round(r.width), h: Math.round(r.height), fontSize: parseFloat(s.fontSize) || null, bg: s.backgroundColor, color: s.color };
          }).filter((x) => x.text) : [];
          return { bannerPresent: !!banner, buttons, vendor: window.__ocVendor || null };
        }), 900);
        if (data) {
          result.bannerPresent ||= data.bannerPresent;
          result.buttons.push(...data.buttons);
          if (data.vendor && !result.vendor) result.vendor = data.vendor;
        }
      } catch {
      }
    }
    return result;
  } catch {
    limits.push(`${label}: inspection unavailable`);
    return null;
  }
}
async function snapshot(page, label, requests, limits, cookieDurations = /* @__PURE__ */ new Map()) {
  const data = await inspect(page, label, limits);
  if (!data) return null;
  let shot = null;
  try {
    let bytes = await bounded(page.screenshot({ type: "jpeg", quality: 45, fullPage: false, timeout: 4e3 }), 4500);
    if (bytes && bytes.length > 600 * 1024) bytes = await bounded(page.screenshot({ type: "jpeg", quality: 25, fullPage: false, timeout: 4e3 }), 4500);
    if (bytes && bytes.length <= 600 * 1024) shot = Buffer.from(bytes).toString("base64");
    else limits.push(`${label}: capture unavailable or too large`);
  } catch {
    limits.push(`${label}: capture failed`);
  }
  let cookies = data.cookies;
  try {
    const browserCookies = await bounded(page.context().cookies(), 1200, null);
    if (browserCookies) cookies = browserCookies.map((cookie) => ({ name: cookie.name, domain: cookie.domain, days: cookie.expires > 0 ? Math.max(0, (cookie.expires * 1e3 - Date.now()) / 864e5) : 0, durationDays: cookieDurations.get(cookie.name) ?? null, firstParty: cookie.domain.replace(/^\./, "") === new URL(page.url()).hostname || new URL(page.url()).hostname.endsWith(`.${cookie.domain.replace(/^\./, "")}`) }));
  } catch {
  }
  return { label, url: page.url(), cookies, requests: [...requests.values()], storageKeys: data.storageKeys, shot, _inspection: data };
}
async function waitForChoiceChange(page, beforeShot) {
  const deadline = Date.now() + 1500;
  while (Date.now() < deadline) {
    await sleep(150);
    try {
      const bytes = await bounded(page.screenshot({ type: "jpeg", quality: 45, fullPage: false, timeout: 1200 }), 1300);
      if (bytes && createHash("sha256").update(bytes).digest("hex") !== beforeShot) return true;
    } catch {
    }
  }
  return false;
}
var shotHash = (shot) => shot ? createHash("sha256").update(Buffer.from(shot, "base64")).digest("hex") : null;
async function collect(browser, url, opts = {}) {
  const limits = [], notes = [], vendors = [], contexts = [];
  const states = { avant: null, refus: null, acceptation: null };
  const consentMode = { defaultDenied: null, updateOnChoice: null, gcs: { avant: null, refus: null, acceptation: null } };
  const pageTimeout = opts.stepTimeoutMs || 15e3;
  const makePage = async () => {
    const context = await browser.newContext({ locale: "fr-FR", timezoneId: "Europe/Paris", userAgent: ordinaryUserAgent(typeof browser.version === "function" ? browser.version() : ""), ...opts.contextOptions || {} });
    contexts.push(context);
    const page = await context.newPage();
    await guardPageRequests(page, { allowLocal: opts.allowLocal });
    const trackerHostMap = opts.trackerHostMap || {};
    if (opts.allowLocal && Object.keys(trackerHostMap).length) {
      await page.route("**/*", async (route) => {
        const original = new URL(route.request().url());
        const mapped = trackerHostMap[original.hostname];
        if (!mapped) return route.continue();
        return route.fulfill({
          status: 200,
          contentType: original.pathname.endsWith(".js") ? "application/javascript" : "text/plain",
          body: original.pathname.endsWith(".js") ? "window.__fixtureTrackerLoaded = true;" : "fixture tracker response"
        });
      });
    }
    page.setDefaultTimeout(Math.min(pageTimeout, 8e3));
    return page;
  };
  const visit = async (page, target, label) => {
    const requests = /* @__PURE__ */ new Map();
    const cookieDurations = /* @__PURE__ */ new Map();
    page.on("request", (req) => {
      try {
        const u = new URL(req.url());
        if (!/^https?:$/.test(u.protocol)) return;
        const entry = Object.keys(opts.trackerHostMap || {}).find((host2) => host2.toLowerCase() === u.hostname.toLowerCase());
        const host = entry ? entry[0] : u.host;
        requests.set(`${host}${u.pathname}`, { host, path: u.pathname });
      } catch {
      }
    });
    page.on("response", async (response) => {
      try {
        for (const header of await response.headersArray()) {
          if (header.name.toLowerCase() !== "set-cookie") continue;
          const name = header.value.split("=", 1)[0].trim();
          const maxAge = header.value.match(/(?:^|;)\s*max-age\s*=\s*(-?\d+)/i);
          const expires = header.value.match(/(?:^|;)\s*expires\s*=\s*([^;]+)/i);
          const days = maxAge ? Math.max(0, Number(maxAge[1]) / 86400) : expires ? Math.max(0, (Date.parse(expires[1]) - Date.now()) / 864e5) : null;
          if (name && Number.isFinite(days)) cookieDurations.set(name, days);
        }
      } catch {
      }
    });
    try {
      await bounded(page.goto(target, { waitUntil: "domcontentloaded", timeout: pageTimeout }), pageTimeout);
    } catch {
      limits.push(`${label}: navigation failed or timed out`);
      return { requests, data: null };
    }
    await sleep(collectionWaitMs(opts.waitMs));
    return { requests, cookieDurations, data: await snapshot(page, label, requests, limits, cookieDurations) };
  };
  const clickChoice = async (page, kind) => {
    let available = false;
    for (const frame of page.frames()) {
      if (frame !== page.mainFrame() && !isKnownCmpFrame(frame)) continue;
      const marked = frame.locator(`[data-oc-kind="${kind}"]`);
      const markedCount = await bounded(marked.count(), 1e3, 0);
      for (let m = 0; m < Math.min(markedCount, 6); m++) {
        const item = marked.nth(m);
        if (!await bounded(item.isVisible().catch(() => false), 500, false)) continue;
        available = true;
        try {
          await item.click({ timeout: 1500 });
          return { clicked: true, available };
        } catch {
        }
      }
      const candidates = frame.locator('button,a,[role="button"],input[type="button"],input[type="submit"]');
      await bounded(frame.evaluate(findBanner), 1500).catch(() => null);
      const count = await bounded(candidates.count(), 1e3, 0);
      const inBanner = await bounded(candidates.evaluateAll((els) => {
        const all = [];
        const walk = (root) => {
          try {
            for (const el of root.querySelectorAll("*")) {
              all.push(el);
              if (el.shadowRoot) walk(el.shadowRoot);
            }
          } catch {
          }
        };
        walk(document);
        const banner = window.__ocBanner || null;
        const inside = (el) => {
          for (let n = el; n; n = n.parentNode || n.host) if (n === banner) return true;
          return false;
        };
        return els.map((el) => ({ inside: !!banner && inside(el), kind: window.__ocKinds && window.__ocKinds.get(el) || null }));
      }), 1e3, []);
      const wanted = Array.from({ length: Math.min(count, inBanner.length || count) }, (_, i) => i).filter((i) => inBanner[i]?.inside).slice(0, 100);
      for (const i of wanted) {
        const item = candidates.nth(i);
        if (!await bounded(item.isVisible().catch(() => false), 500, false)) continue;
        const text2 = await bounded(item.innerText().catch(() => item.getAttribute("aria-label") || ""), 700, "");
        if ((inBanner[i]?.kind || classifyButton(text2)) === kind) {
          available = true;
          try {
            await item.click({ timeout: 1200 });
            return { clicked: true, available };
          } catch {
          }
        }
      }
    }
    return { clicked: false, available };
  };
  let bannerPresent = false, tcf = false, blocked = false;
  let reject = { layer: null, kind: "absent", clicked: false, alternative: null };
  try {
    let page = await makePage();
    let first = await visit(page, url, "avant");
    states.avant = first.data;
    if (first.data) {
      bannerPresent = first.data._inspection.bannerPresent;
      tcf = first.data._inspection.tcf;
      consentMode.gcs.avant = first.data._inspection.gcs;
      for (const name of [first.data._inspection.vendor, ...first.data._inspection.cmpNames || []]) if (name && !vendors.includes(name)) vendors.push(name);
    }
    const insp = first.data?._inspection;
    if (insp && !insp.bannerPresent && (insp.nodeCount < 120 && insp.textLen < 500 || /un instant|just a moment|attention required|access denied|acc[èe]s refus|maintenance|v[ée]rification|verify|captcha|robot|forbidden|blocked|403/i.test(insp.pageTitle || ""))) {
      blocked = true;
      notes.push(`page prot\xE9g\xE9e ou vide au passage du navigateur automatis\xE9 (titre : \xAB ${insp.pageTitle || ""} \xBB)`);
      limits.push("la page lue est une protection anti-robot ou une page vide : le bandeau n\u2019a pas pu \xEAtre observ\xE9");
    }
    const initial = first.data?._inspection.buttons || [];
    const publicButtons = [];
    for (const b of initial) publicButtons.push({ text: b.text, kind: b.kind || classifyButton(b.text), layer: 1, w: b.w, h: b.h, fontSize: b.fontSize, bg: b.bg, color: b.color });
    await page.close().catch(() => {
    });
    page = await makePage();
    const refusal = await visit(page, url, "refus");
    const direct = refusal.data ? await clickChoice(page, "reject") : { clicked: false, available: false };
    reject = { layer: direct.clicked ? 1 : null, kind: classifyRejectKind(direct), clicked: direct.clicked, alternative: null };
    if (!direct.clicked) {
      const settings = await clickChoice(page, "settings");
      if (settings.clicked) {
        const refusedInSettings = await clickChoice(page, "reject");
        reject = { layer: refusedInSettings.clicked ? 2 : null, kind: classifyRejectKind({ ...refusedInSettings, inSettings: true }), clicked: refusedInSettings.clicked, alternative: refusedInSettings.clicked ? "settings" : null };
        const second = await inspect(page, "refus couche 2", limits);
        for (const b of second?.buttons || []) publicButtons.push({ text: b.text, kind: b.kind || classifyButton(b.text), layer: 2, w: b.w, h: b.h, fontSize: b.fontSize, bg: b.bg, color: b.color });
      }
    }
    if (reject.clicked) {
      refusal.requests.clear();
      await waitForChoiceChange(page, shotHash(refusal.data?.shot));
      const after = await snapshot(page, "refus", refusal.requests, limits, refusal.cookieDurations);
      states.refus = after;
      if (shotHash(after?.shot) === shotHash(refusal.data?.shot)) {
        states.refus.shot = null;
        notes.push("refus: \xE9tat visuel inchang\xE9 apr\xE8s le clic");
      }
      consentMode.gcs.refus = after?._inspection.gcs ?? null;
    } else limits.push("refus: aucun contr\xF4le de refus trouv\xE9");
    try {
      await bounded(page.reload({ waitUntil: "domcontentloaded", timeout: pageTimeout }), pageTimeout);
    } catch {
      limits.push("rechargement: timeout");
    }
    const reloadInfo = await inspect(page, "rechargement", limits);
    const bannerBackAfterReload = reloadInfo ? reloadInfo.bannerPresent : null;
    const internal = await page.locator("a[href]").evaluateAll((els, base) => els.map((a) => {
      try {
        return new URL(a.href, base);
      } catch {
        return null;
      }
    }).filter((u) => u && u.origin === new URL(base).origin && u.pathname !== new URL(base).pathname).map((u) => u.href).filter((v, i, a) => a.indexOf(v) === i).slice(0, 2), url).catch(() => []);
    let navData = null;
    for (const target of internal) {
      try {
        await bounded(page.goto(target, { waitUntil: "domcontentloaded", timeout: pageTimeout }), pageTimeout);
        await sleep(500);
        navData = await inspect(page, "navigation refus", limits);
      } catch {
        limits.push("navigation interne: timeout");
      }
    }
    const refusNav = navData ? { cookies: navData.cookies, requests: [...refusal.requests.values()] } : { cookies: states.refus?.cookies || [], requests: [...refusal.requests.values()] };
    await page.close().catch(() => {
    });
    page = await makePage();
    const third = await visit(page, url, "acceptation");
    const accepted = await clickChoice(page, "accept");
    if (accepted.clicked) {
      await waitForChoiceChange(page, shotHash(third.data?.shot));
      states.acceptation = await snapshot(page, "acceptation", third.requests, limits, third.cookieDurations);
      if (shotHash(states.acceptation?.shot) === shotHash(third.data?.shot)) {
        states.acceptation.shot = null;
        notes.push("acceptation: \xE9tat visuel inchang\xE9 apr\xE8s le clic");
      }
    } else if (third.data) {
      states.acceptation = null;
      notes.push("acceptation: \xE9tat inchang\xE9, aucun bouton de choix cliqu\xE9");
      limits.push("acceptation: bouton absent");
    }
    consentMode.gcs.acceptation = states.acceptation?._inspection?.gcs ?? null;
    consentMode.defaultDenied = typeof consentMode.gcs.avant === "string" ? /^G1[0-3]{2}$/.test(consentMode.gcs.avant) ? /0/.test(consentMode.gcs.avant.slice(2)) : /(^|,)(?:ad_storage|analytics_storage)=(?:denied|0)(?=,|$)/.test(consentMode.gcs.avant) : null;
    consentMode.updateOnChoice = consentMode.gcs.refus !== null || consentMode.gcs.acceptation !== null ? consentMode.gcs.refus !== consentMode.gcs.avant || consentMode.gcs.acceptation !== consentMode.gcs.avant : null;
    for (const s of Object.values(states)) if (s?._inspection) delete s._inspection;
    return { url, domain: new URL(url).hostname, locale: "fr-FR", bannerPresent, blocked, tcf, vendors, buttons: publicButtons, reject, states, refusNav, bannerBackAfterReload, consentMode, notes, limits };
  } catch {
    limits.push("collecte: \xE9tape interrompue");
    return { url, domain: (() => {
      try {
        return new URL(url).hostname;
      } catch {
        return "";
      }
    })(), locale: "fr-FR", bannerPresent, tcf, vendors, buttons: [], reject, states, refusNav: { cookies: [], requests: [] }, bannerBackAfterReload: null, consentMode, notes, limits };
  } finally {
    await Promise.all(contexts.map((c) => c.close().catch(() => {
    })));
  }
}

// src/lists/cookies.js
var COOKIES = {
  _ga: { cls: "analytics", reason: "suivi", platform: "Google Analytics" },
  _gid: { cls: "analytics", reason: "suivi", platform: "Google Analytics" },
  _gat: { cls: "analytics", reason: "suivi", platform: "Google Analytics" },
  _fbp: { cls: "marketing", reason: "suivi", platform: "Meta Pixel" },
  _gcl_au: { cls: "marketing", reason: "suivi", platform: "Google Ads" },
  _hjSessionUser: { cls: "analytics", reason: "suivi", platform: "Hotjar" },
  __cf_bm: { cls: "exempt", reason: "technique", platform: "Cloudflare" },
  cookieconsent_status: { cls: "exempt", reason: "choix", platform: "" }
};
function classifyCookie(cookie) {
  const known = COOKIES[cookie.name];
  if (known) return known;
  if (/^(?:_ga|_gid|_fbp|_gcl|_hj|mp_|amplitude)/i.test(cookie.name || "")) return { cls: "identifier", reason: "\xE0-examiner", platform: "" };
  return { cls: "unknown", reason: "non-list\xE9", platform: "" };
}

// src/lists/trackers.js
var TRACKERS = [
  ["google-analytics.com", "Google Analytics", "analytics", "Google"],
  ["googletagmanager.com", "Google Tag Manager", "tagmanager", "Google"],
  ["googleadservices.com", "Google Ads", "ads", "Google"],
  ["doubleclick.net", "Google Ads", "ads", "Google"],
  ["googlesyndication.com", "Google AdSense", "ads", "Google"],
  ["facebook.com", "Meta Pixel", "social", "Meta"],
  ["facebook.net", "Meta Pixel", "social", "Meta"],
  ["connect.instagram.com", "Instagram", "social", "Meta"],
  ["analytics.twitter.com", "X Analytics", "analytics", "X"],
  ["ads-twitter.com", "X Ads", "ads", "X"],
  ["hotjar.com", "Hotjar", "replay", "Hotjar"],
  ["mixpanel.com", "Mixpanel", "analytics", "Mixpanel"],
  ["segment.com", "Segment", "tagmanager", "Twilio"],
  ["amplitude.com", "Amplitude", "analytics", "Amplitude"],
  ["quantserve.com", "Quantcast", "ads", "Quantcast"],
  ["taboola.com", "Taboola", "ads", "Taboola"],
  ["outbrain.com", "Outbrain", "ads", "Outbrain"],
  ["criteo.com", "Criteo", "ads", "Criteo"],
  ["criteo.net", "Criteo", "ads", "Criteo"],
  ["scorecardresearch.com", "Comscore", "analytics", "Comscore"],
  ["newrelic.com", "New Relic", "analytics", "New Relic"],
  ["fullstory.com", "FullStory", "replay", "FullStory"],
  ["crazyegg.com", "Crazy Egg", "analytics", "Crazy Egg"],
  ["mouseflow.com", "Mouseflow", "replay", "Mouseflow"],
  ["clearbit.com", "Clearbit", "analytics", "Clearbit"]
].map(([domain, entity, kind, platform]) => ({ domain, entity, kind, platform, ping: false }));
function matchTracker(host) {
  const name = String(host || "").toLowerCase().replace(/\.$/, "");
  return TRACKERS.find((entry) => name === entry.domain || name.endsWith(`.${entry.domain}`)) || null;
}

// src/evaluate.js
var REGION = "France (Dunkerque)";
var LIMITS = [
  "Un seul passage automatis\xE9 a \xE9t\xE9 effectu\xE9 depuis la r\xE9gion indiqu\xE9e.",
  "Les listes de services et de cookies sont partielles ; un \xE9l\xE9ment absent des listes peut ne pas \xEAtre d\xE9tect\xE9.",
  "Le retrait du choix m\xE9moris\xE9 et les parcours avec compte ou achat ne sont pas test\xE9s."
];
var titles = ["Bandeau de consentement", "Avant tout choix", "Refuser aussi simple qu\u2019accepter", "M\xEAme poids visuel", "Le refus bloque le suivi", "Le choix est m\xE9moris\xE9", "Apr\xE8s \xAB Accepter \xBB", "Google Consent Mode v2", "Dur\xE9e des cookies"];
var ids = ["bandeau", "avant_choix", "refus_facile", "poids_visuel", "refus_bloque", "choix_memorise", "acceptation", "consent_mode", "durees"];
var expected = [
  "Un bandeau permet de choisir avant le d\xE9p\xF4t de cookies de suivi ou le contact de services de suivi.",
  "Aucun cookie ni service de suivi n\u2019est observ\xE9 avant un choix.",
  "Le refus est accessible d\xE8s la premi\xE8re couche, aussi simplement que l\u2019acceptation.",
  "Les boutons Refuser et Accepter ont une pr\xE9sentation de poids comparable.",
  "Apr\xE8s un refus, aucun nouveau cookie ni appel \xE0 un service de suivi n\u2019est observ\xE9.",
  "Le choix est conserv\xE9 apr\xE8s rechargement et le bandeau ne revient pas.",
  "Les services de suivi sont observ\xE9s apr\xE8s acceptation.",
  "Le consentement est refus\xE9 par d\xE9faut et mis \xE0 jour lors du choix.",
  "Les cookies de suivi ne d\xE9passent pas 13 mois."
];
var arr = (v) => Array.isArray(v) ? v : [];
var text = (v, max) => String(v ?? "").slice(0, max);
var list = (v, n, max) => arr(v).slice(0, n).map((x) => text(x, max));
var isTrackCookie = (c) => ["analytics", "marketing", "identifier", "analytics-exemptable"].includes(c.cls);
function observations(state) {
  if (!state) return null;
  const grouped = /* @__PURE__ */ new Map();
  for (const req of arr(state.requests)) {
    const host = String(req.host || "").toLowerCase();
    const match = matchTracker(host);
    if (!match) continue;
    const old = grouped.get(host) || { host, entity: match.entity, kind: match.kind, ping: !!match.ping, paths: [] };
    const path = String(req.path || "/");
    if (!old.paths.includes(path) && old.paths.length < 2) old.paths.push(path);
    grouped.set(host, old);
  }
  return {
    label: text(state.label, 80),
    url: text(state.url, 200),
    cookies: arr(state.cookies).slice(0, 120).map((c) => {
      const cls = classifyCookie(c);
      return { name: text(c.name, 80), domain: text(c.domain, 120), cls: cls.cls, reason: cls.reason, platform: cls.platform, firstParty: !!c.firstParty, days: Number.isFinite(c.days) ? Math.trunc(c.days) : null };
    }),
    trackers: [...grouped.values()].slice(0, 60).map((t) => ({ host: text(t.host, 120), entity: text(t.entity, 60), kind: text(t.kind, 30), ping: !!t.ping, paths: list(t.paths, 2, 60) })),
    storageKeys: Math.max(0, Number(state.storageKeys) || 0)
  };
}
function thirdParties(state, domain) {
  if (!state) return [];
  const own = String(domain || "").toLowerCase().replace(/^https?:\/\//, "").split(/[/:?#]/, 1)[0].replace(/^www\./, "");
  const isOwnHost = (host) => !!own && (host === own || host.endsWith(`.${own}`));
  const found = /* @__PURE__ */ new Map();
  for (const req of arr(state.requests)) {
    const host = String(req.host || "").toLowerCase().split(":")[0];
    if (!host || isOwnHost(host)) continue;
    found.set(host, { host, cookies: [] });
  }
  for (const cookie of arr(state.cookies)) {
    if (cookie.firstParty) continue;
    const host = String(cookie.domain || "").toLowerCase().replace(/^\./, "").split(":")[0];
    if (!host || isOwnHost(host)) continue;
    const entry = found.get(host) || { host, cookies: [] };
    if (cookie.name && entry.cookies.length < 20 && !entry.cookies.includes(text(cookie.name, 80))) entry.cookies.push(text(cookie.name, 80));
    found.set(host, entry);
  }
  return [...found.values()].slice(0, 100).map((item) => ({ host: text(item.host, 120), cookies: item.cookies }));
}
function check(i, verdict, observe, preuves, action) {
  return { id: ids[i], titre: titles[i], attendu: expected[i], observe, verdict, preuves: list(preuves, 12, 220), action: action || (verdict === "na" ? "Aucun service Google d\xE9tect\xE9 : aucun r\xE9glage \xE0 examiner ici." : "Aucune action particuli\xE8re sur ce point.") };
}
function buildReport(collecte = {}, meta = {}) {
  const states = collecte.states || {};
  const before = observations(states.avant), refused = observations(states.refus), accepted = observations(states.acceptation);
  const trackers = (o) => o?.trackers.length > 0;
  const trackingCookies = (o) => o?.cookies.some(isTrackCookie) || false;
  const trackedEarlier = !!(trackingCookies(before) || trackers(before) || trackingCookies(refused) || trackers(refused));
  const evidence = (o) => [...o?.cookies.filter(isTrackCookie).map((c) => `Cookie ${c.name} (${c.cls})`) || [], ...o?.trackers.map((t) => `Service contact\xE9 : ${t.host}`) || []];
  const missing = !before || !refused || !accepted;
  const unseenBanner = collecte.bannerPresent !== true;
  const banner = collecte.bannerPresent === true;
  const reject = collecte.reject || {};
  const buttons = arr(collecte.buttons);
  const acceptButton = buttons.find((b) => b.kind === "accept"), rejectButton = buttons.find((b) => b.kind === "reject");
  const similar = acceptButton && rejectButton && Math.abs(Number(acceptButton.w || 0) - Number(rejectButton.w || 0)) <= Math.max(24, Number(acceptButton.w || 0) * 0.35) && Math.abs(Number(acceptButton.h || 0) - Number(rejectButton.h || 0)) <= 12;
  const refusalState = refused ? {
    ...refused,
    cookies: [...arr(states.refus?.cookies), ...arr(collecte.refusNav?.cookies)],
    requests: [...arr(states.refus?.requests), ...arr(collecte.refusNav?.requests)]
  } : null;
  const refusalEvidence = evidence(observations(refusalState));
  const consent = collecte.consentMode || {};
  const gcs = consent.gcs || {};
  const hasGoogle = [before, refused, accepted].some((o) => o?.trackers.some((t) => t.entity === "Google" || t.entity.startsWith("Google ")));
  const longCookies = [states.avant, states.refus, states.acceptation].flatMap((o) => arr(o?.cookies).filter((c) => isTrackCookie(classifyCookie(c)) && Number(c.durationDays ?? c.days) > 395).map((c) => `${c.name} : ${Math.trunc(Number(c.durationDays ?? c.days))} jours`) || []);
  const checks = [
    check(0, !before ? "verifier" : banner ? "ok" : "verifier", !before ? "\xC9tat avant choix non disponible : pr\xE9sence du bandeau \xE0 v\xE9rifier." : banner ? `Bandeau reconnu${collecte.vendors?.length ? ` (${collecte.vendors.join(", ")})` : ""}.` : collecte.blocked ? "Le site a r\xE9pondu par une page de protection anti-robot ou par une page vide : le bandeau n\u2019a pas pu \xEAtre observ\xE9 lors de ce passage automatis\xE9." : trackingCookies(before) || trackers(before) ? "Aucun bandeau reconnu ; des \xE9l\xE9ments de suivi ont \xE9t\xE9 observ\xE9s avant tout choix, mais le bandeau reste \xE0 v\xE9rifier." : "Aucun bandeau n\u2019a \xE9t\xE9 reconnu ; il peut \xEAtre masqu\xE9 au navigateur automatis\xE9.", evidence(before), !banner ? "V\xE9rifier manuellement que le bandeau appara\xEEt lors d\u2019une visite ordinaire." : ""),
    check(1, !before || unseenBanner ? "verifier" : trackingCookies(before) || trackers(before) ? "corriger" : "ok", !before ? "\xC9tat avant choix non disponible." : unseenBanner ? "Le bandeau n\u2019a pas \xE9t\xE9 vu ; le r\xE9sultat avant choix est \xE0 v\xE9rifier." : trackingCookies(before) || trackers(before) ? "Des \xE9l\xE9ments de suivi ont \xE9t\xE9 observ\xE9s avant tout choix." : "Aucun \xE9l\xE9ment de suivi connu observ\xE9 avant tout choix.", evidence(before), trackingCookies(before) || trackers(before) ? "Emp\xEAcher le chargement de ces \xE9l\xE9ments avant le choix." : ""),
    check(2, unseenBanner || !reject.kind || reject.kind === "absent" ? "verifier" : reject.kind === "direct" ? "ok" : "corriger", unseenBanner ? "Bandeau non vu : acc\xE8s au refus \xE0 v\xE9rifier." : reject.kind === "direct" ? "Le refus a \xE9t\xE9 propos\xE9 d\xE8s la premi\xE8re couche." : reject.kind === "parametres" ? "Le refus a \xE9t\xE9 trouv\xE9 dans les param\xE8tres." : reject.kind === "conditionnel" ? "Le refus \xE9tait associ\xE9 \xE0 une condition." : "Aucun acc\xE8s au refus n\u2019a \xE9t\xE9 observ\xE9.", [reject.clicked, reject.alternative].filter(Boolean), reject.kind === "direct" ? "" : "Placer un bouton de refus aussi visible et direct que celui d\u2019acceptation."),
    check(3, unseenBanner || !acceptButton || !rejectButton ? "verifier" : similar ? "ok" : "corriger", unseenBanner ? "Bandeau non vu : poids visuel \xE0 v\xE9rifier." : !acceptButton || !rejectButton ? "Les deux boutons n\u2019ont pas \xE9t\xE9 identifi\xE9s ; leur poids visuel est \xE0 v\xE9rifier." : similar ? "Les boutons Refuser et Accepter ont des dimensions proches." : "Les dimensions des boutons Refuser et Accepter diff\xE8rent nettement.", [], "Comparer la taille, la couleur et la position des deux boutons."),
    check(4, !refused || unseenBanner ? "verifier" : refusalEvidence.length ? "corriger" : "ok", !refused ? "\xC9tat apr\xE8s refus non disponible." : unseenBanner ? "Bandeau non vu : r\xE9sultat apr\xE8s refus \xE0 v\xE9rifier." : refusalEvidence.length ? "Des \xE9l\xE9ments de suivi ont \xE9t\xE9 observ\xE9s apr\xE8s le refus." : "Aucun \xE9l\xE9ment de suivi connu observ\xE9 apr\xE8s le refus.", refusalEvidence, refusalEvidence.length ? "V\xE9rifier que le refus emp\xEAche le chargement de ces \xE9l\xE9ments." : ""),
    check(5, collecte.bannerBackAfterReload === null || collecte.bannerBackAfterReload === void 0 || unseenBanner ? "verifier" : collecte.bannerBackAfterReload ? "corriger" : "ok", unseenBanner ? "Bandeau non vu : m\xE9morisation du choix \xE0 v\xE9rifier." : collecte.bannerBackAfterReload ? "Le bandeau est revenu apr\xE8s rechargement." : "Le bandeau n\u2019est pas revenu apr\xE8s rechargement.", [], collecte.bannerBackAfterReload ? "Conserver le choix et masquer le bandeau apr\xE8s rechargement." : ""),
    check(6, !accepted || unseenBanner ? "verifier" : trackingCookies(accepted) || trackers(accepted) ? "ok" : trackedEarlier ? "verifier" : "na", !accepted ? "\xC9tat apr\xE8s acceptation non disponible." : unseenBanner ? "Bandeau non vu : r\xE9sultat apr\xE8s acceptation \xE0 v\xE9rifier." : trackingCookies(accepted) || trackers(accepted) ? "Des outils de suivi ont \xE9t\xE9 observ\xE9s apr\xE8s acceptation." : trackedEarlier ? "Aucun outil de suivi connu observ\xE9 apr\xE8s acceptation." : "Aucun service de suivi connu sur ce site : \xAB Accepter \xBB n\u2019a rien \xE0 d\xE9clencher.", evidence(accepted), trackedEarlier ? "V\xE9rifier que les outils attendus sont bien reli\xE9s au bouton Accepter." : "Aucune action particuli\xE8re sur ce point."),
    check(7, !hasGoogle ? "na" : unseenBanner || consent.defaultDenied === null || consent.updateOnChoice === null ? "verifier" : consent.defaultDenied && consent.updateOnChoice ? "ok" : "corriger", !hasGoogle ? "Aucun service Google d\xE9tect\xE9 : contr\xF4le sans objet." : consent.defaultDenied === null || consent.updateOnChoice === null ? "Les signaux Consent Mode n\u2019ont pas tous pu \xEAtre observ\xE9s." : consent.defaultDenied && consent.updateOnChoice ? "Refus par d\xE9faut et mise \xE0 jour au choix observ\xE9s." : "Le refus par d\xE9faut ou la mise \xE0 jour au choix n\u2019a pas \xE9t\xE9 observ\xE9.", [gcs.avant, gcs.refus, gcs.acceptation].filter(Boolean).map((v) => `Signal gcs : ${v}`), "V\xE9rifier les valeurs par d\xE9faut et leur mise \xE0 jour lors du choix."),
    check(8, missing || unseenBanner ? "verifier" : longCookies.length ? "corriger" : "ok", missing ? "\xC9tats incomplets : la dur\xE9e des cookies est \xE0 v\xE9rifier." : unseenBanner ? "Bandeau non vu : interpr\xE9tation des cookies \xE0 v\xE9rifier." : longCookies.length ? "Des cookies de suivi d\xE9passant 13 mois ont \xE9t\xE9 observ\xE9s." : "Aucun cookie de suivi d\xE9passant 13 mois observ\xE9.", longCookies, longCookies.length ? "R\xE9duire la dur\xE9e de ces cookies de suivi." : "")
  ];
  const observationsByState = { avant: before, refus: refused, acceptation: accepted };
  return {
    version: 1,
    url: text(collecte.url || meta.url, 200),
    domain: text(collecte.domain || meta.domain, 120),
    date: text(meta.date || (/* @__PURE__ */ new Date()).toISOString(), 40),
    locale: text(meta.locale || collecte.locale || "fr-FR", 10),
    region: text(meta.region || REGION, 60),
    vendors: list(collecte.vendors, 10, 40),
    tcf: !!collecte.tcf,
    banner: { present: banner, actions: buttons.slice(0, 12).map((b) => ({ text: text(b.text, 60), kind: text(b.kind, 20) })) },
    reject: { layer: Number.isFinite(reject.layer) ? Math.trunc(reject.layer) : null, kind: text(reject.kind, 30), clicked: text(reject.clicked, 60), alternative: text(reject.alternative, 60) },
    checks,
    summary: checks.reduce((s, c) => (s[c.verdict]++, s), { ok: 0, verifier: 0, corriger: 0, na: 0 }),
    observations: observationsByState,
    tiersObserves: thirdParties(states.avant, collecte.domain || meta.domain || ""),
    notes: list(collecte.notes, 10, 220),
    limits: list([...LIMITS, ...arr(collecte.limits)], 10, 320)
  };
}

// src/browser-profiles.js
import { rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
async function createBrowserProfile({ directory = tmpdir() } = {}) {
  const path = join(directory, `opencookies-profile-${randomUUID()}`);
  let cleaned = false;
  return {
    path,
    async cleanup() {
      if (cleaned) return;
      cleaned = true;
      await rm(path, { recursive: true, force: true, maxRetries: 3, retryDelay: 100 });
    }
  };
}
function createProfileCleanup() {
  const profiles = /* @__PURE__ */ new Set();
  let cleanupPromise;
  return {
    async create(options) {
      if (cleanupPromise) throw new Error("Nettoyage d\xE9j\xE0 commenc\xE9");
      const profile = await createBrowserProfile(options);
      profiles.add(profile);
      return profile;
    },
    async cleanup() {
      if (!cleanupPromise) cleanupPromise = Promise.allSettled([...profiles].map((profile) => profile.cleanup()));
      await cleanupPromise;
    }
  };
}

// src/scan.js
var isUs = () => (process.env.OC_REGION || config.region) === "us";
var REGION_LABEL = () => isUs() ? "\xC9tats-Unis (GitHub Actions)" : "France (Dunkerque)";
var safeError = (error) => error?.code === "ssrf" ? "URL refus\xE9e" : "\xC9chec du scan";
async function scanJob(job, opts = {}) {
  const collect2 = opts.collect || collect;
  const buildReport2 = opts.buildReport || buildReport;
  const validateUrl = opts.assertPublicUrl || assertPublicUrl;
  const checkRobots = opts.isAllowed || isAllowed;
  const profiles = createProfileCleanup();
  let timer;
  try {
    const run = async () => {
      await validateUrl(job.url, { allowLocal: opts.allowLocal });
      if (!await checkRobots(job.url, opts.userAgent || "OpenCookiesBot", { allowLocal: opts.allowLocal }))
        return { status: "refused", error: "Acc\xE8s interdit par robots.txt" };
      const collecte = await collect2(opts.browser, job.url, { ...opts, profileCleanup: profiles, locale: job.locale, ...isUs() && !opts.contextOptions ? { contextOptions: { locale: "en-US", timezoneId: "America/New_York" } } : {} });
      const report = await buildReport2(collecte, { id: job.id, url: job.url, domain: job.domain, region: REGION_LABEL(), locale: isUs() ? "en-US" : "fr-FR", timezone: isUs() ? "America/New_York" : "Europe/Paris" });
      return { status: "done", report, shots: Object.fromEntries(["avant", "refus", "acceptation"].map((k) => [k, collecte.states?.[k]?.shot]).filter(([, v]) => typeof v === "string")) };
    };
    return await Promise.race([run(), new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error("timeout")), opts.timeoutMs ?? 11e4);
    })]);
  } catch (error) {
    return { status: "failed", error: safeError(error) };
  } finally {
    clearTimeout(timer);
    await profiles.cleanup();
    try {
      await opts.cleanup?.();
    } catch {
    }
  }
}

// src/worker.js
init_log();
import { mkdir, readdir, readFile, rename, rm as rm2, writeFile } from "node:fs/promises";
import { join as join2 } from "node:path";
import { randomUUID as randomUUID2 } from "node:crypto";
async function runWorker(opts = {}) {
  const ingest = opts.ingest || ingest_client_exports;
  const log = opts.logger || logger;
  const concurrency = Math.min(2, Math.max(1, opts.concurrency || config.concurrency));
  const active = /* @__PURE__ */ new Set();
  const stateDir = opts.stateDir || join2(process.cwd(), ".worker-state");
  const retryMs = opts.retryMs ?? 1e3;
  let stopping = false;
  const stop = () => {
    stopping = true;
  };
  await mkdir(stateDir, { recursive: true });
  const persist = async (id, value) => {
    const target = join2(stateDir, `${id}.json`);
    const temporary = `${target}.${randomUUID2()}.tmp`;
    await writeFile(temporary, JSON.stringify(value), { flag: "wx" });
    await rename(temporary, target);
  };
  const pendingJobs = [];
  for (const file of await readdir(stateDir)) {
    if (!/^[a-f0-9]{24}\.json$/i.test(file)) continue;
    try {
      const state = JSON.parse(await readFile(join2(stateDir, file), "utf8"));
      if (state.job?.id && state.result) pendingJobs.push(state);
      else if (state.job?.id) pendingJobs.push({ job: state.job });
    } catch {
    }
  }
  const pause = () => new Promise((resolve2) => setTimeout(resolve2, retryMs));
  const execute = async (job) => {
    const statePath = join2(stateDir, `${job.id}.json`);
    let result = pendingJobs.find((item) => item.job.id === job.id)?.result;
    if (!result) {
      await persist(job.id, { job });
      try {
        result = await (opts.scanJob || scanJob)(job, opts.scanOptions || opts);
      } catch {
        result = { status: "failed", error: "\xC9chec du scan" };
      }
      log.log("info", "scan.finished", { status: result.status, region: job.region });
      await persist(job.id, { job, result });
    }
    while (!stopping) {
      try {
        await ingest.submit({ id: job.id, ...result });
        log.log("info", "job.submitted", { status: result.status, region: job.region });
        await rm2(statePath, { force: true });
        return;
      } catch {
        log.log("warn", "job.submit_retry", { region: job.region });
        if (stopping) return;
        await pause();
      }
    }
  };
  const recovered = pendingJobs.slice();
  const workers = Array.from({ length: concurrency }, async () => {
    while (!stopping) {
      try {
        const recoveredState = recovered.shift();
        if (recoveredState) {
          const promise2 = execute(recoveredState.job);
          active.add(promise2);
          try {
            await promise2;
          } finally {
            active.delete(promise2);
          }
          continue;
        }
        const job = await ingest.claim();
        if (!job) {
          await new Promise((resolve2) => setTimeout(resolve2, opts.pollMs ?? config.pollMs));
          continue;
        }
        await persist(job.id, { job });
        const promise = execute(job);
        active.add(promise);
        try {
          await promise;
        } finally {
          active.delete(promise);
        }
      } catch {
        log.log("warn", "worker.poll_retry");
        await new Promise((resolve2) => setTimeout(resolve2, opts.pollMs ?? config.pollMs));
      }
    }
  });
  await new Promise((resolve2) => {
    if (opts.signal?.aborted) return resolve2();
    opts.signal?.addEventListener("abort", resolve2, { once: true });
    if (opts.waitForStop) opts.waitForStop(stop);
  });
  stop();
  await Promise.all(workers);
  await Promise.allSettled(active);
}

// src/index.js
import { chromium } from "playwright";
import { pathToFileURL } from "node:url";
import { resolve } from "node:path";
async function startRunner({ signal, browser, ...options } = {}) {
  const ownedBrowser = !browser;
  const instance = browser || await chromium.launch({ headless: true });
  try {
    const jobs = [runWorker({ ...options, browser: instance, signal })];
    if (process.env.FC_INGEST_KEY || process.env.FC_AUTH === "oidc") jobs.push(Promise.resolve().then(() => (init_fc_worker(), fc_worker_exports)).then((m) => m.runFcWorker({ browser: instance, signal })));
    await Promise.all(jobs);
  } finally {
    if (ownedBrowser) await instance.close().catch(() => {
    });
  }
}
if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  const controller = new AbortController();
  for (const signal of ["SIGINT", "SIGTERM"]) process.once(signal, () => controller.abort());
  startRunner({ signal: controller.signal }).catch(() => {
    process.exitCode = 1;
  });
}
export {
  startRunner
};
