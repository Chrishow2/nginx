import archiver from "archiver";
import express from "express";
import { execFile, spawn } from "node:child_process";
import { promisify } from "node:util";
import crypto from "node:crypto";
import fs from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const execFileAsync = promisify(execFile);

const __dirname = path.dirname(fileURLToPath(import.meta.url));

const CONF_DIR = process.env.CONF_DIR ?? "/etc/nginx/conf.d";
const LETSENCRYPT_LIVE = process.env.LETSENCRYPT_LIVE ?? "/etc/letsencrypt/live";
const WEBROOT = process.env.ACME_WEBROOT ?? "/var/www/certbot";
const NGINX_CONTAINER = process.env.NGINX_CONTAINER ?? "nginx_host";
const PORT = Number(process.env.PORT ?? "8080", 10);
const PROXY_TO_HOST_ALIAS = process.env.PROXY_TO_HOST_ALIAS ?? "host.docker.internal";

const DNS_TMP = path.join(__dirname, "tmp", "dns");
const AUTH_HOOK = path.join(__dirname, "hooks", "dns-auth.sh");
const CLEANUP_HOOK = path.join(__dirname, "hooks", "dns-cleanup.sh");

const DOMAIN_RE = /^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$/;
const SKIP_LIST = new Set(["default.conf"]);

const dnsJobs = new Map();

function proxyBlock(upstream) {
  return `    location / {
        proxy_pass ${upstream};
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }`;
}

function httpServerBlock(domain, upstream) {
  return `server {
    listen 80;
    server_name ${domain};

    location /.well-known/acme-challenge/ {
        root ${WEBROOT};
    }

${proxyBlock(upstream)}
}
`;
}

function tlsServerBlocks(domain, upstream, certName) {
  const c = certName && String(certName).trim() ? String(certName).trim() : domain;
  return `server {
    listen 80;
    server_name ${domain};

    location /.well-known/acme-challenge/ {
        root ${WEBROOT};
    }

    location / {
        return 301 https://$host$request_uri;
    }
}

server {
    listen 443 ssl;
    server_name ${domain};
    ssl_certificate ${LETSENCRYPT_LIVE.replace(/\\/g, "/")}/${c}/fullchain.pem;
    ssl_certificate_key ${LETSENCRYPT_LIVE.replace(/\\/g, "/")}/${c}/privkey.pem;

${proxyBlock(upstream)}
}
`;
}

function validateDomain(d) {
  if (!d || !DOMAIN_RE.test(d)) {
    throw new Error("invalid server name");
  }
}

function validateUpstream(u) {
  let url;
  try {
    url = new URL(u);
  } catch {
    throw new Error("invalid upstream URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("upstream must be http or https");
  }
  return url.toString().replace(/\/$/, "") || u;
}

function upstreamForNginxContainer(u) {
  if (!PROXY_TO_HOST_ALIAS) return u;
  try {
    const url = new URL(u);
    if (url.hostname === "127.0.0.1" || url.hostname === "localhost") {
      url.hostname = PROXY_TO_HOST_ALIAS;
      return url.toString().replace(/\/$/, "");
    }
  } catch {
    /* fall through */
  }
  return u;
}

function upstreamForDisplay(u) {
  if (!PROXY_TO_HOST_ALIAS || !u) return u;
  try {
    const url = new URL(u);
    if (url.hostname === PROXY_TO_HOST_ALIAS) {
      url.hostname = "127.0.0.1";
      return url.toString().replace(/\/$/, "");
    }
  } catch {
    /* fall through */
  }
  return u;
}

function confPathForDomain(domain) {
  return path.join(CONF_DIR, `${domain}.conf`);
}

function safeConfBasename(name) {
  const base = path.basename(name);
  if (!/^[a-zA-Z0-9._-]+\.conf$/.test(base) || base.includes("..")) {
    throw new Error("invalid config file name");
  }
  return base;
}

async function reloadNginx() {
  await execFileAsync("docker", ["exec", NGINX_CONTAINER, "nginx", "-s", "reload"], {
    timeout: 60_000,
  });
}

async function runCertbotHttp(domain, email) {
  await execFileAsync(
    "certbot",
    [
      "certonly",
      "--webroot",
      "-w",
      WEBROOT,
      "-d",
      domain,
      "--email",
      email,
      "--agree-tos",
      "--non-interactive",
      "--no-eff-email",
    ],
    { timeout: 300_000 },
  );
}

function parseConfText(text) {
  const sn = text.match(/server_name\s+([^;]+);/);
  const names = sn
    ? sn[1]
        .trim()
        .split(/\s+/)
        .map((s) => s.trim())
        .filter(Boolean)
    : [];
  const hasSsl = /\blisten\s+443\s+ssl\b/.test(text) || /\bssl_certificate\b/.test(text);
  const pp = text.match(/proxy_pass\s+([^;]+);/);
  const upstreamRaw = pp ? pp[1].trim() : null;
  const sslPath = text.match(/ssl_certificate\s+([^;]+);/);
  let ssl_cert_name = null;
  if (sslPath) {
    const p = sslPath[1].trim();
    const liveNorm = path.normalize(LETSENCRYPT_LIVE).replace(/\\/g, "/");
    const m = p.replace(/\\/g, "/").match(
      new RegExp("^" + liveNorm.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") + "/([^/]+)/fullchain\\.pem$"),
    );
    if (m) ssl_cert_name = m[1];
  }
  return {
    server_names: names,
    has_ssl: hasSsl,
    upstream: upstreamRaw,
    upstream_display: upstreamRaw ? upstreamForDisplay(upstreamRaw) : null,
    ssl_cert_name,
  };
}

async function finishDnsJob(job, code, stderr) {
  if (code === 0) {
    job.status = "success";
  } else {
    job.status = "error";
    job.error = stderr?.trim() || `certbot exited with code ${code}`;
  }
  job.done = true;
  setTimeout(() => dnsJobs.delete(job.id), 600_000);
}

/**
 * @param {string} domain
 * @param {string} email
 */
async function startDnsCertJob(domain, email) {
  for (const j of dnsJobs.values()) {
    if (j.domain === domain && !j.done) {
      throw new Error("a certificate job is already running for this domain");
    }
  }

  await fs.mkdir(DNS_TMP, { recursive: true });
  await fs.rm(path.join(DNS_TMP, `${domain}.validation`), { force: true });
  await fs.rm(path.join(DNS_TMP, `${domain}.continue`), { force: true });

  const id = crypto.randomUUID();
  const job = {
    id,
    domain,
    email,
    status: "starting",
    txtName: null,
    txtValue: null,
    error: null,
    done: false,
  };
  dnsJobs.set(id, job);

  const proc = spawn(
    "certbot",
    [
      "certonly",
      "--manual",
      "--preferred-challenges",
      "dns",
      "--manual-auth-hook",
      AUTH_HOOK,
      "--manual-cleanup-hook",
      CLEANUP_HOOK,
      "-d",
      domain,
      "--email",
      email,
      "--agree-tos",
      "--non-interactive",
      "--no-eff-email",
      "--manual-public-ip-logging-ok",
    ],
    { stdio: ["ignore", "pipe", "pipe"] },
  );

  let stderr = "";
  proc.stderr?.on("data", (c) => {
    stderr += c;
  });

  const poll = setInterval(() => {
    void (async () => {
      try {
        const valPath = path.join(DNS_TMP, `${domain}.validation`);
        const buf = await fs.readFile(valPath, "utf8");
        if (buf !== undefined && job.status === "starting") {
          job.status = "dns_wait";
          job.txtName = `_acme-challenge.${domain}`;
          job.txtValue = buf.trim();
          clearInterval(poll);
        }
      } catch {
        /* file missing */
      }
    })();
  }, 400);

  proc.on("close", (code) => {
    clearInterval(poll);
    void finishDnsJob(job, code ?? -1, stderr);
  });

  return job;
}

async function listVhosts() {
  const entries = await fs.readdir(CONF_DIR, { withFileTypes: true });
  const out = [];
  for (const e of entries) {
    if (!e.isFile() || !e.name.endsWith(".conf")) continue;
    if (SKIP_LIST.has(e.name)) continue;
    const full = path.join(CONF_DIR, e.name);
    const text = await fs.readFile(full, "utf8");
    const meta = parseConfText(text);
    out.push({
      filename: e.name,
      server_names: meta.server_names,
      has_ssl: meta.has_ssl,
      upstream: meta.upstream_display,
    });
  }
  out.sort((a, b) => a.filename.localeCompare(b.filename));
  return out;
}

const CERT_NAME_RE = /^[a-zA-Z0-9]([a-zA-Z0-9._-]*[a-zA-Z0-9])?$/;

function safeCertificateName(s) {
  if (s == null) return null;
  const t = String(s).trim();
  if (t === "") return null;
  if (t.length === 1) {
    if (!/^[a-zA-Z0-9]$/.test(t)) {
      throw new Error("invalid certificate name");
    }
    return t;
  }
  if (!CERT_NAME_RE.test(t) || t.includes("..") || t.includes("/") || t.includes("\\")) {
    throw new Error("invalid certificate name");
  }
  return t;
}

async function listCertNames() {
  let entries;
  try {
    entries = await fs.readdir(LETSENCRYPT_LIVE, { withFileTypes: true });
  } catch (e) {
    if (e?.code === "ENOENT") {
      return [];
    }
    throw e;
  }
  const out = [];
  for (const e of entries) {
    if (!e.isDirectory()) continue;
    const name = e.name;
    if (name === "." || name === ".." || name.includes("..") || /[/\\]/.test(name)) continue;
    const full = path.join(LETSENCRYPT_LIVE, name);
    try {
      await fs.access(path.join(full, "fullchain.pem"));
      await fs.access(path.join(full, "privkey.pem"));
      out.push(name);
    } catch {
      /* incomplete cert dir */
    }
  }
  out.sort((a, b) => a.localeCompare(b));
  return out;
}

/**
 * vhost conf files in CONF_DIR (excluding default) that reference a live cert name in ssl_certificate.
 * @returns {Promise<Map<string, { filename: string, server_names: string[] }[]>>}
 */
async function vhostsUsingCertName() {
  const map = new Map();
  const entries = await fs.readdir(CONF_DIR, { withFileTypes: true });
  for (const e of entries) {
    if (!e.isFile() || !e.name.endsWith(".conf")) continue;
    if (SKIP_LIST.has(e.name)) continue;
    const full = path.join(CONF_DIR, e.name);
    const text = await fs.readFile(full, "utf8");
    const meta = parseConfText(text);
    if (!meta.ssl_cert_name) continue;
    const k = meta.ssl_cert_name;
    if (!map.has(k)) {
      map.set(k, []);
    }
    map.get(k).push({ filename: e.name, server_names: meta.server_names || [] });
  }
  return map;
}

async function listCertificatesWithUsage() {
  const names = await listCertNames();
  const usage = await vhostsUsingCertName();
  return names.map((name) => {
    const used = usage.get(name) || [];
    return {
      name,
      in_use: used.length > 0,
      used_by: used,
    };
  });
}

async function assertCertificateExists(name) {
  await fs.access(path.join(LETSENCRYPT_LIVE, name, "fullchain.pem"));
  await fs.access(path.join(LETSENCRYPT_LIVE, name, "privkey.pem"));
}

const app = express();
app.use(express.json({ limit: "48kb" }));

app.get("/api/vhosts", async (_req, res) => {
  try {
    res.json({ vhosts: await listVhosts() });
  } catch (e) {
    res.status(500).json({ error: String(e.message ?? e) });
  }
});

app.get("/api/certificates", async (_req, res) => {
  try {
    res.json({ certificates: await listCertificatesWithUsage() });
  } catch (e) {
    res.status(500).json({ error: String(e.message ?? e) });
  }
});

app.get("/api/certificates/:name/download", async (req, res) => {
  let name;
  try {
    name = safeCertificateName(String(req.params.name || ""));
  } catch {
    res.status(400).json({ error: "invalid certificate name" });
    return;
  }
  if (!name) {
    res.status(400).json({ error: "invalid certificate name" });
    return;
  }
  try {
    await assertCertificateExists(name);
  } catch (e) {
    if (e?.code === "ENOENT") {
      res.status(404).json({ error: "certificate not found" });
      return;
    }
    res.status(500).json({ error: String(e.message ?? e) });
    return;
  }
  const certDir = path.join(LETSENCRYPT_LIVE, name);
  res.setHeader("Content-Type", "application/zip");
  res.setHeader(
    "Content-Disposition",
    `attachment; filename="${name.replace(/[^\w!-.]/g, "_")}.zip"`,
  );
  const archive = archiver("zip", { zlib: { level: 9 } });
  archive.on("error", (err) => {
    if (!res.headersSent) {
      res.status(500).json({ error: String(err.message) });
    }
  });
  archive.pipe(res);
  archive.file(path.join(certDir, "fullchain.pem"), { name: "fullchain.pem" });
  archive.file(path.join(certDir, "privkey.pem"), { name: "privkey.pem" });
  try {
    await archive.finalize();
  } catch (e) {
    if (!res.headersSent) {
      res.status(500).json({ error: String(e.message ?? e) });
    }
  }
});

app.delete("/api/certificates/:name", async (req, res) => {
  let name;
  try {
    name = safeCertificateName(String(req.params.name || ""));
  } catch {
    res.status(400).json({ error: "invalid certificate name" });
    return;
  }
  if (!name) {
    res.status(400).json({ error: "invalid certificate name" });
    return;
  }
  try {
    const used = (await vhostsUsingCertName()).get(name) || [];
    if (used.length > 0) {
      res.status(409).json({
        error: "certificate is in use by a proxy host",
        used_by: used,
      });
      return;
    }
    try {
      await assertCertificateExists(name);
    } catch (e) {
      if (e?.code === "ENOENT") {
        res.status(404).json({ error: "certificate not found" });
        return;
      }
      throw e;
    }
    await execFileAsync(
      "certbot",
      ["delete", "--cert-name", name, "--non-interactive", "--config-dir", path.dirname(LETSENCRYPT_LIVE)],
      { timeout: 120_000 },
    );
    res.json({ ok: true });
  } catch (e) {
    const msg = String((e && e.stderr) || (e && e.stdout) || e?.message || e);
    res.status(500).json({ error: msg });
  }
});

app.get("/api/vhosts/file/:name", async (req, res) => {
  try {
    const base = safeConfBasename(req.params.name);
    if (SKIP_LIST.has(base)) {
      res.status(400).json({ error: "cannot edit protected config" });
      return;
    }
    const full = path.join(CONF_DIR, base);
    const text = await fs.readFile(full, "utf8");
    const meta = parseConfText(text);
    res.json({
      filename: base,
      server_names: meta.server_names,
      has_ssl: meta.has_ssl,
      upstream: meta.upstream_display,
      ssl_cert_name: meta.ssl_cert_name,
      domain: path.basename(base, ".conf"),
    });
  } catch (e) {
    if (e?.code === "ENOENT") {
      res.status(404).json({ error: "not found" });
      return;
    }
    res.status(500).json({ error: String(e.message ?? e) });
  }
});

app.put("/api/vhosts/:name", async (req, res) => {
  try {
    const base = safeConfBasename(req.params.name);
    if (SKIP_LIST.has(base)) {
      res.status(400).json({ error: "cannot edit protected config" });
      return;
    }
    const oldPath = path.join(CONF_DIR, base);
    const oldDomain = path.basename(base, ".conf");
    const body = req.body ?? {};
    const newDomain = (body.server_name?.trim() || oldDomain);
    validateDomain(newDomain);
    const up = upstreamForNginxContainer(validateUpstream(body.upstream));
    const certIn = body.certificate;
    const certPicked = certIn != null && String(certIn).trim() !== "";
    const certName = certPicked ? safeCertificateName(String(certIn)) : null;

    const text = await fs.readFile(oldPath, "utf8");
    const meta = parseConfText(text);

    if (meta.has_ssl && newDomain !== oldDomain) {
      res.status(400).json({ error: "cannot rename TLS vhost; remove HTTPS config first or recreate" });
      return;
    }

    if (certPicked) {
      await assertCertificateExists(certName);
    }

    let target = oldPath;
    if (newDomain !== oldDomain) {
      target = confPathForDomain(newDomain);
      await fs.unlink(oldPath);
    }

    let bodyText;
    if (certPicked) {
      bodyText = tlsServerBlocks(newDomain, up, certName);
    } else {
      bodyText = httpServerBlock(newDomain, up);
    }
    await fs.writeFile(target, bodyText, "utf8");
    await reloadNginx();
    res.json({ ok: true, filename: path.basename(target) });
  } catch (e) {
    if (e?.code === "ENOENT") {
      res.status(404).json({ error: "not found" });
      return;
    }
    const msg = String(e.message ?? e);
    const code = msg.includes("invalid") ? 400 : 500;
    res.status(code).json({ error: msg });
  }
});

app.post("/api/vhosts", async (req, res) => {
  try {
    const { server_name: domain, upstream: up } = req.body ?? {};
    validateDomain(domain);
    const upstream = upstreamForNginxContainer(validateUpstream(up));
    const target = confPathForDomain(domain);
    await fs.writeFile(target, httpServerBlock(domain, upstream), "utf8");
    await reloadNginx();
    res.json({ ok: true });
  } catch (e) {
    const msg = String(e.message ?? e);
    const code = msg.includes("invalid") ? 400 : 500;
    res.status(code).json({ error: msg });
  }
});

app.get("/api/cert/jobs/:id", (req, res) => {
  const job = dnsJobs.get(req.params.id);
  if (!job) {
    res.status(404).json({ error: "job not found" });
    return;
  }
  res.json({
    id: job.id,
    domain: job.domain,
    status: job.status,
    done: job.done,
    txtName: job.txtName,
    txtValue: job.txtValue,
    error: job.error,
  });
});

app.post("/api/cert/jobs/:id/continue", async (req, res) => {
  const job = dnsJobs.get(req.params.id);
  if (!job) {
    res.status(404).json({ error: "job not found" });
    return;
  }
  if (job.status !== "dns_wait") {
    res.status(400).json({ error: "job is not waiting for DNS record" });
    return;
  }
  try {
    await fs.writeFile(path.join(DNS_TMP, `${job.domain}.continue`), "", "utf8");
    job.status = "verifying";
    res.json({ ok: true });
  } catch (e) {
    res.status(500).json({ error: String(e.message ?? e) });
  }
});

app.post("/api/cert", async (req, res) => {
  try {
    const { server_name: domain, email, challenge: ch } = req.body ?? {};
    const challenge = ch === "dns" ? "dns" : "http";
    validateDomain(domain);
    if (!email || !String(email).includes("@")) {
      res.status(400).json({ error: "valid email required" });
      return;
    }

    if (challenge === "http") {
      const target = confPathForDomain(domain);
      try {
        await fs.access(target);
      } catch (e) {
        if (e?.code === "ENOENT") {
          res
            .status(400)
            .json({ error: "create an HTTP proxy host for this name first (needed for the ACME challenge)" });
          return;
        }
        throw e;
      }
      await runCertbotHttp(domain, String(email).trim());
      res.json({ ok: true });
      return;
    }

    const job = await startDnsCertJob(domain, String(email).trim());
    res.json({ ok: true, asyncCert: true, jobId: job.id });
  } catch (e) {
    res.status(500).json({ error: String(e.stderr ?? e.message ?? e) });
  }
});

app.delete("/api/vhosts/:name", async (req, res) => {
  try {
    const base = safeConfBasename(req.params.name);
    if (SKIP_LIST.has(base)) {
      res.status(400).json({ error: "cannot delete protected config" });
      return;
    }
    await fs.unlink(path.join(CONF_DIR, base));
    await reloadNginx();
    res.json({ ok: true });
  } catch (e) {
    if (e?.code === "ENOENT") {
      res.status(404).json({ error: "not found" });
      return;
    }
    res.status(500).json({ error: String(e.message ?? e) });
  }
});

app.use(express.static(path.join(__dirname, "public")));

app.listen(PORT, () => {
  void fs.mkdir(DNS_TMP, { recursive: true });
  console.error(`vhost-ui listening on :${PORT}`);
});
