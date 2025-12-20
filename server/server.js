require("dotenv").config();

const http = require("http");
const { createClient } = require("@supabase/supabase-js");

const hostName = "127.0.0.1";
const port = process.env.PORT || 3000;

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_KEY);
const URLSCAN_API_KEY = process.env.URLSCAN_API_KEY;

function sendJson(res, statusCode, payload) {
  res.writeHead(statusCode, { "Content-Type": "application/json" });
  res.end(JSON.stringify(payload));
}

const server = http.createServer((req, res) => {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS");

  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  if (req.url === "/" && req.method === "GET") {
    sendJson(res, 200, { message: "Backend is running" });
    return;
  }

  if (req.url === "/test-db" && req.method === "GET") {
    (async () => {
      const { data, error } = await supabase.from("scan_history").select("*").limit(5);
      if (error) return sendJson(res, 500, { success: false, error: error.message });
      sendJson(res, 200, { success: true, data });
    })();
    return;
  }

  if (req.url === "/save-scan" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => (body += chunk.toString()));
    req.on("end", async () => {
      try {
        const { url, result } = JSON.parse(body);
        if (!url || !result) return sendJson(res, 400, { error: "url and result are required" });

        const { data, error } = await supabase
          .from("scan_history")
          .insert([{ url, result }])
          .select()
          .single();

        if (error) return sendJson(res, 500, { error: error.message });
        sendJson(res, 200, { success: true, data });
      } catch {
        sendJson(res, 400, { error: "Invalid JSON body" });
      }
    });
    return;
  }

  if (req.url === "/urlscan" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => (body += chunk.toString()));
    req.on("end", async () => {
      try {
        if (!URLSCAN_API_KEY) return sendJson(res, 500, { error: "URLSCAN_API_KEY missing in .env" });

        const { url } = JSON.parse(body);
        if (!url) return sendJson(res, 400, { error: "url is required" });

        const submitRes = await fetch("https://urlscan.io/api/v1/scan/", {
          method: "POST",
          headers: {
            "Content-Type": "application/json",
            "API-Key": URLSCAN_API_KEY
          },
          body: JSON.stringify({ url, visibility: "public" })
        });

        if (!submitRes.ok) {
          const details = await submitRes.text();
          return sendJson(res, 502, { error: "urlscan submit failed", details });
        }

        const submitData = await submitRes.json();
        const uuid = submitData.uuid;

        for (let i = 0; i < 10; i++) {
          await new Promise((r) => setTimeout(r, 3000));

          const resultRes = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`);
          if (resultRes.status === 404) continue;

          if (!resultRes.ok) {
            const details = await resultRes.text();
            return sendJson(res, 502, { error: "urlscan result failed", details });
          }

          const data = await resultRes.json();
          const verdict = data.verdicts?.overall || {};
          const tags = Array.isArray(verdict.tags) ? verdict.tags : [];

          let status = "Safe";
          if (verdict.malicious === true) status = "Malicious";
          else if (verdict.score >= 50 || tags.includes("phishing") || tags.includes("malware")) status = "Suspicious";

          return sendJson(res, 200, {
            status,
            score: verdict.score ?? null,
            tags,
            reportUrl: data?.task?.reportURL || null
          });
        }

        sendJson(res, 504, { error: "urlscan timeout" });
      } catch {
        sendJson(res, 400, { error: "Invalid JSON body" });
      }
    });
    return;
  }

  sendJson(res, 404, { error: "Route not found" });
});

server.listen(port, hostName, () => {
  console.log(`Server running at http://${hostName}:${port}`);
});
