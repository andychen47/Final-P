document.addEventListener("DOMContentLoaded", () => {
  const input = document.getElementById("urlInput");
  const button = document.getElementById("scanBtn");
  const statusDiv = document.getElementById("status");
  const resultDiv = document.getElementById("result");
  const chartCanvas = document.getElementById("riskChart");

  const URLSCAN_API_KEY = "019a8ea0-dace-7737-a633-dc0bb80abe27";

  function normalizeUrl(value) {
    const v = value.trim();
    if (!v) return "";
    return /^https?:\/\//i.test(v) ? v : "https://" + v;
  }

  function startScanningAnimation() {
    statusDiv.textContent = "Scanning";
    statusDiv.style.opacity = "1";

    const anim = anime({
      targets: statusDiv,
      opacity: [0.35, 1],
      duration: 650,
      direction: "alternate",
      loop: true,
      easing: "easeInOutSine"
    });

    let dots = 0;
    const interval = setInterval(() => {
      dots = (dots + 1) % 4;
      statusDiv.textContent = "Scanning" + ".".repeat(dots);
    }, 420);

    return () => {
      anim.pause();
      clearInterval(interval);
      statusDiv.textContent = "";
      statusDiv.style.opacity = "1";
    };
  }

  function loadCounts() {
    try {
      const raw = localStorage.getItem("scanCounts");
      if (!raw) return { safe: 0, suspicious: 0, malicious: 0 };
      const obj = JSON.parse(raw);
      return {
        safe: Number(obj.safe) || 0,
        suspicious: Number(obj.suspicious) || 0,
        malicious: Number(obj.malicious) || 0
      };
    } catch {
      return { safe: 0, suspicious: 0, malicious: 0 };
    }
  }

  function saveCounts(counts) {
    localStorage.setItem("scanCounts", JSON.stringify(counts));
  }

  let counts = loadCounts();

  const chart = new Chart(chartCanvas, {
    type: "bar",
    data: {
      labels: ["Safe", "Suspicious", "Malicious"],
      datasets: [
        {
          label: "Scan Results",
          data: [counts.safe, counts.suspicious, counts.malicious]
        }
      ]
    },
    options: {
      responsive: true,
      plugins: {
        legend: { display: true }
      },
      scales: {
        y: { beginAtZero: true, ticks: { precision: 0 } }
      }
    }
  });

  function updateChart() {
    chart.data.datasets[0].data = [counts.safe, counts.suspicious, counts.malicious];
    chart.update();
  }

  async function checkPhishStats(urlText) {
    const domain = new URL(urlText).hostname.toLowerCase();

    const endpoint =
      "https://api.phishstats.info/api/phishing" +
      "?_where=(url,like," +
      encodeURIComponent(domain) +
      ")&_size=10&_sort=-date";

    const res = await fetch(endpoint);
    if (!res.ok) throw new Error("PhishStats failed");

    const data = await res.json();
    const matches = Array.isArray(data) ? data : [];

    return {
      domain,
      matches,
      isPhishing: matches.length > 0
    };
  }

  async function checkUrlscan(urlText) {
    const submitRes = await fetch("https://urlscan.io/api/v1/scan/", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "API-Key": URLSCAN_API_KEY
      },
      body: JSON.stringify({
        url: urlText,
        visibility: "public"
      })
    });

    if (!submitRes.ok) throw new Error("urlscan submit failed");
    const submitData = await submitRes.json();
    const uuid = submitData.uuid;

    for (let i = 0; i < 10; i++) {
      await new Promise(r => setTimeout(r, 3000));

      const resultRes = await fetch(`https://urlscan.io/api/v1/result/${uuid}/`);
      if (resultRes.status === 404) continue;
      if (!resultRes.ok) throw new Error("urlscan result failed");

      const data = await resultRes.json();
      const verdict = data.verdicts?.overall || {};
      const tags = Array.isArray(verdict.tags) ? verdict.tags : [];

      let status = "Safe";
      if (verdict.malicious === true) status = "Malicious";
      else if (verdict.score >= 50 || tags.includes("phishing") || tags.includes("malware")) {
        status = "Suspicious";
      }

      return {
        status,
        score: verdict.score ?? null,
        tags,
        reportUrl: data?.task?.reportURL || null
      };
    }

    throw new Error("urlscan timeout");
  }

  button.addEventListener("click", async () => {
    const normalized = normalizeUrl(input.value);

    if (!normalized) {
      alert("Please enter a URL.");
      return;
    }

    let parsed;
    try {
      parsed = new URL(normalized);
    } catch {
      resultDiv.textContent = "Invalid URL.";
      return;
    }

    const stopAnim = startScanningAnimation();
    resultDiv.textContent = "";
    button.disabled = true;

    try {
      const [phish, scan] = await Promise.all([
        checkPhishStats(parsed.href),
        checkUrlscan(parsed.href)
      ]);
      stopAnim();
      if (scan.status === "Malicious") counts.malicious += 1;
      else if (scan.status === "Suspicious") counts.suspicious += 1;
      else counts.safe += 1;
      saveCounts(counts);
      updateChart();
      let text = "";
      text += "Site: " + phish.domain + "\n\n";
      if (phish.isPhishing) {
        const latest = phish.matches[0] || {};
        text += "PhishStats: phishing record found\n";
        text += "Matches: " + phish.matches.length + "\n";
        text += "Latest URL: " + (latest.url || "Unknown") + "\n";
        text += "Brand: " + (latest.brand || "Unknown") + "\n";
        text += "Date: " + (latest.date || "Unknown") + "\n\n";
      } else {
        text += "PhishStats: no phishing records found\n\n";
      }

      text += "urlscan.io: " + scan.status + "\n";
      text += "Score: " + (scan.score ?? "N/A") + "\n";
      text += "Tags: " + (scan.tags.length ? scan.tags.join(", ") : "None") + "\n";
      if (scan.reportUrl) text += "Report: " + scan.reportUrl + "\n";

      resultDiv.textContent = text;
    } catch {
      stopAnim();
      resultDiv.textContent = "Error running checks.";
    } finally {
      button.disabled = false;
    }
  });
});
