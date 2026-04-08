const apiBaseInput = document.getElementById("apiBase");
const fileInput = document.getElementById("fileInput");
const output = document.getElementById("output");
const badge = document.getElementById("statusBadge");

const buttons = {
  health: document.getElementById("btnHealth"),
  local: document.getElementById("btnLocal"),
  example: document.getElementById("btnExample"),
  upload: document.getElementById("btnUpload")
};

function setBadge(type, text) {
  badge.className = "badge";
  if (type) {
    badge.classList.add(type);
  }
  badge.textContent = text;
}

function printResult(title, responseStatus, payload) {
  const formatted = JSON.stringify(payload, null, 2);
  output.textContent = `${title}\nHTTP ${responseStatus}\n\n${formatted}`;

  if (responseStatus >= 500 || payload.status === "error") {
    setBadge("error", "ERROR");
    return;
  }

  if (responseStatus === 422 || payload.status === "failed") {
    setBadge("warn", "VULNERABLE");
    return;
  }

  if (responseStatus >= 200 && responseStatus < 300) {
    setBadge("ok", "SEGURO");
    return;
  }

  setBadge("error", "REVISA RESPUESTA");
}

async function callJsonEndpoint(path) {
  const base = apiBaseInput.value.trim().replace(/\/$/, "");
  const url = `${base}${path}`;

  try {
    setBadge("", "EJECUTANDO");
    const res = await fetch(url);
    const payload = await res.json();
    printResult(`GET ${path}`, res.status, payload);
  } catch (err) {
    setBadge("error", "ERROR RED");
    output.textContent = `No se pudo conectar con la API.\n\n${String(err)}`;
  }
}

async function uploadAndScan() {
  const selected = fileInput.files[0];
  if (!selected) {
    setBadge("warn", "FALTA ARCHIVO");
    output.textContent = "Selecciona un archivo .txt para escanear.";
    return;
  }

  const base = apiBaseInput.value.trim().replace(/\/$/, "");
  const url = `${base}/scan`;
  const formData = new FormData();
  formData.append("file", selected);

  try {
    setBadge("", "SUBIENDO");
    const res = await fetch(url, {
      method: "POST",
      body: formData
    });

    const payload = await res.json();
    printResult("POST /scan", res.status, payload);
  } catch (err) {
    setBadge("error", "ERROR RED");
    output.textContent = `No se pudo conectar con la API.\n\n${String(err)}`;
  }
}

buttons.health.addEventListener("click", () => callJsonEndpoint("/health"));
buttons.local.addEventListener("click", () => callJsonEndpoint("/scan-local"));
buttons.example.addEventListener("click", () => callJsonEndpoint("/scan-example"));
buttons.upload.addEventListener("click", uploadAndScan);
