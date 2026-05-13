// linpodx Web UI — vanilla JS, 1Hz polling. Renders via textContent only.
(function () {
  "use strict";

  var TOKEN_KEY = "linpodx_token";
  var POLL_MS = 1000;

  var TABS = {
    containers: {
      url: "/api/v1/containers",
      cols: ["id", "name", "image", "status", "created_at"]
    },
    images: {
      url: "/api/v1/images",
      cols: ["id", "repo_tags", "size", "created_at"]
    },
    volumes: {
      url: "/api/v1/volumes",
      cols: ["name", "driver", "mountpoint", "created_at"]
    },
    networks: {
      url: "/api/v1/networks",
      cols: ["name", "driver", "subnet", "gateway", "internal"]
    },
    snapshots: {
      url: "/api/v1/snapshots",
      cols: ["id", "container_id", "label", "image_ref", "created_at"]
    },
    sessions: {
      url: "/api/v1/sessions",
      cols: ["id", "container_id", "container_name", "profile_name", "started_at", "ended_at"]
    },
    sandbox: {
      url: "/api/v1/sandbox/profiles",
      cols: ["name", "version", "category", "rules"]
    },
    audit: {
      url: "/api/v1/audit?limit=100",
      cols: ["seq", "ts", "kind", "profile_name", "container_id"]
    }
  };

  var state = {
    activeTab: "containers",
    token: null,
    timer: null
  };

  function setStatus(kind, text) {
    var dot = document.getElementById("status-dot");
    var label = document.getElementById("status-text");
    dot.className = "dot " + kind;
    label.textContent = text;
  }

  function promptForToken() {
    var t = window.prompt("Enter linpodx remote token:", state.token || "");
    if (t === null) return;
    var trimmed = t.trim();
    if (!trimmed) {
      window.localStorage.removeItem(TOKEN_KEY);
      state.token = null;
      setStatus("offline", "no token");
      return;
    }
    window.localStorage.setItem(TOKEN_KEY, trimmed);
    state.token = trimmed;
    setStatus("loading", "fetching…");
    refresh();
  }

  function loadToken() {
    state.token = window.localStorage.getItem(TOKEN_KEY);
  }

  function clearToken() {
    window.localStorage.removeItem(TOKEN_KEY);
    state.token = null;
  }

  function ensureGridShape(grid, cols) {
    var want = "repeat(" + cols.length + ", minmax(80px, max-content))";
    if (grid.style.gridTemplateColumns !== want) {
      grid.style.gridTemplateColumns = want;
    }
  }

  function clearChildren(node) {
    while (node.firstChild) {
      node.removeChild(node.firstChild);
    }
  }

  function appendCell(grid, text, isHead) {
    var div = document.createElement("div");
    div.className = "cell" + (isHead ? " head" : "");
    div.textContent = text;
    grid.appendChild(div);
  }

  function appendEmpty(grid, message) {
    var div = document.createElement("div");
    div.className = "cell empty";
    div.textContent = message;
    grid.appendChild(div);
  }

  function fmt(value) {
    if (value === null || value === undefined) return "";
    if (typeof value === "string" || typeof value === "number" || typeof value === "boolean") {
      return String(value);
    }
    if (Array.isArray(value)) {
      return value.map(fmt).join(", ");
    }
    try {
      return JSON.stringify(value);
    } catch (_e) {
      return String(value);
    }
  }

  function pickField(row, key) {
    if (row === null || typeof row !== "object") return "";
    if (key in row) return fmt(row[key]);
    return "";
  }

  function renderTable(tabName, rows) {
    var def = TABS[tabName];
    var grid = document.getElementById("grid-" + tabName);
    clearChildren(grid);
    ensureGridShape(grid, def.cols);
    for (var i = 0; i < def.cols.length; i++) {
      appendCell(grid, def.cols[i], true);
    }
    if (!Array.isArray(rows) || rows.length === 0) {
      appendEmpty(grid, "no rows");
      return;
    }
    for (var r = 0; r < rows.length; r++) {
      var row = rows[r];
      for (var c = 0; c < def.cols.length; c++) {
        appendCell(grid, pickField(row, def.cols[c]), false);
      }
    }
  }

  function renderError(tabName, message) {
    var grid = document.getElementById("grid-" + tabName);
    clearChildren(grid);
    var def = TABS[tabName];
    ensureGridShape(grid, def.cols);
    for (var i = 0; i < def.cols.length; i++) {
      appendCell(grid, def.cols[i], true);
    }
    appendEmpty(grid, message);
  }

  function refresh() {
    if (!state.token) {
      setStatus("offline", "no token");
      renderError(state.activeTab, "set a token to load data");
      return;
    }
    var def = TABS[state.activeTab];
    var tab = state.activeTab;
    fetch(def.url, {
      method: "GET",
      headers: { Authorization: "Bearer " + state.token },
      cache: "no-store",
      credentials: "omit"
    }).then(function (resp) {
      if (resp.status === 401) {
        clearToken();
        setStatus("offline", "auth failed");
        renderError(tab, "auth failed — token rejected");
        promptForToken();
        return null;
      }
      if (!resp.ok) {
        setStatus("offline", "http " + resp.status);
        renderError(tab, "http " + resp.status);
        return null;
      }
      return resp.json();
    }).then(function (data) {
      if (data === null || data === undefined) return;
      setStatus("online", "ok");
      var ts = new Date().toISOString().slice(11, 19);
      document.getElementById("last-update").textContent = "updated " + ts;
      var rows = Array.isArray(data) ? data : [data];
      renderTable(tab, rows);
    }).catch(function (err) {
      setStatus("offline", "fetch error");
      renderError(tab, "fetch error: " + (err && err.message ? err.message : err));
    });
  }

  function selectTab(name) {
    state.activeTab = name;
    var tabs = document.querySelectorAll(".tab");
    for (var i = 0; i < tabs.length; i++) {
      var el = tabs[i];
      if (el.getAttribute("data-tab") === name) {
        el.classList.add("active");
      } else {
        el.classList.remove("active");
      }
    }
    var panels = document.querySelectorAll(".panel");
    for (var p = 0; p < panels.length; p++) {
      var panel = panels[p];
      if (panel.id === "panel-" + name) {
        panel.classList.remove("hidden");
      } else {
        panel.classList.add("hidden");
      }
    }
    refresh();
  }

  function startPolling() {
    if (state.timer !== null) {
      window.clearInterval(state.timer);
    }
    state.timer = window.setInterval(refresh, POLL_MS);
  }

  function init() {
    loadToken();
    var tabs = document.querySelectorAll(".tab");
    for (var i = 0; i < tabs.length; i++) {
      tabs[i].addEventListener("click", function (ev) {
        selectTab(ev.currentTarget.getAttribute("data-tab"));
      });
    }
    document.getElementById("token-btn").addEventListener("click", promptForToken);
    selectTab("containers");
    if (!state.token) {
      promptForToken();
    }
    startPolling();
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
