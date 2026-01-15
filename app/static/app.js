(() => {
  const statusEl = document.getElementById("status");

  let stopped = false;

  function setStatus(msg) {
    if (statusEl) statusEl.textContent = msg;
  }

  // ---------------------------------------------------------------------------
  // v3 polling (stateful)
  // ---------------------------------------------------------------------------
  async function pollV3(sessionId) {
    if (stopped) return;

    try {
      const res = await fetch(`/api/v1/session/${encodeURIComponent(sessionId)}`, {
        cache: "no-store",
      });

      if (!res.ok) {
        setStatus("Server error");
        return;
      }

      const data = await res.json();
      console.log("AUTH STATUS v3:", data);

      switch (data.status) {
        case "pending":
          setStatus("Waiting for approval…");
          break;

        case "approved":
          stopped = true;
          setStatus("Approved ✔");
          console.log("Redirecting to /success (v3)");
          window.location.href = "/success";
          return;

        case "denied":
          stopped = true;
          setStatus("Denied");
          return;

        case "expired":
          stopped = true;
          setStatus("Expired");
          return;

        default:
          setStatus(`Unknown status: ${data.status}`);
      }
    } catch (e) {
      console.error("v3 polling failed:", e);
    }
  }

  // ---------------------------------------------------------------------------
  // v4 polling (stateless)
  // ---------------------------------------------------------------------------
  async function pollV4(sid) {
    if (stopped) return;

    try {
      const res = await fetch(`/api/v4/status?sid=${encodeURIComponent(sid)}`, {
        cache: "no-store",
      });

      if (!res.ok) {
        setStatus("Server error");
        return;
      }

      const data = await res.json();
      console.log("AUTH STATUS v4:", data);

      if (data.approved) {
        stopped = true;
        setStatus("Approved ✔");
        console.log("Redirecting to /success (v4)");
        window.location.href = "/success";
        return;
      }

      if (data.expired) {
        stopped = true;
        setStatus("Expired");
        return;
      }

      setStatus("Waiting for approval…");
    } catch (e) {
      console.error("v4 polling failed:", e);
    }
  }

  // ---------------------------------------------------------------------------
  // Wait for session identifiers to exist (v4 is async: set after fetch completes)
  // ---------------------------------------------------------------------------
  function waitForSessionId({ timeoutMs = 15000, intervalMs = 150 } = {}) {
    const start = Date.now();

    const timer = setInterval(() => {
      const v3SessionId = window.DNA_AUTH_SESSION_ID || null;
      const v4Sid = window.V4_SID || null;

      if (v4Sid && String(v4Sid).trim().length > 0) {
        clearInterval(timer);
        console.log("Using v4 stateless polling, sid =", v4Sid);
        pollV4(v4Sid);
        setInterval(() => pollV4(v4Sid), 1000);
        return;
      }

      if (v3SessionId && String(v3SessionId).trim().length > 0) {
        clearInterval(timer);
        console.log("Using v3 stateful polling, session =", v3SessionId);
        pollV3(v3SessionId);
        setInterval(() => pollV3(v3SessionId), 1500);
        return;
      }

      if (Date.now() - start > timeoutMs) {
        clearInterval(timer);
        console.error("Timed out waiting for DNA session identifier (v3 or v4)");
        setStatus("Error: session id not available");
      }
    }, intervalMs);
  }

  // Start
  waitForSessionId();
})();
