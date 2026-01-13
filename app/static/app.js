(() => {
  const sessionId = window.DNA_AUTH_SESSION_ID;
  const statusEl = document.getElementById("status");

  if (!sessionId) {
    console.error("DNA_AUTH_SESSION_ID missing");
    return;
  }

  let stopped = false;

  async function poll() {
    if (stopped) return;

    try {
      const res = await fetch(`/api/v1/session/${sessionId}`, {
        cache: "no-store",
      });

      if (!res.ok) {
        statusEl.textContent = "Server error";
        return;
      }

      const data = await res.json();
      console.log("AUTH STATUS:", data);

      switch (data.status) {
        case "pending":
          statusEl.textContent = "Waiting for approval…";
          break;

        case "approved":
          stopped = true;              // 🔒 stop polling
          statusEl.textContent = "Approved ✔";
          window.location.replace("/success"); // 🚀 redirect
          return;

        case "denied":
          stopped = true;
          statusEl.textContent = "Denied";
          return;

        case "expired":
          stopped = true;
          statusEl.textContent = "Expired";
          return;

        default:
          statusEl.textContent = `Unknown status: ${data.status}`;
      }
    } catch (e) {
      console.error("Polling failed:", e);
    }
  }

  poll();                    // run immediately
  setInterval(poll, 1500);   // then poll
})();
