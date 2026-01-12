async function poll() {
  const res = await fetch(`/api/session/${sid}`);
  if (!res.ok) return;
  const data = await res.json();
  const el = document.getElementById("status");

  if (data.status === "approved") {
    el.textContent = "Approved ✅";
    el.className = "status ok";
    return;
  }
  if (data.status === "denied") {
    el.textContent = "Denied ❌";
    el.className = "status bad";
    return;
  }
  if (data.status === "expired") {
    el.textContent = "Expired ⏳ Reload page.";
    el.className = "status warn";
    return;
  }

  setTimeout(poll, 1000);
}
poll();
