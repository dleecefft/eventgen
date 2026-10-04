"use strict";

document.addEventListener("DOMContentLoaded", () => {
  const form = document.getElementById("waf-auto-next");
  if (!form) return;
  const delay = Number.parseInt(form.dataset.delayMs || "250", 10);
  window.setTimeout(() => form.requestSubmit(), Math.max(250, delay));
});
