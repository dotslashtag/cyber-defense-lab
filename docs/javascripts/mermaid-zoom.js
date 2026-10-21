/* ---------- Click-to-enlarge for Mermaid flowcharts ----------
   GLightbox (the screenshot zoom) only works on image files. Mermaid flowcharts are drawn by the
   browser inside a sealed box (a "closed shadow root"), so they can't be copied out. Instead, on
   click we lift the flowchart itself above the page, center it and scale it to fit the screen.
   Click anywhere or press Esc to close. Flowcharts are vector graphics, so they stay sharp. */
(function () {
  let open = null; // the flowchart currently enlarged (or null)

  function close() {
    if (!open) return;
    open.classList.remove("mermaid-zoomed");
    open.style.removeProperty("--mz-scale");
    document.body.classList.remove("mermaid-zoom-open");
    open = null;
  }

  function enlarge(el) {
    open = el;
    document.body.classList.add("mermaid-zoom-open"); // dark backdrop
    el.classList.add("mermaid-zoomed");              // shrink-wrap and center
    const box = el.getBoundingClientRect();           // its natural size, before scaling
    const scale = Math.min((window.innerWidth * 0.95) / box.width,
                           (window.innerHeight * 0.9) / box.height);
    el.style.setProperty("--mz-scale", scale);
  }

  document.addEventListener("click", function (event) {
    if (open) { close(); return; }                    // any click closes
    const el = event.target.closest("div.mermaid");
    if (el) enlarge(el);
  });
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") close();
  });
  window.addEventListener("resize", close);
})();
