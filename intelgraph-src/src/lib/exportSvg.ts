function triggerDownload(name: string, blob: Blob) {
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

const THEME_VARS = [
  "--bg",
  "--panel",
  "--panel2",
  "--border",
  "--border2",
  "--text",
  "--muted",
  "--faint",
  "--accent",
  "--card",
  "--node-grad-1",
  "--node-grad-2",
  "--edge-dim",
  "--flow-color",
];

/** var() only resolves against a live stylesheet — inline current values so a serialized/standalone SVG still renders correctly. */
function inlineThemeVars(clone: SVGSVGElement) {
  const computed = getComputedStyle(document.documentElement);
  const decls = THEME_VARS.map((v) => `${v}: ${computed.getPropertyValue(v).trim()};`).join(" ");
  const style = document.createElementNS("http://www.w3.org/2000/svg", "style");
  style.textContent = `:root { ${decls} }`;
  clone.insertBefore(style, clone.firstChild);
}

function serializeSvg(svg: SVGSVGElement): string {
  const clone = svg.cloneNode(true) as SVGSVGElement;
  clone.removeAttribute("style");
  clone.setAttribute("xmlns", "http://www.w3.org/2000/svg");
  inlineThemeVars(clone);
  return new XMLSerializer().serializeToString(clone);
}

export function currentBgColor(): string {
  return getComputedStyle(document.documentElement).getPropertyValue("--bg").trim() || "#0b1120";
}

export function exportSvgFile(svg: SVGSVGElement, name = "diagram.svg") {
  const str = serializeSvg(svg);
  const blob = new Blob([str], { type: "image/svg+xml" });
  triggerDownload(name, blob);
}

export function exportPngFile(
  svg: SVGSVGElement,
  name = "diagram.png",
  background = currentBgColor()
) {
  const bbox = svg.getBoundingClientRect();
  const w = Math.max(1, Math.round(bbox.width));
  const h = Math.max(1, Math.round(bbox.height));

  const str = serializeSvg(svg);
  const svgBlob = new Blob([str], { type: "image/svg+xml" });
  const url = URL.createObjectURL(svgBlob);

  const img = new Image();
  img.onload = () => {
    const canvas = document.createElement("canvas");
    canvas.width = w * 2;
    canvas.height = h * 2;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;
    ctx.scale(2, 2);
    ctx.fillStyle = background;
    ctx.fillRect(0, 0, w, h);
    ctx.drawImage(img, 0, 0, w, h);
    URL.revokeObjectURL(url);
    canvas.toBlob((blob) => {
      if (blob) triggerDownload(name, blob);
    }, "image/png");
  };
  img.src = url;
}
