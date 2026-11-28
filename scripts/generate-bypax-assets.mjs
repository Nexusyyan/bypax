#!/usr/bin/env node
/**
 * Deterministic cross-platform brand asset generator for Bypax.
 *
 * Zero Python dependencies:
 * - Built-in HSL color math, macOS G2 squircle geometry, Overpass X ribbons,
 *   and De Casteljau cubic Bezier physical split from the finalized Bypax Brand Studio.
 * - Single-process headless Chromium/Edge HTML5 Canvas rasterization for true RGBA PNGs.
 * - Pure-JS hybrid multi-size Windows .ico encoder (vector BMP DIB 16-64px + mesh PNG 128-256px).
 * - Pure-JS Apple .icns encoder (vector icp4/icp5/ic11/icp6/ic12 + mesh ic07..ic10).
 *
 * Usage:
 *   node scripts/generate-bypax-assets.mjs [--variant full-rainbow|contrast-overpass|prism-dual]
 *                                          [--saturation 105] [--hue-shift 0] [--gap standard]
 */

import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const REPO_ROOT = path.resolve(__dirname, "..");

const MACOS_SQUIRCLE_PATH =
  "M 512 100 L 702 100 C 842 100 924 182 924 322 L 924 702 C 924 842 842 924 702 924 L 322 924 C 182 924 100 842 100 702 L 100 322 C 100 182 182 100 322 100 Z";

// Small-size optical squircle (~92% fill: 40..984) for 16/24/32px ICO/ICNS & favicon readability
const SMALL_OPTICAL_SQUIRCLE_PATH =
  "M 512 40 L 730 40 C 890 40 984 134 984 294 L 984 730 C 984 890 890 984 730 984 L 294 984 C 134 984 40 890 40 730 L 40 294 C 40 134 134 40 294 40 Z";

const OVERPASS_LOWER_PATH =
  "M 318 346 C 390 346 446 446 512 512 C 578 578 634 678 706 678";

const OVERPASS_UPPER_PATH =
  "M 318 678 C 390 678 446 578 512 512 C 578 446 634 346 706 346";

// Expanded Overpass X ribbons (~1.38x span & ~1.31x stroke) for crisp 16-32px rendering
const SMALL_OVERPASS_LOWER_PATH =
  "M 244 282 C 344 282 420 420 512 512 C 604 604 680 742 780 742";

const SMALL_OVERPASS_UPPER_PATH =
  "M 244 742 C 344 742 420 604 512 512 C 604 420 680 282 780 282";

const OVERPASS_GAPS = {
  tight: { appMaskPad: 22, trayCutT: 0.67 },
  standard: { appMaskPad: 34, trayCutT: 0.6 },
  wide: { appMaskPad: 46, trayCutT: 0.53 },
};

const DEFAULT_CONFIG = {
  brand: "Bypax",
  slug: "bypax",
  tagline: "Cross-platform app routing & proxy workbench",
  variant: "full-rainbow",
  saturation: 105,
  hueShift: 0,
  gapMode: "standard",
};

function parseArgs(argv) {
  const cfg = { ...DEFAULT_CONFIG };
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    if (arg === "--variant" && argv[i + 1]) {
      cfg.variant = argv[++i];
    } else if (arg === "--saturation" && argv[i + 1]) {
      cfg.saturation = Number(argv[++i]);
    } else if (arg === "--hue-shift" && argv[i + 1]) {
      cfg.hueShift = Number(argv[++i]);
    } else if (arg === "--gap" && argv[i + 1]) {
      cfg.gapMode = argv[++i];
    } else if (arg === "--help" || arg === "-h") {
      console.log(
        "Usage: node scripts/generate-bypax-assets.mjs [--variant full-rainbow|contrast-overpass|prism-dual] [--saturation 105] [--hue-shift 0] [--gap tight|standard|wide]",
      );
      process.exit(0);
    }
  }
  if (!["full-rainbow", "contrast-overpass", "prism-dual"].includes(cfg.variant)) {
    throw new Error(`Unsupported --variant: ${cfg.variant}`);
  }
  if (!OVERPASS_GAPS[cfg.gapMode]) {
    throw new Error(`Unsupported --gap: ${cfg.gapMode}`);
  }
  return cfg;
}

// ---------------------------------------------------------------------------
// 1. Color Math & Geometry Helpers (exact port from Bypax Brand Studio HTML)
// ---------------------------------------------------------------------------

function hexToRgb(hex) {
  const clean = hex.replace("#", "");
  const num = parseInt(clean, 16);
  return {
    r: (num >> 16) & 255,
    g: (num >> 8) & 255,
    b: num & 255,
  };
}

function rgbToHsl(r, g, b) {
  r /= 255;
  g /= 255;
  b /= 255;
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  let h = 0;
  let s = 0;
  const l = (max + min) / 2;
  if (max !== min) {
    const d = max - min;
    s = l > 0.5 ? d / (2 - max - min) : d / (max + min);
    switch (max) {
      case r:
        h = ((g - b) / d + (g < b ? 6 : 0)) / 6;
        break;
      case g:
        h = ((b - r) / d + 2) / 6;
        break;
      case b:
        h = ((r - g) / d + 4) / 6;
        break;
    }
  }
  return { h: h * 360, s: s * 100, l: l * 100 };
}

function hslToHex(h, s, l) {
  h = ((h % 360) + 360) % 360;
  s = Math.max(0, Math.min(100, s)) / 100;
  l = Math.max(0, Math.min(100, l)) / 100;
  const c = (1 - Math.abs(2 * l - 1)) * s;
  const x = c * (1 - Math.abs(((h / 60) % 2) - 1));
  const m = l - c / 2;
  let r1 = 0;
  let g1 = 0;
  let b1 = 0;
  if (h < 60) {
    r1 = c;
    g1 = x;
  } else if (h < 120) {
    r1 = x;
    g1 = c;
  } else if (h < 180) {
    g1 = c;
    b1 = x;
  } else if (h < 240) {
    g1 = x;
    b1 = c;
  } else if (h < 300) {
    r1 = x;
    b1 = c;
  } else {
    r1 = c;
    b1 = x;
  }
  const toHex = (v) =>
    Math.round((v + m) * 255)
      .toString(16)
      .padStart(2, "0");
  return `#${toHex(r1)}${toHex(g1)}${toHex(b1)}`.toUpperCase();
}

function adjustColor(hex, hueDelta, satPercent) {
  const { r, g, b } = hexToRgb(hex);
  const hsl = rgbToHsl(r, g, b);
  return hslToHex(hsl.h + hueDelta, Math.min(100, hsl.s * (satPercent / 100)), hsl.l);
}

function getPalette(cfg) {
  const h = cfg.hueShift;
  const s = cfg.saturation;
  return {
    sky: adjustColor("#38BDF8", h, s),
    emerald: adjustColor("#4ADE80", h, s),
    gold: adjustColor("#FACC15", h, s),
    tangerine: adjustColor("#FB923C", h, s),
    coral: adjustColor("#F43F5E", h, s),
    cobalt: adjustColor("#3B82F6", h, s),
    violet: adjustColor("#A855F7", h, s),
    aqua: adjustColor("#22D3EE", h, s),
    slateLight: "#CBD5E1",
    slateMid: "#94A3B8",
    slateDeep: "#64748B",
  };
}

function escapeXml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&apos;");
}

function splitCubic(p0, p1, p2, p3, t) {
  const lerp = (a, b) => [a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t];
  const q0 = lerp(p0, p1);
  const q1 = lerp(p1, p2);
  const q2 = lerp(p2, p3);
  const r0 = lerp(q0, q1);
  const r1 = lerp(q1, q2);
  const s0 = lerp(r0, r1);
  return {
    left: [p0, q0, r0, s0],
    right: [s0, r1, q2, p3],
  };
}

function fmtPt(pt) {
  return `${pt[0].toFixed(2)} ${pt[1].toFixed(2)}`;
}

// ---------------------------------------------------------------------------
// 2. SVG Builders
// ---------------------------------------------------------------------------

function buildMasterLogoSvg(cfg, idPrefix, options = {}) {
  const p = idPrefix ? `${idPrefix}-` : "bypax-";
  const pal = getPalette(cfg);
  const gapCfg = OVERPASS_GAPS[cfg.gapMode] || OVERPASS_GAPS.standard;
  const isMesh = (options.renderMode || "vector") === "mesh";
  const isSmallOptical = Boolean(options.opticalSmall) && !isMesh;
  const squirclePath = isSmallOptical ? SMALL_OPTICAL_SQUIRCLE_PATH : MACOS_SQUIRCLE_PATH;
  const lowerPath = isSmallOptical ? SMALL_OVERPASS_LOWER_PATH : OVERPASS_LOWER_PATH;
  const upperPath = isSmallOptical ? SMALL_OVERPASS_UPPER_PATH : OVERPASS_UPPER_PATH;
  const strokeW = isSmallOptical ? 142 : 108;
  const maskPad = isSmallOptical ? Math.round(gapCfg.appMaskPad * 1.3) : gapCfg.appMaskPad;
  const maskKnockoutW = strokeW + maskPad * 2;
  const sizeAttrs = options.includeSizeAttr ? ' width="1024" height="1024"' : "";
  const omitShadow = Boolean(options.omitShadow) || isSmallOptical;

  let defsInner = "";
  let lowerGraphic = "";
  let upperGraphic = "";
  let ambientUnderGlow = "";

  defsInner += `
    <linearGradient id="${p}sq-bg" x1="120" y1="100" x2="900" y2="924" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#FFFFFF" />
      <stop offset="72%" stop-color="#FDFEFF" />
      <stop offset="100%" stop-color="#F4F7FB" />
    </linearGradient>
    <linearGradient id="${p}sq-rim" x1="100" y1="100" x2="924" y2="924" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="#FFFFFF" stop-opacity="0.95" />
      <stop offset="100%" stop-color="#CBD5E1" stop-opacity="0.6" />
    </linearGradient>`;

  defsInner += `
    <mask id="${p}mask-lower" maskUnits="userSpaceOnUse" x="80" y="80" width="864" height="864">
      <path d="${lowerPath}" fill="none" stroke="#FFFFFF" stroke-width="${strokeW}" stroke-linecap="round" />
      <path d="${upperPath}" fill="none" stroke="#000000" stroke-width="${maskKnockoutW}" stroke-linecap="round" />
    </mask>
    <mask id="${p}mask-upper" maskUnits="userSpaceOnUse" x="80" y="80" width="864" height="864">
      <path d="${upperPath}" fill="none" stroke="#FFFFFF" stroke-width="${strokeW}" stroke-linecap="round" />
    </mask>`;

  if (isMesh) {
    defsInner += `
    <filter id="${p}sq-shadow" x="30" y="42" width="964" height="964" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB">
      <feDropShadow dx="0" dy="18" stdDeviation="24" flood-color="#0F172A" flood-opacity="${options.forDarkSurface ? "0.38" : "0.13"}" />
      <feDropShadow dx="0" dy="4" stdDeviation="6" flood-color="#0F172A" flood-opacity="${options.forDarkSurface ? "0.22" : "0.06"}" />
    </filter>
    <filter id="${p}mesh-blur" x="120" y="120" width="784" height="784" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB">
      <feGaussianBlur stdDeviation="74" />
    </filter>
    <filter id="${p}glyph-float" x="180" y="210" width="664" height="624" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB">
      <feDropShadow dx="0" dy="14" stdDeviation="16" flood-color="${pal.cobalt}" flood-opacity="0.18" />
    </filter>
    <filter id="${p}bridge-cast" x="200" y="200" width="624" height="624" filterUnits="userSpaceOnUse" color-interpolation-filters="sRGB">
      <feDropShadow dx="0" dy="16" stdDeviation="18" flood-color="#0F172A" flood-opacity="0.22" />
    </filter>`;
  }

  if (cfg.variant === "full-rainbow") {
    if (isMesh) {
      const rainbowMeshBlobs = `
        <rect x="200" y="200" width="624" height="624" fill="${pal.cobalt}" />
        <g filter="url(#${p}mesh-blur)">
          <circle cx="315" cy="690" r="195" fill="${pal.sky}" />
          <circle cx="330" cy="405" r="205" fill="${pal.emerald}" />
          <circle cx="505" cy="295" r="185" fill="${pal.gold}" />
          <circle cx="655" cy="360" r="190" fill="${pal.tangerine}" />
          <circle cx="710" cy="475" r="175" fill="${pal.coral}" />
          <circle cx="535" cy="545" r="175" fill="${pal.cobalt}" />
          <circle cx="715" cy="695" r="185" fill="${pal.sky}" />
        </g>`;
      lowerGraphic = `<g mask="url(#${p}mask-lower)">${rainbowMeshBlobs}</g>`;
      upperGraphic = `<g filter="url(#${p}glyph-float)"><g mask="url(#${p}mask-upper)">${rainbowMeshBlobs}</g></g>`;
      ambientUnderGlow = `<path d="${OVERPASS_UPPER_PATH}" fill="none" stroke="${pal.sky}" stroke-opacity="0.16" stroke-width="116" stroke-linecap="round" filter="url(#${p}glyph-float)" />`;
    } else {
      defsInner += `
    <linearGradient id="${p}vec-lower" x1="300" y1="320" x2="720" y2="700" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="${pal.emerald}" />
      <stop offset="35%" stop-color="${pal.gold}" />
      <stop offset="68%" stop-color="${pal.cobalt}" />
      <stop offset="100%" stop-color="${pal.sky}" />
    </linearGradient>
    <linearGradient id="${p}vec-upper" x1="300" y1="690" x2="720" y2="330" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="${pal.sky}" />
      <stop offset="28%" stop-color="${pal.emerald}" />
      <stop offset="52%" stop-color="${pal.gold}" />
      <stop offset="76%" stop-color="${pal.tangerine}" />
      <stop offset="100%" stop-color="${pal.coral}" />
    </linearGradient>
    <radialGradient id="${p}vec-highlight" cx="512" cy="512" r="240" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="${pal.cobalt}" stop-opacity="0.34" />
      <stop offset="100%" stop-color="${pal.cobalt}" stop-opacity="0" />
    </radialGradient>`;
      lowerGraphic = `
    <g mask="url(#${p}mask-lower)">
      <path d="${lowerPath}" fill="none" stroke="url(#${p}vec-lower)" stroke-width="${strokeW}" stroke-linecap="round" />
    </g>`;
      upperGraphic = `
    <g>
      <path d="${upperPath}" fill="none" stroke="url(#${p}vec-upper)" stroke-width="${strokeW}" stroke-linecap="round" />
      <path d="${upperPath}" fill="none" stroke="url(#${p}vec-highlight)" stroke-width="${strokeW}" stroke-linecap="round" />
    </g>`;
    }
  } else if (cfg.variant === "contrast-overpass") {
    defsInner += `
    <linearGradient id="${p}silver-lower" x1="310" y1="330" x2="710" y2="690" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="${pal.slateMid}" />
      <stop offset="48%" stop-color="${pal.slateLight}" />
      <stop offset="100%" stop-color="${pal.slateDeep}" />
    </linearGradient>`;
    lowerGraphic = `
    <g mask="url(#${p}mask-lower)">
      <path d="${OVERPASS_LOWER_PATH}" fill="none" stroke="url(#${p}silver-lower)" stroke-width="${strokeW}" stroke-linecap="round" />
    </g>`;

    if (isMesh) {
      upperGraphic = `
    <g filter="url(#${p}glyph-float)">
      <g mask="url(#${p}mask-upper)">
        <rect x="200" y="200" width="624" height="624" fill="${pal.cobalt}" />
        <g filter="url(#${p}mesh-blur)">
          <circle cx="310" cy="690" r="195" fill="${pal.sky}" />
          <circle cx="425" cy="595" r="175" fill="${pal.emerald}" />
          <circle cx="540" cy="450" r="170" fill="${pal.gold}" />
          <circle cx="635" cy="365" r="175" fill="${pal.tangerine}" />
          <circle cx="720" cy="340" r="175" fill="${pal.coral}" />
          <circle cx="520" cy="545" r="140" fill="${pal.cobalt}" />
        </g>
      </g>
    </g>`;
    } else {
      defsInner += `
    <linearGradient id="${p}rainbow-upper" x1="310" y1="685" x2="715" y2="335" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="${pal.sky}" />
      <stop offset="25%" stop-color="${pal.emerald}" />
      <stop offset="50%" stop-color="${pal.gold}" />
      <stop offset="75%" stop-color="${pal.tangerine}" />
      <stop offset="100%" stop-color="${pal.coral}" />
    </linearGradient>`;
      upperGraphic = `<path d="${OVERPASS_UPPER_PATH}" fill="none" stroke="url(#${p}rainbow-upper)" stroke-width="${strokeW}" stroke-linecap="round" />`;
    }
  } else {
    if (isMesh) {
      lowerGraphic = `
    <g mask="url(#${p}mask-lower)">
      <rect x="200" y="200" width="624" height="624" fill="${pal.sky}" />
      <g filter="url(#${p}mesh-blur)">
        <circle cx="320" cy="345" r="200" fill="${pal.aqua}" />
        <circle cx="455" cy="465" r="185" fill="${pal.emerald}" />
        <circle cx="620" cy="610" r="190" fill="${pal.sky}" />
        <circle cx="725" cy="690" r="180" fill="${pal.cobalt}" />
      </g>
    </g>`;
      upperGraphic = `
    <g filter="url(#${p}bridge-cast)">
      <g mask="url(#${p}mask-upper)">
        <rect x="200" y="200" width="624" height="624" fill="${pal.coral}" />
        <g filter="url(#${p}mesh-blur)">
          <circle cx="310" cy="690" r="190" fill="${pal.gold}" />
          <circle cx="455" cy="560" r="180" fill="${pal.tangerine}" />
          <circle cx="600" cy="420" r="180" fill="${pal.coral}" />
          <circle cx="720" cy="335" r="185" fill="${pal.violet}" />
        </g>
      </g>
    </g>`;
    } else {
      defsInner += `
    <linearGradient id="${p}cool-lower" x1="310" y1="335" x2="715" y2="690" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="${pal.aqua}" />
      <stop offset="40%" stop-color="${pal.emerald}" />
      <stop offset="72%" stop-color="${pal.sky}" />
      <stop offset="100%" stop-color="${pal.cobalt}" />
    </linearGradient>
    <linearGradient id="${p}warm-upper" x1="310" y1="690" x2="715" y2="335" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="${pal.gold}" />
      <stop offset="34%" stop-color="${pal.tangerine}" />
      <stop offset="68%" stop-color="${pal.coral}" />
      <stop offset="100%" stop-color="${pal.violet}" />
    </linearGradient>`;
      lowerGraphic = `
    <g mask="url(#${p}mask-lower)">
      <path d="${OVERPASS_LOWER_PATH}" fill="none" stroke="url(#${p}cool-lower)" stroke-width="${strokeW}" stroke-linecap="round" />
    </g>`;
      upperGraphic = `
    <g>
      <path d="${OVERPASS_UPPER_PATH}" transform="translate(0 12)" fill="none" stroke="#0F172A" stroke-opacity="0.09" stroke-width="${strokeW}" stroke-linecap="round" />
      <path d="${OVERPASS_UPPER_PATH}" fill="none" stroke="url(#${p}warm-upper)" stroke-width="${strokeW}" stroke-linecap="round" />
    </g>`;
    }
  }

  const vectorRimWidth = isSmallOptical ? 20 : omitShadow ? 10 : 4;
  const squircleBlock = isMesh
    ? `
  <!-- Ceramic-white macOS G2 squircle tile (10% safe margin) -->
  <g filter="url(#${p}sq-shadow)">
    <path d="${squirclePath}" fill="url(#${p}sq-bg)" />
    <path d="${squirclePath}" fill="none" stroke="url(#${p}sq-rim)" stroke-width="3" />
  </g>`
    : `
  <!-- Ceramic-white macOS G2 squircle tile (pure vector, zero filter) -->
  <g>${
    omitShadow
      ? ""
      : `\n    <path d="${squirclePath}" transform="translate(0 12)" fill="#0F172A" fill-opacity="0.07" />`
  }
    <path d="${squirclePath}" fill="url(#${p}sq-bg)" />
    <path d="${squirclePath}" fill="none" stroke="${omitShadow ? "#CBD5E1" : "#E2E8F0"}" stroke-width="${vectorRimWidth}" />
  </g>`;

  return `<svg xmlns="http://www.w3.org/2000/svg"${sizeAttrs} viewBox="0 0 1024 1024" fill="none">
  <defs>${defsInner}
  </defs>${squircleBlock}
  <!-- Bypax Rainbow Overpass X -->
  <g>${ambientUnderGlow}
    ${lowerGraphic.trim()}
    ${upperGraphic.trim()}
  </g>
</svg>`;
}

function buildTrayPaths(cfg) {
  const gapCfg = OVERPASS_GAPS[cfg.gapMode] || OVERPASS_GAPS.standard;
  const t = gapCfg.trayCutT;
  const leftHalf = splitCubic([3.4, 5.8], [6.8, 5.8], [9.2, 9.2], [12, 12], t).left;
  const rightHalf = splitCubic([12, 12], [14.8, 14.8], [17.2, 18.2], [20.6, 18.2], 1 - t).right;
  return {
    lowerLeft: `M ${fmtPt(leftHalf[0])} C ${fmtPt(leftHalf[1])} ${fmtPt(leftHalf[2])} ${fmtPt(leftHalf[3])}`,
    lowerRight: `M ${fmtPt(rightHalf[0])} C ${fmtPt(rightHalf[1])} ${fmtPt(rightHalf[2])} ${fmtPt(rightHalf[3])}`,
    upper: "M 3.4 18.2 C 6.8 18.2 9.2 14.8 12 12 C 14.8 9.2 17.2 5.8 20.6 5.8",
  };
}

function buildTraySvg(cfg) {
  const paths = buildTrayPaths(cfg);
  return `<svg xmlns="http://www.w3.org/2000/svg" width="24" height="24" viewBox="0 0 24 24" fill="none">
  <!-- Bypax 24x24 monochrome Overpass X tray template (De Casteljau physical split) -->
  <path d="${paths.lowerLeft}" stroke="currentColor" stroke-width="2.65" stroke-linecap="round" />
  <path d="${paths.lowerRight}" stroke="currentColor" stroke-width="2.65" stroke-linecap="round" />
  <path d="${paths.upper}" stroke="currentColor" stroke-width="2.75" stroke-linecap="round" />
</svg>`;
}

function buildRainbowTrayRasterSvg(cfg, opts) {
  const { dotColor, size, idPrefix = "bypax-tray" } = opts;
  const pal = getPalette(cfg);
  const paths = buildTrayPaths(cfg);
  const maskDef = dotColor
    ? `
    <mask id="${idPrefix}-dot-cut" maskUnits="userSpaceOnUse" x="0" y="0" width="24" height="24">
      <rect x="0" y="0" width="24" height="24" fill="#FFFFFF" />
      <circle cx="20.4" cy="20.4" r="3.45" fill="#000000" />
    </mask>`
    : "";
  const maskAttr = dotColor ? ` mask="url(#${idPrefix}-dot-cut)"` : "";
  const ribbonTransform = dotColor ? ' transform="translate(-0.45 -0.55) scale(0.95)"' : "";
  const dotMarkup = dotColor
    ? `
  <circle cx="20.4" cy="20.4" r="2.55" fill="${dotColor}" />`
    : "";

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${size}" height="${size}" viewBox="0 0 24 24" fill="none">
  <defs>
    <linearGradient id="${idPrefix}-lower" x1="3.4" y1="5.8" x2="20.6" y2="18.2" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="${pal.emerald}" />
      <stop offset="35%" stop-color="${pal.gold}" />
      <stop offset="68%" stop-color="${pal.cobalt}" />
      <stop offset="100%" stop-color="${pal.sky}" />
    </linearGradient>
    <linearGradient id="${idPrefix}-upper" x1="3.4" y1="18.2" x2="20.6" y2="5.8" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="${pal.sky}" />
      <stop offset="28%" stop-color="${pal.emerald}" />
      <stop offset="52%" stop-color="${pal.gold}" />
      <stop offset="76%" stop-color="${pal.tangerine}" />
      <stop offset="100%" stop-color="${pal.coral}" />
    </linearGradient>
    <radialGradient id="${idPrefix}-hl" cx="12" cy="12" r="5.6" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="${pal.cobalt}" stop-opacity="0.34" />
      <stop offset="100%" stop-color="${pal.cobalt}" stop-opacity="0" />
    </radialGradient>${maskDef}
  </defs>
  <g${maskAttr}>
    <g${ribbonTransform}>
      <path d="${paths.lowerLeft}" stroke="url(#${idPrefix}-lower)" stroke-width="2.95" stroke-linecap="round" />
      <path d="${paths.lowerRight}" stroke="url(#${idPrefix}-lower)" stroke-width="2.95" stroke-linecap="round" />
      <path d="${paths.upper}" stroke="url(#${idPrefix}-upper)" stroke-width="3.05" stroke-linecap="round" />
      <path d="${paths.upper}" stroke="url(#${idPrefix}-hl)" stroke-width="3.05" stroke-linecap="round" />
    </g>
  </g>${dotMarkup}
</svg>`;
}

function buildBannerSvg(cfg, mode) {
  const isDark = mode === "dark";
  const p = `bypax-banner-${mode}-`;
  const pal = getPalette(cfg);
  const brand = escapeXml(cfg.brand);
  const tagline = escapeXml(cfg.tagline);

  const titleColor = isDark ? "#F8FAFC" : "#0F172A";
  const subtitleColor = isDark ? "#94A3B8" : "#475569";
  const pillBg = isDark ? "rgba(255, 255, 255, 0.06)" : "#F8FAFC";
  const pillStroke = isDark ? "rgba(255, 255, 255, 0.13)" : "#E2E8F0";
  const pillText = isDark ? "#CBD5E1" : "#334155";

  // Pure-vector nested icon guarantees 100% consistent GitHub README rendering across all browsers.
  const rawIcon = buildMasterLogoSvg(cfg, `${p}icon`, {
    renderMode: "vector",
    includeSizeAttr: false,
    forDarkSurface: isDark,
  });
  const nestedIcon = rawIcon.replace(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" fill="none">',
    '<svg x="48" y="38" width="224" height="224" viewBox="0 0 1024 1024" fill="none">',
  );

  let bgDefs = "";
  let bgLayer = "";
  if (isDark) {
    bgDefs = `
    <radialGradient id="${p}icon-halo" cx="160" cy="150" r="140" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="${pal.sky}" stop-opacity="0.28" />
      <stop offset="52%" stop-color="${pal.violet}" stop-opacity="0.10" />
      <stop offset="100%" stop-color="${pal.cobalt}" stop-opacity="0" />
    </radialGradient>`;
    bgLayer = `
  <circle cx="160" cy="150" r="136" fill="url(#${p}icon-halo)" />`;
  }

  const badges = [
    { label: "Windows", dot: pal.sky, w: 112 },
    { label: "macOS", dot: pal.emerald, w: 102 },
    { label: "App Routing", dot: pal.gold, w: 132 },
    { label: "Proxy Core", dot: pal.tangerine, w: 124 },
    { label: "CLI & MCP", dot: pal.coral, w: 118 },
  ];

  let badgeOffset = 0;
  const badgesMarkup = `
  <g transform="translate(304, 194)">${badges
    .map((b) => {
      const x = badgeOffset;
      badgeOffset += b.w + 12;
      return `
    <g transform="translate(${x}, 0)">
      <rect x="0" y="0" width="${b.w}" height="34" rx="17" fill="${pillBg}" stroke="${pillStroke}" stroke-width="1.2" />
      <circle cx="18" cy="17" r="4.5" fill="${b.dot}" />
      <text x="31" y="22" fill="${pillText}" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif" font-size="14" font-weight="500">${escapeXml(b.label)}</text>
    </g>`;
    })
    .join("")}
  </g>`;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="300" viewBox="0 0 1200 300" fill="none">
  <defs>${bgDefs}
  </defs>${bgLayer}
  ${nestedIcon}
  <text x="302" y="116" fill="${titleColor}" font-family="-apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Segoe UI', system-ui, sans-serif" font-size="76" font-weight="700" letter-spacing="-0.035em">${brand}</text>
  <text x="305" y="162" fill="${subtitleColor}" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif" font-size="24" font-weight="400">${tagline}</text>${badgesMarkup}
</svg>`;
}

function buildSocialPreviewSvg(cfg) {
  const p = "bypax-social-";
  const pal = getPalette(cfg);
  const brand = escapeXml(cfg.brand);
  const tagline = escapeXml(cfg.tagline);
  const slug = escapeXml(cfg.slug);

  const rawIcon = buildMasterLogoSvg(cfg, `${p}icon`, {
    renderMode: "mesh",
    includeSizeAttr: false,
    forDarkSurface: true,
  });
  const nestedIcon = rawIcon.replace(
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1024 1024" fill="none">',
    '<svg x="524" y="76" width="232" height="232" viewBox="0 0 1024 1024" fill="none">',
  );

  const badges = [
    { label: "Windows", dot: pal.sky, w: 122 },
    { label: "macOS", dot: pal.emerald, w: 112 },
    { label: "App Routing", dot: pal.gold, w: 146 },
    { label: "Proxy Core", dot: pal.tangerine, w: 136 },
    { label: "CLI & MCP", dot: pal.coral, w: 130 },
  ];
  const totalBadgeW =
    badges.reduce((sum, b) => sum + b.w, 0) + (badges.length - 1) * 14;
  let cursorX = Math.round((1280 - totalBadgeW) / 2);

  return `<svg xmlns="http://www.w3.org/2000/svg" width="1280" height="640" viewBox="0 0 1280 640" fill="none">
  <defs>
    <radialGradient id="${p}aura-1" cx="240" cy="120" r="480" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="${pal.sky}" stop-opacity="0.22" />
      <stop offset="55%" stop-color="${pal.emerald}" stop-opacity="0.08" />
      <stop offset="100%" stop-color="${pal.sky}" stop-opacity="0" />
    </radialGradient>
    <radialGradient id="${p}aura-2" cx="1060" cy="140" r="480" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="${pal.coral}" stop-opacity="0.20" />
      <stop offset="55%" stop-color="${pal.gold}" stop-opacity="0.08" />
      <stop offset="100%" stop-color="${pal.coral}" stop-opacity="0" />
    </radialGradient>
    <radialGradient id="${p}aura-center" cx="640" cy="192" r="240" gradientUnits="userSpaceOnUse">
      <stop offset="0%" stop-color="${pal.cobalt}" stop-opacity="0.25" />
      <stop offset="100%" stop-color="${pal.cobalt}" stop-opacity="0" />
    </radialGradient>
    <pattern id="${p}grid" width="48" height="48" patternUnits="userSpaceOnUse">
      <path d="M 48 0 L 0 0 0 48" fill="none" stroke="rgba(255,255,255,0.035)" stroke-width="1" />
    </pattern>
  </defs>
  <rect width="1280" height="640" fill="#0B1120" />
  <rect width="1280" height="640" fill="url(#${p}grid)" />
  <rect width="1280" height="640" fill="url(#${p}aura-1)" />
  <rect width="1280" height="640" fill="url(#${p}aura-2)" />
  <circle cx="640" cy="192" r="230" fill="url(#${p}aura-center)" />
  ${nestedIcon}
  <text x="640" y="388" text-anchor="middle" fill="#F8FAFC" font-family="-apple-system, BlinkMacSystemFont, 'SF Pro Display', 'Segoe UI', system-ui, sans-serif" font-size="84" font-weight="800" letter-spacing="-0.04em">${brand}</text>
  <text x="640" y="438" text-anchor="middle" fill="#94A3B8" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif" font-size="27" font-weight="400">${tagline}</text>
  <g transform="translate(0, 482)">${badges
    .map((b) => {
      const x = cursorX;
      cursorX += b.w + 14;
      return `
    <g transform="translate(${x}, 0)">
      <rect x="0" y="0" width="${b.w}" height="40" rx="20" fill="rgba(255,255,255,0.07)" stroke="rgba(255,255,255,0.14)" stroke-width="1.3" />
      <circle cx="20" cy="20" r="5" fill="${b.dot}" />
      <text x="35" y="25.5" fill="#E2E8F0" font-family="-apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif" font-size="15.5" font-weight="500">${escapeXml(b.label)}</text>
    </g>`;
    })
    .join("")}
  </g>
  <text x="640" y="590" text-anchor="middle" fill="#94A3B8" font-family="ui-monospace, SFMono-Regular, Menlo, Consolas, monospace" font-size="16" font-weight="500">github.com/nexusyyan/${slug}</text>
</svg>`;
}

// ---------------------------------------------------------------------------
// 3. Headless Chromium / Edge Single-Launch Canvas Rasterizer
// ---------------------------------------------------------------------------

function findBrowserBinary() {
  const candidates =
    process.platform === "win32"
      ? [
          "C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
          "C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
          "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
          "C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        ]
      : process.platform === "darwin"
        ? [
            "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
            "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
            "/Applications/Chromium.app/Contents/MacOS/Chromium",
          ]
        : [
            "/usr/bin/google-chrome",
            "/usr/bin/chromium",
            "/usr/bin/chromium-browser",
            "/usr/bin/microsoft-edge",
          ];

  for (const bin of candidates) {
    if (fs.existsSync(bin)) return bin;
  }
  throw new Error(
    "No local Chromium/Edge/Chrome binary found for headless SVG rasterization.",
  );
}

async function rasterizeBatch(jobs) {
  const browserBin = findBrowserBinary();
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "bypax-raster-"));
  const results = new Map();

  let resolveDone;
  let rejectDone;
  const donePromise = new Promise((resolve, reject) => {
    resolveDone = resolve;
    rejectDone = reject;
  });

  const jobsPayload = JSON.stringify(
    jobs.map((j) => ({
      id: j.id,
      width: j.width,
      height: j.height,
      svg: j.svg,
      wantRgba: Boolean(j.wantRgba),
    })),
  );

  const html = `<!doctype html>
<html>
<head><meta charset="utf-8" /></head>
<body style="margin:0;background:transparent;">
<script>
const JOBS = ${jobsPayload};

function rasterizeOne(job) {
  return new Promise((resolve, reject) => {
    const xml = '<?xml version="1.0" encoding="UTF-8"?>\\n' + job.svg;
    const blob = new Blob([xml], { type: 'image/svg+xml;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const img = new Image();
    img.width = job.width;
    img.height = job.height;
    img.onload = () => {
      try {
        const canvas = document.createElement('canvas');
        canvas.width = job.width;
        canvas.height = job.height;
        const ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, job.width, job.height);
        ctx.imageSmoothingEnabled = true;
        ctx.imageSmoothingQuality = 'high';
        ctx.drawImage(img, 0, 0, job.width, job.height);
        const pngDataUrl = canvas.toDataURL('image/png');
        const pngBase64 = pngDataUrl.split(',')[1];
        let rgbaBase64 = null;
        if (job.wantRgba) {
          const data = ctx.getImageData(0, 0, job.width, job.height).data;
          let binary = '';
          const chunk = 0x8000;
          for (let i = 0; i < data.length; i += chunk) {
            binary += String.fromCharCode.apply(null, data.subarray(i, i + chunk));
          }
          rgbaBase64 = btoa(binary);
        }
        URL.revokeObjectURL(url);
        resolve({ id: job.id, pngBase64, rgbaBase64 });
      } catch (err) {
        URL.revokeObjectURL(url);
        reject(err);
      }
    };
    img.onerror = () => {
      URL.revokeObjectURL(url);
      reject(new Error('Image load failed for job ' + job.id));
    };
    img.src = url;
  });
}

(async () => {
  try {
    for (const job of JOBS) {
      const out = await rasterizeOne(job);
      await fetch('/result', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(out),
      });
    }
    await fetch('/done', { method: 'POST', body: 'ok' });
  } catch (err) {
    await fetch('/error', { method: 'POST', body: String(err && err.stack ? err.stack : err) });
  }
})();
</script>
</body>
</html>`;

  const server = http.createServer((req, res) => {
    if (req.method === "GET" && req.url === "/") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end(html);
      return;
    }
    if (req.method === "POST") {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        const body = Buffer.concat(chunks).toString("utf8");
        res.writeHead(200, { "Content-Type": "text/plain" });
        res.end("ok");
        if (req.url === "/result") {
          const parsed = JSON.parse(body);
          results.set(parsed.id, {
            png: Buffer.from(parsed.pngBase64, "base64"),
            rgba: parsed.rgbaBase64 ? Buffer.from(parsed.rgbaBase64, "base64") : null,
          });
        } else if (req.url === "/done") {
          resolveDone();
        } else if (req.url === "/error") {
          rejectDone(new Error(`Browser rasterizer error: ${body}`));
        }
      });
      return;
    }
    res.writeHead(404);
    res.end();
  });

  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const { port } = server.address();
  const targetUrl = `http://127.0.0.1:${port}/`;

  const child = spawn(
    browserBin,
    [
      "--headless=new",
      "--disable-gpu",
      "--no-first-run",
      "--no-default-browser-check",
      "--disable-background-networking",
      "--disable-extensions",
      `--user-data-dir=${userDataDir}`,
      "--window-size=1280,720",
      targetUrl,
    ],
    { stdio: "ignore" },
  );

  const timeout = setTimeout(() => {
    rejectDone(new Error("Headless browser rasterization timed out after 30s"));
  }, 30000);

  try {
    await donePromise;
  } finally {
    clearTimeout(timeout);
    try {
      child.kill();
    } catch {
      // Ignore already exited child.
    }
    server.close();
    // Give Chromium a brief moment to release profile locks on Windows before cleanup.
    setTimeout(() => {
      try {
        fs.rmSync(userDataDir, { recursive: true, force: true });
      } catch {
        // Ignore transient temp lock on Windows.
      }
    }, 300);
  }

  return results;
}

// ---------------------------------------------------------------------------
// 4. Pure-JS Hybrid Windows .ico & Apple .icns Encoders
// ---------------------------------------------------------------------------

/**
 * Encode 32-bit BGRA uncompressed BMP DIB (BITMAPINFOHEADER + bottom-up pixels + 1-bit AND mask)
 * for small ICO layers (16-64px) for universal Windows rc.exe / Explorer / GDI+ compatibility.
 */
function encodeIcoBmpDib(width, height, rgba) {
  const headerSize = 40;
  const pixelBytes = width * height * 4;
  const andRowStride = Math.ceil(width / 32) * 4;
  const andMaskBytes = andRowStride * height;
  const buf = Buffer.alloc(headerSize + pixelBytes + andMaskBytes);

  buf.writeUInt32LE(headerSize, 0);
  buf.writeInt32LE(width, 4);
  buf.writeInt32LE(height * 2, 8); // ICO DIB height includes XOR + AND masks
  buf.writeUInt16LE(1, 12); // planes
  buf.writeUInt16LE(32, 14); // bpp
  buf.writeUInt32LE(0, 16); // BI_RGB
  buf.writeUInt32LE(pixelBytes + andMaskBytes, 20);

  // Bottom-up BGRA pixels
  let dst = headerSize;
  for (let y = height - 1; y >= 0; y--) {
    for (let x = 0; x < width; x++) {
      const src = (y * width + x) * 4;
      buf[dst++] = rgba[src + 2]; // B
      buf[dst++] = rgba[src + 1]; // G
      buf[dst++] = rgba[src]; // R
      buf[dst++] = rgba[src + 3]; // A
    }
  }

  // Bottom-up 1-bit AND mask (bit=1 where fully transparent)
  const andStart = headerSize + pixelBytes;
  for (let y = height - 1; y >= 0; y--) {
    const rowOffset = andStart + (height - 1 - y) * andRowStride;
    for (let x = 0; x < width; x++) {
      const alpha = rgba[(y * width + x) * 4 + 3];
      if (alpha === 0) {
        buf[rowOffset + (x >> 3)] |= 0x80 >> (x & 7);
      }
    }
  }

  return buf;
}

function buildIcoBuffer(entries) {
  const header = Buffer.alloc(6);
  header.writeUInt16LE(0, 0); // reserved
  header.writeUInt16LE(1, 2); // type = ICO
  header.writeUInt16LE(entries.length, 4);

  const dirEntries = [];
  let offset = 6 + entries.length * 16;

  for (const entry of entries) {
    const dir = Buffer.alloc(16);
    dir.writeUInt8(entry.size >= 256 ? 0 : entry.size, 0);
    dir.writeUInt8(entry.size >= 256 ? 0 : entry.size, 1);
    dir.writeUInt8(0, 2);
    dir.writeUInt8(0, 3);
    dir.writeUInt16LE(1, 4);
    dir.writeUInt16LE(32, 6);
    dir.writeUInt32LE(entry.data.length, 8);
    dir.writeUInt32LE(offset, 12);
    dirEntries.push(dir);
    offset += entry.data.length;
  }

  return Buffer.concat([header, ...dirEntries, ...entries.map((e) => e.data)]);
}

function buildIcnsBuffer(chunks) {
  const blocks = chunks.map(({ type, data }) => {
    if (type.length !== 4) throw new Error(`Invalid ICNS OSType: ${type}`);
    const head = Buffer.alloc(8);
    head.write(type, 0, 4, "ascii");
    head.writeUInt32BE(8 + data.length, 4);
    return Buffer.concat([head, data]);
  });
  const totalLen = 8 + blocks.reduce((acc, b) => acc + b.length, 0);
  const fileHead = Buffer.alloc(8);
  fileHead.write("icns", 0, 4, "ascii");
  fileHead.writeUInt32BE(totalLen, 4);
  return Buffer.concat([fileHead, ...blocks]);
}

// ---------------------------------------------------------------------------
// 5. Main Asset Pipeline
// ---------------------------------------------------------------------------

function writeTextFile(relPath, content) {
  const fullPath = path.join(REPO_ROOT, relPath);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, content, "utf8");
  return relPath;
}

function writeBinaryFile(relPath, buffer) {
  const fullPath = path.join(REPO_ROOT, relPath);
  fs.mkdirSync(path.dirname(fullPath), { recursive: true });
  fs.writeFileSync(fullPath, buffer);
  return relPath;
}

async function main() {
  const cfg = parseArgs(process.argv.slice(2));
  const written = [];

  // 1) Authoritative SVG deliverables
  const logoVectorSvg = buildMasterLogoSvg(cfg, "bypax", {
    renderMode: "vector",
    includeSizeAttr: true,
    forDarkSurface: false,
  });
  const logoVectorOpticalSmallSvg = buildMasterLogoSvg(cfg, "bypax-opt", {
    renderMode: "vector",
    includeSizeAttr: true,
    forDarkSurface: false,
    opticalSmall: true,
  });
  const logoVectorCrispMedSvg = buildMasterLogoSvg(cfg, "bypax-md", {
    renderMode: "vector",
    includeSizeAttr: true,
    forDarkSurface: false,
    omitShadow: true,
  });
  const logoMeshSvg = buildMasterLogoSvg(cfg, "bypax-mesh", {
    renderMode: "mesh",
    includeSizeAttr: true,
    forDarkSurface: false,
  });
  const traySvg = buildTraySvg(cfg);
  const faviconSvg = buildMasterLogoSvg(cfg, "bypax-fav", {
    renderMode: "vector",
    includeSizeAttr: false,
    forDarkSurface: false,
    opticalSmall: true,
  });
  const bannerLightSvg = buildBannerSvg(cfg, "light");
  const bannerDarkSvg = buildBannerSvg(cfg, "dark");
  const socialSvg = buildSocialPreviewSvg(cfg);

  const xmlHeader = '<?xml version="1.0" encoding="UTF-8"?>\n';
  written.push(writeTextFile("src-tauri/icons/bypax-logo.svg", xmlHeader + logoVectorSvg + "\n"));
  written.push(writeTextFile("assets/bypax-logo-mesh.svg", xmlHeader + logoMeshSvg + "\n"));
  written.push(writeTextFile("src-tauri/icons/bypax-tray.svg", xmlHeader + traySvg + "\n"));
  written.push(writeTextFile("public/favicon.svg", xmlHeader + faviconSvg + "\n"));
  written.push(writeTextFile("assets/bypax-banner-light.svg", xmlHeader + bannerLightSvg + "\n"));
  written.push(writeTextFile("assets/bypax-banner-dark.svg", xmlHeader + bannerDarkSvg + "\n"));
  written.push(writeTextFile("assets/bypax-social-preview.svg", xmlHeader + socialSvg + "\n"));

  // 2) Hybrid rasterization batch (single headless Chromium launch)
  const jobs = [
    // Small-size optical pure-vector master (16..32px) + crisp standard vector (48..64px)
    { id: "vec-16", width: 16, height: 16, svg: logoVectorOpticalSmallSvg, wantRgba: true },
    { id: "vec-24", width: 24, height: 24, svg: logoVectorOpticalSmallSvg, wantRgba: true },
    { id: "vec-32", width: 32, height: 32, svg: logoVectorOpticalSmallSvg, wantRgba: true },
    { id: "vec-48", width: 48, height: 48, svg: logoVectorCrispMedSvg, wantRgba: true },
    { id: "vec-64", width: 64, height: 64, svg: logoVectorCrispMedSvg, wantRgba: true },
    // High-fi liquid mesh large icon sizes (128..1024px)
    { id: "mesh-128", width: 128, height: 128, svg: logoMeshSvg },
    { id: "mesh-256", width: 256, height: 256, svg: logoMeshSvg },
    { id: "mesh-512", width: 512, height: 512, svg: logoMeshSvg },
    { id: "mesh-1024", width: 1024, height: 1024, svg: logoMeshSvg },
    // System tray variants (6 transparent full-rainbow Overpass X PNGs: 44px @2x macOS + 32px Win/Linux)
    {
      id: "tray-color-2x",
      width: 44,
      height: 44,
      svg: buildRainbowTrayRasterSvg(cfg, { size: 44, idPrefix: "tr2x" }),
    },
    {
      id: "tray-color-2x-active",
      width: 44,
      height: 44,
      svg: buildRainbowTrayRasterSvg(cfg, { dotColor: "#10B981", size: 44, idPrefix: "tr2xa" }),
    },
    {
      id: "tray-color-2x-warn",
      width: 44,
      height: 44,
      svg: buildRainbowTrayRasterSvg(cfg, { dotColor: "#F59E0B", size: 44, idPrefix: "tr2xw" }),
    },
    {
      id: "tray-color",
      width: 32,
      height: 32,
      svg: buildRainbowTrayRasterSvg(cfg, { size: 32, idPrefix: "tr1x" }),
    },
    {
      id: "tray-color-active",
      width: 32,
      height: 32,
      svg: buildRainbowTrayRasterSvg(cfg, { dotColor: "#10B981", size: 32, idPrefix: "tr1xa" }),
    },
    {
      id: "tray-color-warn",
      width: 32,
      height: 32,
      svg: buildRainbowTrayRasterSvg(cfg, { dotColor: "#F59E0B", size: 32, idPrefix: "tr1xw" }),
    },
    // GitHub Social Preview (1280x640 PNG)
    { id: "social-preview", width: 1280, height: 640, svg: socialSvg },
  ];

  const raster = await rasterizeBatch(jobs);

  // 3) Write PNGs
  written.push(writeBinaryFile("src-tauri/icons/32x32.png", raster.get("vec-32").png));
  written.push(writeBinaryFile("src-tauri/icons/64x64.png", raster.get("vec-64").png));
  written.push(writeBinaryFile("src-tauri/icons/128x128.png", raster.get("mesh-128").png));
  written.push(writeBinaryFile("src-tauri/icons/128x128@2x.png", raster.get("mesh-256").png));
  written.push(writeBinaryFile("src-tauri/icons/icon.png", raster.get("mesh-1024").png));

  for (const name of [
    "tray-color-2x",
    "tray-color-2x-active",
    "tray-color-2x-warn",
    "tray-color",
    "tray-color-active",
    "tray-color-warn",
  ]) {
    written.push(writeBinaryFile(`src-tauri/icons/${name}.png`, raster.get(name).png));
  }

  written.push(
    writeBinaryFile("assets/bypax-social-preview.png", raster.get("social-preview").png),
  );

  // 4) Build hybrid Windows icon.ico (16/24/32/48/64 vector BMP DIB + 128/256 mesh PNG)
  const icoBuf = buildIcoBuffer([
    { size: 16, data: encodeIcoBmpDib(16, 16, raster.get("vec-16").rgba) },
    { size: 24, data: encodeIcoBmpDib(24, 24, raster.get("vec-24").rgba) },
    { size: 32, data: encodeIcoBmpDib(32, 32, raster.get("vec-32").rgba) },
    { size: 48, data: encodeIcoBmpDib(48, 48, raster.get("vec-48").rgba) },
    { size: 64, data: encodeIcoBmpDib(64, 64, raster.get("vec-64").rgba) },
    { size: 128, data: raster.get("mesh-128").png },
    { size: 256, data: raster.get("mesh-256").png },
  ]);
  written.push(writeBinaryFile("src-tauri/icons/icon.ico", icoBuf));

  // 5) Build hybrid macOS icon.icns (icp4..ic12 vector PNG + ic07..ic10 mesh PNG)
  const icnsBuf = buildIcnsBuffer([
    { type: "icp4", data: raster.get("vec-16").png },
    { type: "icp5", data: raster.get("vec-32").png },
    { type: "ic11", data: raster.get("vec-32").png },
    { type: "icp6", data: raster.get("vec-64").png },
    { type: "ic12", data: raster.get("vec-64").png },
    { type: "ic07", data: raster.get("mesh-128").png },
    { type: "ic08", data: raster.get("mesh-256").png },
    { type: "ic13", data: raster.get("mesh-256").png },
    { type: "ic09", data: raster.get("mesh-512").png },
    { type: "ic14", data: raster.get("mesh-512").png },
    { type: "ic10", data: raster.get("mesh-1024").png },
  ]);
  written.push(writeBinaryFile("src-tauri/icons/icon.icns", icnsBuf));

  console.log(
    `OK: generated ${written.length} Bypax brand assets (variant=${cfg.variant}, sat=${cfg.saturation}%, hue=${cfg.hueShift}deg, gap=${cfg.gapMode}).`,
  );
  for (const rel of written) {
    const stat = fs.statSync(path.join(REPO_ROOT, rel));
    console.log(`  - ${rel} (${stat.size} bytes)`);
  }
}

main().catch((err) => {
  console.error("ERROR:", err);
  process.exit(1);
});
