import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App";
import { TrayPopup } from "./features/tray/TrayPopup";
import "./index.css";

if (typeof window !== "undefined") {
  // Suppress WebView2 / browser default right-click menu ("Back / Reload / Save as / Print")
  // across desktop chrome while preserving native cut/copy/paste inside editable inputs and
  // selectable code/log blocks.
  window.addEventListener("contextmenu", (event) => {
    const target = event.target as HTMLElement | null;
    if (target) {
      const editable = target.closest(
        'textarea, [contenteditable="true"], input:not([type="checkbox"]):not([type="radio"]):not([type="button"]):not([type="submit"]):not([type="range"])',
      );
      if (editable) return;

      const selectedText = window.getSelection()?.toString().trim() ?? "";
      if (selectedText.length > 0 && target.closest(".select-text, pre, code")) {
        return;
      }
    }
    event.preventDefault();
  });
}

const isTrayView =
  typeof window !== "undefined" &&
  new URLSearchParams(window.location.search).get("view") === "tray";

ReactDOM.createRoot(document.getElementById("root") as HTMLElement).render(
  <React.StrictMode>{isTrayView ? <TrayPopup /> : <App />}</React.StrictMode>
);
