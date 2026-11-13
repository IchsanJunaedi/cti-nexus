import type { DiagramState, ViewState } from "../types";

export const LS_KEY = "netdraw:autosave";

export interface PersistedDoc {
  state: DiagramState;
  view: ViewState;
}

export function loadFromLocalStorage(): PersistedDoc | null {
  try {
    const raw = localStorage.getItem(LS_KEY);
    if (!raw) return null;
    return JSON.parse(raw) as PersistedDoc;
  } catch {
    return null;
  }
}

export function downloadJSON(doc: PersistedDoc, name = "diagram.json") {
  const blob = new Blob([JSON.stringify(doc, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export function importJSONFile(file: File): Promise<PersistedDoc> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = () => {
      try {
        const doc = JSON.parse(String(reader.result)) as PersistedDoc;
        resolve(doc);
      } catch (err) {
        reject(err);
      }
    };
    reader.onerror = reject;
    reader.readAsText(file);
  });
}
