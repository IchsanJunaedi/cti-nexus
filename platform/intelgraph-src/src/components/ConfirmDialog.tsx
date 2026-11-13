import { useState, useCallback } from "react";

interface ConfirmState {
  message: string;
  resolve: (ok: boolean) => void;
}

export function useConfirm() {
  const [state, setState] = useState<ConfirmState | null>(null);

  const confirm = useCallback((message: string): Promise<boolean> => {
    return new Promise((resolve) => {
      setState({ message, resolve });
    });
  }, []);

  function handle(ok: boolean) {
    state?.resolve(ok);
    setState(null);
  }

  const dialog = state ? (
    <div className="confirm-overlay" onClick={() => handle(false)}>
      <div className="confirm-box" onClick={(e) => e.stopPropagation()}>
        <div className="confirm-message">{state.message}</div>
        <div className="confirm-actions">
          <button className="confirm-cancel" onClick={() => handle(false)}>
            Cancel
          </button>
          <button className="confirm-ok" onClick={() => handle(true)} autoFocus>
            Delete
          </button>
        </div>
      </div>
    </div>
  ) : null;

  return { confirm, confirmDialog: dialog };
}
