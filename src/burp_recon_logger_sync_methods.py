# -*- coding: utf-8 -*-
# pylint: disable=import-error
"""Recon/Logger dual-sync orchestration and memory-safe proxy-history window helpers."""
import threading
import time


def _proxy_history_tail_window(self, max_items):
    """Return at most max_items newest proxy-history rows without full-history copying."""
    try:
        limit = int(max_items or 0)
    except (TypeError, ValueError):
        limit = 1000
    limit = max(1, min(120000, limit))

    history = self._callbacks.getProxyHistory()
    if not history:
        return []

    size_fn = getattr(history, "size", None)
    get_fn = getattr(history, "get", None)
    if callable(size_fn) and callable(get_fn):
        try:
            total = int(size_fn() or 0)
            if total <= 0:
                return []
            start = max(0, total - limit)
            rows = []
            for idx in range(start, total):
                rows.append(get_fn(idx))
            return rows
        except Exception as java_list_err:
            self._callbacks.printError(
                "Proxy history Java-window fallback: {}".format(str(java_list_err))
            )

    try:
        rows = list(history or [])
    except Exception as iter_err:
        self._callbacks.printError("Proxy history snapshot error: {}".format(str(iter_err)))
        return []
    if len(rows) > limit:
        rows = rows[-limit:]
    return rows


def _wait_for_backfill_idle(self, flag_attr, timeout_seconds=240):
    """Wait until one backfill flag is cleared (best effort, bounded wait)."""
    timeout_s = int(timeout_seconds or 0)
    if timeout_s < 5:
        timeout_s = 5
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if not bool(getattr(self, flag_attr, False)):
            return True
        time.sleep(0.12)
    return not bool(getattr(self, flag_attr, False))


def _run_recon_logger_backfill_pipeline(self, force=False):
    """Run Recon then Logger history backfill as one bounded pipeline."""
    run_force = bool(force)
    with self.lock:
        if bool(getattr(self, "recon_logger_backfill_pipeline_running", False)):
            if run_force:
                self.recon_logger_backfill_pipeline_force_pending = True
            self.log_to_ui("[*] Recon/Logger refill already running")
            return
        self.recon_logger_backfill_pipeline_running = True
        self.recon_logger_backfill_pipeline_force_pending = False

    def _worker():
        rerun_force = False
        try:
            self._recon_backfill_history(force=run_force)
            recon_ok = self._wait_for_backfill_idle("recon_backfill_running", 240)
            if not recon_ok:
                self.log_to_ui("[!] Recon refill timeout; skipped coupled Logger refill")
                return
            self._logger_backfill_history(force=run_force)
        finally:
            with self.lock:
                rerun_force = bool(
                    getattr(self, "recon_logger_backfill_pipeline_force_pending", False)
                )
                self.recon_logger_backfill_pipeline_running = False
                self.recon_logger_backfill_pipeline_force_pending = False
            if rerun_force:
                self._run_recon_logger_backfill_pipeline(force=True)

    worker = threading.Thread(target=_worker, name="recon-logger-backfill")
    worker.daemon = True
    worker.start()


def _refresh_recon_and_logger_views(self):
    """Refresh Recon and Logger views together to keep UI state aligned."""
    self.refresh_view()
    if hasattr(self, "_refresh_logger_view"):
        self._refresh_logger_view()


def _backfill_recon_and_logger(self, force=False):
    """Run Recon+Logger refill through a single coordinated pipeline."""
    self._run_recon_logger_backfill_pipeline(force=force)


def _clear_and_refill_recon_logger(self):
    """Clear Recon/Logger data, then refill both from Proxy history."""
    self.clear_data()
    self._backfill_recon_and_logger(force=True)


def _on_recon_autopopulate_toggle(self):
    """Handle Recon history-autopopulate checkbox changes."""
    box = getattr(self, "recon_autopopulate_checkbox", None)
    enabled = True if box is None else bool(box.isSelected())
    self.recon_autopopulate_on_open = enabled
    if enabled:
        self._backfill_recon_and_logger(force=True)
    else:
        self.log_to_ui("[*] Recon autopopulate disabled")


def _maybe_backfill_logger_on_open(self):
    """Avoid duplicate heavy backfills when Recon autopopulate already seeds Logger."""
    import_on_open_box = getattr(self, "logger_import_on_open_checkbox", None)
    import_on_open = bool(getattr(self, "logger_import_on_open", True))
    if import_on_open_box is not None:
        import_on_open = bool(import_on_open_box.isSelected())
    if not import_on_open:
        return
    if bool(getattr(self, "recon_autopopulate_on_open", True)):
        return
    self._logger_backfill_history(force=False)


__all__ = [
    "_proxy_history_tail_window",
    "_wait_for_backfill_idle",
    "_run_recon_logger_backfill_pipeline",
    "_refresh_recon_and_logger_views",
    "_backfill_recon_and_logger",
    "_clear_and_refill_recon_logger",
    "_on_recon_autopopulate_toggle",
    "_maybe_backfill_logger_on_open",
]
