# -*- coding: utf-8 -*-
"""External tool profile builders and runtime health probes.

Pure-Python helper module so command/profile logic is testable outside Burp/Jython UI.
"""

import os
import tempfile
import time
import subprocess


PROFILE_FAST = "fast"
PROFILE_BALANCED = "balanced"
PROFILE_DEEP = "deep"


def normalize_profile(profile_value):
    """Normalize profile name to fast/balanced/deep."""
    raw = (profile_value or "").strip().lower()
    if raw in ["fast", "quick", "speed"]:
        return PROFILE_FAST
    if raw in ["deep", "thorough", "max", "maximum"]:
        return PROFILE_DEEP
    return PROFILE_BALANCED


def profile_labels():
    """UI-friendly profile labels."""
    return ["Fast", "Balanced", "Deep"]


def sqlmap_profile_settings(profile_value):
    """Return SQLMap tuning values for the selected profile."""
    profile = normalize_profile(profile_value)
    if profile == PROFILE_FAST:
        return {
            "profile": profile,
            "level": "1",
            "risk": "1",
            "threads": "1",
            "sql_timeout": "6",
            "retries": "0",
        }
    if profile == PROFILE_DEEP:
        return {
            "profile": profile,
            "level": "3",
            "risk": "2",
            "threads": "2",
            "sql_timeout": "12",
            "retries": "2",
        }
    return {
        "profile": PROFILE_BALANCED,
        "level": "2",
        "risk": "1",
        "threads": "1",
        "sql_timeout": "8",
        "retries": "1",
    }


def build_sqlmap_command(sqlmap_path, target, profile_value):
    """Build SQLMap command for one verification target."""
    cfg = sqlmap_profile_settings(profile_value)
    cmd = [
        sqlmap_path,
        "-u",
        target.get("url", ""),
        "--batch",
        "--level",
        cfg["level"],
        "--risk",
        cfg["risk"],
        "--threads",
        cfg["threads"],
        "--timeout",
        cfg["sql_timeout"],
        "--retries",
        cfg["retries"],
        "--flush-session",
    ]

    params = target.get("params", []) or []
    if params:
        cmd.extend(["-p", ",".join(params[:6])])

    method = (target.get("method") or "GET").upper()
    data = target.get("data") or ""
    if method in ["POST", "PUT", "PATCH", "DELETE"] and data:
        cmd.extend(["--method", method, "--data", data[:1200]])
    return cmd, cfg


def dalfox_profile_settings(profile_value):
    """Return Dalfox tuning values for the selected profile."""
    profile = normalize_profile(profile_value)
    if profile == PROFILE_FAST:
        return {
            "profile": profile,
            "timeout": "6",
            "worker": "20",
            "skip_mining": True,
        }
    if profile == PROFILE_DEEP:
        return {
            "profile": profile,
            "timeout": "12",
            "worker": "50",
            "skip_mining": False,
        }
    return {
        "profile": PROFILE_BALANCED,
        "timeout": "8",
        "worker": "30",
        "skip_mining": True,
    }


def build_dalfox_command(dalfox_path, target, out_file, profile_value):
    """Build Dalfox command for one verification target."""
    cfg = dalfox_profile_settings(profile_value)
    cmd = [
        dalfox_path,
        "url",
        target.get("url", ""),
        "--format",
        "jsonl",
        "-o",
        out_file,
        "-S",
        "--no-color",
        "--timeout",
        cfg["timeout"],
        "--worker",
        cfg["worker"],
    ]
    if cfg["skip_mining"]:
        cmd.extend(["--skip-bav", "--skip-mining-all", "--skip-mining-dom", "--skip-headless"])

    for param in (target.get("params", []) or [])[:4]:
        cmd.extend(["-p", param])

    method = (target.get("method") or "GET").upper()
    data = target.get("data") or ""
    if method in ["POST", "PUT", "PATCH", "DELETE"] and data:
        cmd.extend(["-X", method, "-d", data[:1200]])
    return cmd, cfg


def asset_profile_settings(profile_value):
    """Return API asset discovery stage tuning."""
    profile = normalize_profile(profile_value)
    if profile == PROFILE_FAST:
        return {
            "profile": profile,
            "subfinder_timeout": 150,
            "dnsx_timeout": 120,
            "httpx_timeout": 150,
            "httpx_args": ["-sc"],
        }
    if profile == PROFILE_DEEP:
        return {
            "profile": profile,
            "subfinder_timeout": 360,
            "dnsx_timeout": 240,
            "httpx_timeout": 360,
            "httpx_args": ["-sc", "-title", "-tech-detect", "-server"],
        }
    return {
        "profile": PROFILE_BALANCED,
        "subfinder_timeout": 240,
        "dnsx_timeout": 180,
        "httpx_timeout": 240,
        "httpx_args": ["-sc", "-title"],
    }


def build_asset_stage_commands(
    subfinder_path,
    dnsx_path,
    httpx_path,
    domains_file,
    subfinder_file,
    dnsx_file,
    httpx_file,
    profile_value,
):
    """Build staged subfinder -> dnsx -> httpx commands."""
    cfg = asset_profile_settings(profile_value)

    subfinder_cmd = [
        subfinder_path,
        "-dL",
        domains_file,
        "-silent",
        "-o",
        subfinder_file,
    ]
    dnsx_cmd = [
        dnsx_path,
        "-l",
        subfinder_file,
        "-silent",
        "-o",
        dnsx_file,
    ]
    httpx_cmd = [httpx_path, "-l", dnsx_file, "-silent"]
    httpx_cmd.extend(cfg["httpx_args"])
    httpx_cmd.extend(["-o", httpx_file])

    return [
        ("Subfinder", subfinder_cmd, int(cfg["subfinder_timeout"])),
        ("DNSX", dnsx_cmd, int(cfg["dnsx_timeout"])),
        ("HTTPX", httpx_cmd, int(cfg["httpx_timeout"])),
    ], cfg


def nuclei_profile_settings(profile_value):
    """Return Nuclei tuning values for selected profile."""
    profile = normalize_profile(profile_value)
    if profile == PROFILE_FAST:
        return {
            "profile": profile,
            "include_tags": "exposure,api,swagger,openapi",
            "exclude_tags": "dos,intrusive,headless,cve,fuzz,fuzzing,brute-force",
            "request_timeout": 8,
            "retries": 1,
            "rate_limit": 100,
            "concurrency": 20,
            "bulk_size": 8,
            "max_host_error": 8,
            "scan_strategy": "host-spray",
            "max_scan_seconds": 600,
        }
    if profile == PROFILE_DEEP:
        return {
            "profile": profile,
            "include_tags": "exposure,api,swagger,openapi,graphql,auth,jwt,config,debug,backup,logs,trace,files,paths",
            "exclude_tags": "dos,intrusive,headless,cve,fuzz,fuzzing,brute-force",
            "request_timeout": 12,
            "retries": 2,
            "rate_limit": 40,
            "concurrency": 8,
            "bulk_size": 4,
            "max_host_error": 6,
            "scan_strategy": "host-spray",
            "max_scan_seconds": 1200,
        }
    return {
        "profile": PROFILE_BALANCED,
        "include_tags": "exposure,api,swagger,openapi,graphql,auth,jwt,config",
        "exclude_tags": "dos,intrusive,headless,cve,fuzz,fuzzing,brute-force",
        "request_timeout": 10,
        "retries": 1,
        "rate_limit": 70,
        "concurrency": 12,
        "bulk_size": 6,
        "max_host_error": 8,
        "scan_strategy": "host-spray",
        "max_scan_seconds": 900,
    }


def _decode_safe(data):
    """Decode subprocess output to text safely."""
    if data is None:
        return ""
    if isinstance(data, bytes):
        try:
            return data.decode("utf-8", "ignore")
        except Exception as e:
            return "<decode-bytes-error:{}>".format(str(e))
    try:
        return str(data)
    except Exception as e:
        return "<decode-error:{}>".format(str(e))


def _read_file_safe(path):
    """Read text file contents safely."""
    if not path or not os.path.exists(path):
        return ""
    reader = None
    text = ""
    read_error = ""
    close_error = ""
    try:
        reader = open(path, "rb")
        text = _decode_safe(reader.read())
    except Exception as e:
        read_error = str(e)
    finally:
        if reader:
            try:
                reader.close()
            except Exception as e:
                close_error = str(e)

    if read_error:
        return "<read-error:{}>".format(read_error)
    if close_error:
        return "<close-error:{}>".format(close_error)
    return text


def probe_binary_help(binary_path, help_flags=None, timeout_seconds=8):
    """Probe binary help text without pipe-deadlock by capturing to temp file."""
    result = {
        "path": binary_path or "",
        "ok": False,
        "help_flag": "",
        "error": "",
        "help_text": "",
        "return_code": None,
        "timed_out": False,
    }
    if not binary_path:
        result["error"] = "empty binary path"
        return result

    flags = list(help_flags or ["-h", "--help"])
    best_text = ""
    last_error = ""

    for flag in flags:
        capture_path = None
        capture_handle = None
        process = None
        try:
            fd, capture_path = tempfile.mkstemp(prefix="tool_probe_", suffix=".log")
            os.close(fd)
            capture_handle = open(capture_path, "wb")
            process = subprocess.Popen(
                [binary_path, flag],
                stdout=capture_handle,
                stderr=subprocess.STDOUT,
                shell=False,
            )
        except Exception as e:
            last_error = str(e)
            if capture_handle:
                try:
                    capture_handle.close()
                except Exception as close_err:
                    last_error = "{} | close error: {}".format(
                        last_error, str(close_err)
                    )
            if capture_path:
                try:
                    os.remove(capture_path)
                except Exception as rm_err:
                    last_error = "{} | cleanup error: {}".format(
                        last_error, str(rm_err)
                    )
            continue

        timed_out = False
        started = time.time()
        while process.poll() is None:
            if (time.time() - started) > timeout_seconds:
                timed_out = True
                try:
                    process.terminate()
                except Exception as e:
                    last_error = "terminate error: {}".format(str(e))
                wait_started = time.time()
                while process.poll() is None and (time.time() - wait_started) < 2:
                    time.sleep(0.1)
                if process.poll() is None:
                    try:
                        process.kill()
                    except Exception as e:
                        last_error = "kill error: {}".format(str(e))
                break
            time.sleep(0.1)

        if capture_handle:
            try:
                capture_handle.close()
            except Exception as e:
                last_error = "close error: {}".format(str(e))

        text = _read_file_safe(capture_path)
        if capture_path:
            try:
                os.remove(capture_path)
            except Exception as e:
                last_error = "cleanup error: {}".format(str(e))
        if text and len(text) > len(best_text):
            best_text = text

        rc = process.returncode
        markers = (text or "").lower()
        has_help_text = (
            "usage" in markers
            or "options" in markers
            or "flags:" in markers
            or "commands:" in markers
        )
        if (not timed_out) and (rc == 0 or has_help_text):
            result["ok"] = True
            result["help_flag"] = flag
            result["return_code"] = rc
            result["help_text"] = text or best_text
            return result

        if timed_out:
            result["timed_out"] = True
            last_error = "timed out after {}s".format(timeout_seconds)
        else:
            last_error = "exit code {}".format(rc)

    result["help_text"] = best_text
    result["error"] = last_error or "unable to execute binary"
    return result


def evaluate_help_text(help_text, required_tokens=None, forbidden_tokens=None):
    """Evaluate required/forbidden token health on help output."""
    lower_text = (help_text or "").lower()
    required_tokens = list(required_tokens or [])
    forbidden_tokens = list(forbidden_tokens or [])
    missing = [token for token in required_tokens if token.lower() not in lower_text]
    forbidden_found = [token for token in forbidden_tokens if token.lower() in lower_text]
    return {
        "missing": missing,
        "forbidden_found": forbidden_found,
        "healthy": (len(missing) == 0 and len(forbidden_found) == 0),
    }
