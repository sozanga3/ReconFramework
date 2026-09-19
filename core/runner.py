import subprocess
import os
import signal
from core.output import debug_log

def run_command(cmd_args, timeout=300, debug_path=None, cwd=None):
    """
    Safely executes a command.
    cmd_args should be a list of arguments (e.g., ["katana", "-list", "targets.txt"]).
    Avoids shell=True to prevent zombie processes.
    """
    if not cmd_args or not cmd_args[0]:
        return []
    try:
        result = subprocess.run(
            cmd_args,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd
        )
        if result.returncode != 0 and debug_path:
            err_snip = result.stderr[:200] if result.stderr else ""
            debug_log(f"[Tool Error] {cmd_args[0]}: {err_snip}", debug_path)
        return result.stdout.splitlines() if result.stdout else []
    except subprocess.TimeoutExpired:
        if debug_path:
            debug_log(f"[Timeout] {cmd_args[0]} exceeded {timeout}s", debug_path)
        return []
    except FileNotFoundError as e:
        if debug_path:
            debug_log(f"[Tool Not Found] {cmd_args[0]}: {e}", debug_path)
        return []
    except Exception as e:
        if debug_path:
            debug_log(f"[Exception] {cmd_args[0]}: {e}", debug_path)
        return []

def run_command_with_input(cmd_args, input_data, timeout=300, debug_path=None, cwd=None):
    """
    Safely executes a command passing input_data to stdin.
    """
    if not cmd_args or not cmd_args[0]:
        return []
    try:
        result = subprocess.run(
            cmd_args,
            input=input_data,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=cwd
        )
        if result.returncode != 0 and debug_path:
            err_snip = result.stderr[:200] if result.stderr else ""
            debug_log(f"[Tool Error] {cmd_args[0]}: {err_snip}", debug_path)
        return result.stdout.splitlines() if result.stdout else []
    except subprocess.TimeoutExpired:
        if debug_path:
            debug_log(f"[Timeout] {cmd_args[0]} exceeded {timeout}s", debug_path)
        return []
    except FileNotFoundError as e:
        if debug_path:
            debug_log(f"[Tool Not Found] {cmd_args[0]}: {e}", debug_path)
        return []
    except Exception as e:
        if debug_path:
            debug_log(f"[Exception] {cmd_args[0]}: {e}", debug_path)
        return []

def run_command_shell(cmd_string, timeout=300, debug_path=None, cwd=None):
    """
    USE ONLY WHEN NECESSARY (e.g. complex pipes).
    Uses shell=True but wraps in a process group to prevent zombie children on timeout.
    """
    if not cmd_string:
        return []
    try:
        proc = subprocess.Popen(
            cmd_string,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
            cwd=cwd
        )
        try:
            stdout, stderr = proc.communicate(timeout=timeout)
            if proc.returncode != 0 and debug_path:
                tool_name = cmd_string.split()[0]
                err_snip = stderr[:200] if stderr else ""
                debug_log(f"[Tool Error] {tool_name}: {err_snip}", debug_path)
            return stdout.splitlines() if stdout else []
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except OSError:
                pass
            proc.communicate() # wait for cleanup
            if debug_path:
                tool_name = cmd_string.split()[0]
                debug_log(f"[Timeout] {tool_name} exceeded {timeout}s (Process Group Killed)", debug_path)
            return []
    except FileNotFoundError as e:
        if debug_path:
            debug_log(f"[Tool Not Found] {cmd_string.split()[0]}: {e}", debug_path)
        return []
    except Exception as e:
        if debug_path:
            debug_log(f"[Exception] {cmd_string.split()[0]}: {e}", debug_path)
        return []