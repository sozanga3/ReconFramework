import json
import os

def load_state(paths):
    """Load the state file if it exists, otherwise return an empty state dict."""
    state_file = f"{paths['base']}/state.json"
    if os.path.exists(state_file):
        try:
            with open(state_file, "r") as f:
                return json.load(f)
        except Exception:
            return {}
    return {}

def save_state(paths, step_name):
    """Mark a step as completed in the state file."""
    state = load_state(paths)
    state[step_name] = True
    
    state_file = f"{paths['base']}/state.json"
    try:
        with open(state_file, "w") as f:
            json.dump(state, f, indent=4)
    except Exception as e:
        print(f"[!] Warning: Could not save state for step {step_name} - {e}")

def is_step_completed(paths, step_name):
    """Check if a specific step has been completed in previous runs."""
    state = load_state(paths)
    return state.get(step_name, False)

def load_list_from_file(filepath):
    """Fallback loader for simple lists from text files."""
    if not os.path.exists(filepath): return []
    with open(filepath, "r") as f:
        return [line.strip() for line in f if line.strip() and not line.startswith("#")]

def load_json_from_file(filepath):
    """Fallback loader for JSON results."""
    if not os.path.exists(filepath): return []
    try:
        with open(filepath, "r") as f:
            return json.load(f)
    except:
        return []

def load_tuple_from_file(filepath):
    """Fallback loader for crawler tuple (js_files, endpoints) from raw file."""
    if not os.path.exists(filepath):
        return [], []
    
    from config.settings import EXCLUDED_EXTENSIONS
    js_files = set()
    endpoints = set()
    
    with open(filepath, "r") as f:
        for line in f:
            url = line.strip()
            if not url:
                continue
            
            # Global Exclusion Filter
            if any(bad in url.lower() for bad in EXCLUDED_EXTENSIONS):
                continue

            if url.endswith(".js") or ".js?" in url:
                js_files.add(url)
            else:
                endpoints.add(url)
                
    return list(js_files), list(endpoints)

def run_or_resume(resume_mode, paths, step_name, fallback_file, loader_type, func, *args, **kwargs):
    """
    If resume_mode is True and the step is completed, it loads from fallback_file.
    Otherwise, runs the func and saves state.
    """
    if resume_mode and is_step_completed(paths, step_name):
        print(f"[*] Skipping {step_name} (already completed) - Loading state...")
        if loader_type == "list":
            return load_list_from_file(fallback_file)
        elif loader_type == "json":
            return load_json_from_file(fallback_file)
        elif loader_type == "tuple":
            return load_tuple_from_file(fallback_file)
        return []
    
    # Run the actual function
    result = func(*args, **kwargs)
    
    # Only save state if we actually got a result (or ran it)
    if resume_mode or result or result == []:
        save_state(paths, step_name)
        
    return result
