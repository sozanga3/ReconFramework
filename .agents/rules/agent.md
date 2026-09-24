# 🤖 AGENT.MD — AI Agent Operating Instructions

> This file is an entrypoint and alias for [AGENTS.md](file:///home/akram/Documents/recon_framework-3.2.0/AGENTS.md).
>
> Please consult the primary guideline documents:
> - **Operational & Coding Rules:** [AGENTS.md](file:///home/akram/Documents/recon_framework-3.2.0/AGENTS.md)
> - **Architecture & Pipeline Reference:** [CONTEXT.md](file:///home/akram/Documents/recon_framework-3.2.0/CONTEXT.md)
> - **User & Setup Guide:** [README.md](file:///home/akram/Documents/recon_framework-3.2.0/README.md)

---

## ⚡ Quick Reference Checklist for AI Agents

1. **Subprocess Execution:** Call `core.runner.run_command(cmd_args_list)` — never `os.system` or raw `shell=True`.
2. **Binary Resolution:** Import tool paths from `config.tools` and verify with `is_tool_available()`.
3. **Configuration:** Read thread limits, timeouts, rate limits, and thresholds from `config.settings`.
4. **Data Hygiene & Strict Scope Enforcement:**
   - Scope Invariant: Anchor all domains with `candidate == target or candidate.endswith('.' + target)`.
   - Never use loose substring checks (`target in candidate`). Discard multi-tenant SANs and external JS APIs.
   - Noise: Strip `EXCLUDED_EXTENSIONS` and `NOISE_PARAMS`.
   - Deduplication: Apply `unique_list()` or `clean_data()`.
5. **State & Resume:** Wrap all pipeline steps with `core.state.run_or_resume()`.
6. **Output Integrity:** Preserve schemas for `stats.json`, `ranked.json`, `safety_profile.json`, and `scored_params.json`.
7. **Verification:** Validate code syntax with `python3 -m py_compile main.py core/*.py modules/*.py config/*.py`.
