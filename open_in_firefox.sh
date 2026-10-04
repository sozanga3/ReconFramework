#!/usr/bin/env bash
# ==============================================================================
# open_in_firefox.sh - Open URLs from a file in Firefox in configurable chunks
# ==============================================================================
#
# Usage:
#   ./open_in_firefox.sh [options] [file] [chunk_size] [delay]
#
# Examples:
#   ./open_in_firefox.sh urls.txt                   # 10 URLs per chunk, press Enter for next
#   ./open_in_firefox.sh urls.txt 15                # 15 URLs per chunk, press Enter for next
#   ./open_in_firefox.sh urls.txt 10 5              # 10 URLs per chunk, 5s delay between chunks
#   ./open_in_firefox.sh -f urls.txt -s 20 --private# 20 URLs per chunk in private browsing
# ==============================================================================

# ANSI Color codes (bash ANSI-C quoting)
BOLD=$'\e[1m'
GREEN=$'\e[0;32m'
CYAN=$'\e[0;36m'
YELLOW=$'\e[1;33m'
RED=$'\e[0;31m'
BLUE=$'\e[0;34m'
DIM=$'\e[2m'
RESET=$'\e[0m'

# Default configuration
CHUNK_SIZE=10
DELAY=0
INPUT_FILE=""
PRIVATE_MODE=0
DRY_RUN=0
BROWSER_BIN=""

# Handle graceful exit on Ctrl+C
trap 'echo -e "\n\n${YELLOW}[!] Script terminated by user.${RESET}"; exit 130' SIGINT

show_help() {
    cat << EOF
${BOLD}open_in_firefox.sh${RESET} - Open URL lists in Firefox in chunks / batches

${BOLD}USAGE:${RESET}
  $0 [OPTIONS] [FILE] [CHUNK_SIZE] [DELAY]

${BOLD}POSITIONAL ARGUMENTS:${RESET}
  FILE            Path to the file containing URLs (one per line)
  CHUNK_SIZE      Number of tabs to open per batch (default: 10)
  DELAY           Seconds to wait between batches. If 0 or omitted,
                  the script pauses and waits for user confirmation (Enter).

${BOLD}OPTIONS:${RESET}
  -f, --file PATH       Path to the URL list file
  -s, --size NUM        Number of URLs per chunk (default: 10)
  -d, --delay SECONDS   Automatic delay in seconds between chunks (default: interactive)
  -p, --private         Open URLs in Private Browsing mode
  -n, --dry-run         Simulate and preview batches without launching Firefox
  -b, --browser PATH    Custom browser binary (defaults to detecting 'firefox')
  -h, --help            Show this help message and exit

${BOLD}INTERACTIVE CONTROLS:${RESET}
  When running in interactive mode (delay = 0), at each batch prompt you can:
    • Press ${BOLD}[Enter]${RESET} to open the next batch
    • Type  ${BOLD}s${RESET} + [Enter] to skip the current batch
    • Type  ${BOLD}q${RESET} + [Enter] to quit the script
EOF
}

# Find Firefox binary
find_browser() {
    if [[ -n "$BROWSER_BIN" ]]; then
        if command -v "$BROWSER_BIN" >/dev/null 2>&1; then
            return 0
        fi
        echo -e "${RED}[ERROR] Specified browser '$BROWSER_BIN' not found.${RESET}" >&2
        exit 1
    fi

    for candidate in firefox firefox-esr; do
        if command -v "$candidate" >/dev/null 2>&1; then
            BROWSER_BIN="$(command -v "$candidate")"
            return 0
        fi
    done

    echo -e "${RED}[ERROR] Neither 'firefox' nor 'firefox-esr' was found in your PATH.${RESET}" >&2
    echo -e "${YELLOW}Please install Firefox or specify the path with -b /path/to/firefox${RESET}" >&2
    exit 1
}

# Parse command line flags & positional arguments
POSITIONAL_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -f|--file)
            INPUT_FILE="$2"
            shift 2
            ;;
        -s|--size|--chunk-size)
            CHUNK_SIZE="$2"
            shift 2
            ;;
        -d|--delay)
            DELAY="$2"
            shift 2
            ;;
        -p|--private)
            PRIVATE_MODE=1
            shift
            ;;
        -n|--dry-run)
            DRY_RUN=1
            shift
            ;;
        -b|--browser)
            BROWSER_BIN="$2"
            shift 2
            ;;
        -*)
            echo -e "${RED}[ERROR] Unknown option: $1${RESET}" >&2
            show_help
            exit 1
            ;;
        *)
            POSITIONAL_ARGS+=("$1")
            shift
            ;;
    esac
done

# Map positional arguments if not provided by flags
if [[ -z "$INPUT_FILE" && ${#POSITIONAL_ARGS[@]} -ge 1 ]]; then
    INPUT_FILE="${POSITIONAL_ARGS[0]}"
fi

if [[ ${#POSITIONAL_ARGS[@]} -ge 2 ]]; then
    CHUNK_SIZE="${POSITIONAL_ARGS[1]}"
fi

if [[ ${#POSITIONAL_ARGS[@]} -ge 3 ]]; then
    DELAY="${POSITIONAL_ARGS[2]}"
fi

# Prompt for file if still missing
if [[ -z "$INPUT_FILE" ]]; then
    echo -e "${CYAN}${BOLD}Firefox URL Chunk Opener${RESET}\n"
    read -r -p "Enter path to URL file: " INPUT_FILE
fi

# Validation
if [[ -z "$INPUT_FILE" || ! -f "$INPUT_FILE" ]]; then
    echo -e "${RED}[ERROR] File '$INPUT_FILE' does not exist or is not readable.${RESET}" >&2
    exit 1
fi

if ! [[ "$CHUNK_SIZE" =~ ^[1-9][0-9]*$ ]]; then
    echo -e "${RED}[ERROR] Chunk size must be a positive integer, got '$CHUNK_SIZE'.${RESET}" >&2
    exit 1
fi

if ! [[ "$DELAY" =~ ^[0-9]+(\.[0-9]+)?$ ]]; then
    echo -e "${RED}[ERROR] Delay must be a non-negative number, got '$DELAY'.${RESET}" >&2
    exit 1
fi

find_browser

# Read and sanitize URLs into array
# Strips empty lines, trailing CRLF '\r', comments starting with '#'
# Prepends https:// if missing scheme
URLS=()
while IFS= read -r line || [[ -n "$line" ]]; do
    # Strip carriage return and leading/trailing whitespace
    line="${line//$'\r'/}"
    line="$(echo "$line" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')"

    # Skip empty lines and comment lines
    [[ -z "$line" ]] && continue
    [[ "$line" =~ ^# ]] && continue

    # Ensure URL has protocol scheme
    if [[ ! "$line" =~ ^[a-zA-Z][a-zA-Z0-9+.-]*:// ]]; then
        line="https://$line"
    fi

    URLS+=("$line")
done < "$INPUT_FILE"

TOTAL_URLS=${#URLS[@]}

if [[ "$TOTAL_URLS" -eq 0 ]]; then
    echo -e "${YELLOW}[!] No valid URLs found in '$INPUT_FILE'. Exiting.${RESET}"
    exit 0
fi

# Compute total chunks
TOTAL_CHUNKS=$(( (TOTAL_URLS + CHUNK_SIZE - 1) / CHUNK_SIZE ))

echo -e "\n${BOLD}${CYAN}======================================================${RESET}"
echo -e "${BOLD}${GREEN}  Firefox URL Batch Opener${RESET}"
echo -e "${BOLD}${CYAN}======================================================${RESET}"
echo -e "  ${BOLD}Input File:${RESET}    $INPUT_FILE"
echo -e "  ${BOLD}Total URLs:${RESET}    ${YELLOW}${TOTAL_URLS}${RESET}"
echo -e "  ${BOLD}Chunk Size:${RESET}    ${YELLOW}${CHUNK_SIZE}${RESET} URLs/batch"
echo -e "  ${BOLD}Total Batches:${RESET} ${YELLOW}${TOTAL_CHUNKS}${RESET}"
echo -e "  ${BOLD}Browser:${RESET}       $BROWSER_BIN"
is_delay_enabled() {
    awk -v d="$DELAY" 'BEGIN{exit !(d > 0)}' 2>/dev/null
}

if [[ "$DRY_RUN" -eq 1 ]]; then
    echo -e "  ${BOLD}Mode:${RESET}          ${YELLOW}[DRY RUN] Simulation only (no tabs opened)${RESET}"
elif [[ "$PRIVATE_MODE" -eq 1 ]]; then
    echo -e "  ${BOLD}Mode:${RESET}          ${CYAN}Private Window${RESET}"
fi
if is_delay_enabled; then
    echo -e "  ${BOLD}Pacing:${RESET}        Auto-advance after ${YELLOW}${DELAY}s${RESET}"
else
    echo -e "  ${BOLD}Pacing:${RESET}        ${GREEN}Interactive (wait for Enter key)${RESET}"
fi
echo -e "${BOLD}${CYAN}======================================================${RESET}\n"

# Process chunks
CURRENT_INDEX=0
CHUNK_NUM=1

while [[ $CURRENT_INDEX -lt $TOTAL_URLS ]]; do
    # Extract sub-slice for this chunk
    END_INDEX=$(( CURRENT_INDEX + CHUNK_SIZE ))
    if [[ $END_INDEX -gt $TOTAL_URLS ]]; then
        END_INDEX=$TOTAL_URLS
    fi
    CURRENT_BATCH_COUNT=$(( END_INDEX - CURRENT_INDEX ))

    BATCH_URLS=("${URLS[@]:CURRENT_INDEX:CURRENT_BATCH_COUNT}")

    echo -e "${BOLD}${BLUE}--- Batch [${CHUNK_NUM}/${TOTAL_CHUNKS}] (${CURRENT_BATCH_COUNT} URLs: #$((CURRENT_INDEX + 1)) to #${END_INDEX} of ${TOTAL_URLS}) ---${RESET}"
    
    # Print preview of URLs in this batch
    for u in "${BATCH_URLS[@]}"; do
        echo -e "  ${DIM}→${RESET} $u"
    done

    # Open URLs in Firefox (or simulate if dry run)
    if [[ "$DRY_RUN" -eq 1 ]]; then
        echo -e "${YELLOW}⚡ [DRY RUN] Simulated opening ${CURRENT_BATCH_COUNT} tabs in Firefox.${RESET}"
    elif [[ "$PRIVATE_MODE" -eq 1 ]]; then
        ("$BROWSER_BIN" --private-window "${BATCH_URLS[@]}" >/dev/null 2>&1 &)
        echo -e "${GREEN}✓ Launched ${CURRENT_BATCH_COUNT} tabs in Firefox (Private).${RESET}"
    else
        ("$BROWSER_BIN" "${BATCH_URLS[@]}" >/dev/null 2>&1 &)
        echo -e "${GREEN}✓ Launched ${CURRENT_BATCH_COUNT} tabs in Firefox.${RESET}"
    fi

    CURRENT_INDEX=$END_INDEX
    CHUNK_NUM=$(( CHUNK_NUM + 1 ))

    # If all URLs processed, stop
    if [[ $CURRENT_INDEX -ge $TOTAL_URLS ]]; then
        echo -e "\n${BOLD}${GREEN}✔ All ${TOTAL_URLS} URLs have been opened in Firefox!${RESET}\n"
        break
    fi

    # Pacing: delay or prompt
    if is_delay_enabled; then
        echo -e "${YELLOW}Waiting ${DELAY} seconds before next batch... (Ctrl+C to abort)${RESET}\n"
        sleep "$DELAY"
    else
        echo -e ""
        while true; do
            read -r -p "$(echo -e "${BOLD}${CYAN}Press [Enter] for next batch, [s] to skip, [q] to quit:${RESET} ")" choice
            case "$choice" in
                [Qq]*)
                    echo -e "\n${YELLOW}Quitting at batch $((CHUNK_NUM - 1)) of ${TOTAL_CHUNKS}. Remaining URLs skipped.${RESET}"
                    exit 0
                    ;;
                [Ss]*)
                    echo -e "${YELLOW}Skipping batch ${CHUNK_NUM}...${RESET}"
                    # Skip the next batch
                    CURRENT_INDEX=$(( CURRENT_INDEX + CHUNK_SIZE ))
                    CHUNK_NUM=$(( CHUNK_NUM + 1 ))
                    break
                    ;;
                *)
                    echo ""
                    break
                    ;;
            esac
        done
    fi
done
