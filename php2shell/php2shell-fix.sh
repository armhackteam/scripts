#!/usr/bin/env bash
#
# PHP2Shell Mitigation Tool (CVE-2026-109618 & CVE-2026-109619)
# Author: ArmHack-Team (https://github.com/armhackteam)
# Targets: PHP 7.4, 8.1, and legacy unpatched PHP environments.
#
# Safely mitigates RCE vectors related to PHP session upload progress and
# FPM worker memory reuse without breaking production servers.
#
# DISCLAIMER / WARNING:
# 1. Always create a manual backup of your server configurations (/etc/php*,
#    /etc/nginx*, etc.) before running this script in production.
# 2. While this tool handles the vast majority of standard PHP deployments
#    (Debian/Ubuntu, RHEL/AlmaLinux/Rocky/Remi, cPanel), it is impossible to
#    account for every custom or non-standard PHP build and environment.
#    Verify your services after applying changes.
#

set -uo pipefail

COLOR_RED="\033[0;31m"
COLOR_GREEN="\033[0;32m"
COLOR_YELLOW="\033[0;33m"
COLOR_BLUE="\033[0;34m"
COLOR_RESET="\033[0m"

BACKUP_EXT=".bak_php2shell"
NGINX_SNIPPET="/etc/nginx/conf.d/php2shell_protect.conf"
DEFAULT_MAX_REQUESTS=500

# Dedicated temporary workspace in parent shell, guaranteed to be cleaned up on exit or interrupt
TMP_WORK_DIR=""
cleanup_tmp() {
    if [[ -n "${TMP_WORK_DIR:-}" && -d "$TMP_WORK_DIR" ]]; then
        rm -rf "$TMP_WORK_DIR"
    fi
}
trap cleanup_tmp EXIT INT TERM HUP

log_info() { echo -e "${COLOR_BLUE}[*]${COLOR_RESET} $1"; }
log_ok()   { echo -e "${COLOR_GREEN}[+]${COLOR_RESET} $1"; }
log_warn() { echo -e "${COLOR_YELLOW}[!]${COLOR_RESET} $1"; }
log_err()  { echo -e "${COLOR_RED}[-]${COLOR_RESET} $1" >&2; }

print_banner() {
    echo "====================================================="
    echo "  PHP2Shell Mitigation Tool (CVE-2026-109618/19)     "
    echo "  Developed by ArmHack-Team                          "
    echo "====================================================="
}

usage() {
    print_banner
    cat <<EOF

Usage: sudo bash $(basename "$0") [OPTIONS]

Modes:
  --check                 Audit PHP and FPM configurations for vulnerability (default)
  --apply                 Apply safe mitigations (creates idempotent backups automatically)
  --rollback              Restore original configurations from backups
  -h, --help              Show this help message

Options:
  --max-requests <N>      Target pm.max_requests for PHP-FPM pools (default: ${DEFAULT_MAX_REQUESTS}).
                          Note: ${DEFAULT_MAX_REQUESTS} prevents memory leaks with minimal CPU overhead,
                          but to strictly break multi-request exploit chains per request,
                          use: --max-requests 1
  --keep-backups          Do not delete *${BACKUP_EXT} files after --rollback

IMPORTANT WARNINGS:
  * Please create a manual backup of your PHP and web server configurations
    before running --apply on a production system.
  * Although this script covers the vast majority of standard PHP environments,
    it is impossible to foresee every custom PHP setup. Always verify your
    services after applying changes.
EOF
}

MODE="--check"
TARGET_MAX_REQUESTS="$DEFAULT_MAX_REQUESTS"
KEEP_BACKUPS=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --check|--apply|--rollback)
            MODE="$1"
            shift
            ;;
        --max-requests)
            if [[ -z "${2:-}" || ! "${2}" =~ ^[0-9]+$ || "${2}" -lt 1 ]]; then
                log_err "Invalid value for --max-requests. Provide a positive integer."
                exit 1
            fi
            TARGET_MAX_REQUESTS="$2"
            shift 2
            ;;
        --keep-backups)
            KEEP_BACKUPS=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            log_err "Unknown argument: $1"
            usage
            exit 1
            ;;
    esac
done

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
    log_err "This script must be run as root (use sudo)."
    exit 1
fi

TMP_WORK_DIR=$(mktemp -d) || {
    log_err "Failed to create temporary working directory in /tmp."
    exit 1
}

make_temp_file() {
    mktemp "${TMP_WORK_DIR}/tmp.XXXXXX"
}

restore_selinux_context() {
    local file="$1"
    if command -v restorecon &>/dev/null; then
        restorecon -F "$file" 2>/dev/null || true
    fi
}

# Create an idempotent backup of a file (dereferencing symlinks so backup has actual content).
# Returns non-zero if backup creation fails (e.g. disk full) so caller can abort safely.
backup_file() {
    local file="$1"
    if [[ ! -f "${file}${BACKUP_EXT}" ]]; then
        if ! cp -L -p "$file" "${file}${BACKUP_EXT}"; then
            log_err "Failed to create backup ${file}${BACKUP_EXT} (check disk space/permissions). Aborting change."
            return 1
        fi
        restore_selinux_context "${file}${BACKUP_EXT}"
    fi
    return 0
}

# Write content into an existing target file in-place (preserving inode, permissions, ownership, SELinux context, and symlinks)
write_file_preserving_target() {
    local src="$1"
    local dst="$2"
    if [[ ! -s "$src" ]]; then
        log_err "Refusing to overwrite $dst with empty content."
        return 1
    fi
    if ! cat "$src" > "$dst"; then
        log_err "Failed to write updated configuration to $dst."
        return 1
    fi
    restore_selinux_context "$dst"
    return 0
}

# Return the list of configured search roots (supports custom PHP2SHELL_SEARCH_ROOTS override)
get_configured_candidates() {
    echo ${PHP2SHELL_SEARCH_ROOTS:-/etc/php /etc/php.ini /etc/php.d /etc/php-fpm.d /etc/opt/remi /opt/cpanel /var/cpanel}
}

# Discover existing root paths for PHP configurations across Debian/Ubuntu, RHEL/Remi, and cPanel
get_search_roots() {
    local roots=()
    local candidate
    for candidate in $(get_configured_candidates); do
        if [[ -e "$candidate" ]]; then
            roots+=("$candidate")
        fi
    done
    echo "${roots[@]}"
}

# Find all backup files created by this tool (supports both directory roots and arbitrary single-file roots)
find_backup_files() {
    local candidate
    for candidate in $(get_configured_candidates); do
        if [[ -f "${candidate}${BACKUP_EXT}" ]]; then
            echo "${candidate}${BACKUP_EXT}"
        fi
        if [[ -d "$candidate" ]]; then
            find -H "$candidate" -type f -name "*${BACKUP_EXT}" 2>/dev/null
        elif [[ -f "$candidate" ]]; then
            local parent_dir
            parent_dir=$(dirname "$candidate")
            local base_name
            base_name=$(basename "$candidate")
            find -H "$parent_dir" -maxdepth 1 -type f -name "${base_name}${BACKUP_EXT}" 2>/dev/null
        fi
    done | sort -u
}

# Deduplicate files by canonical path, preferring regular files over symlinks when both are in search roots
dedup_realpaths() {
    local all_paths=()
    local path real
    while IFS= read -r path; do
        [[ -z "$path" || ! -f "$path" ]] && continue
        all_paths+=("$path")
    done

    local seen=" "
    # Pass 1: regular files (not symlinks)
    for path in "${all_paths[@]:-}"; do
        [[ -z "$path" || -L "$path" ]] && continue
        real=$(readlink -f "$path" 2>/dev/null || echo "$path")
        if [[ "$seen" != *"|${real}|"* ]]; then
            seen="${seen}|${real}|"
            echo "$path"
        fi
    done
    # Pass 2: symlinks whose target was not already visited in Pass 1
    for path in "${all_paths[@]:-}"; do
        [[ -z "$path" || ! -L "$path" ]] && continue
        real=$(readlink -f "$path" 2>/dev/null || echo "$path")
        if [[ "$seen" != *"|${real}|"* ]]; then
            seen="${seen}|${real}|"
            echo "$path"
        fi
    done
}

# Find primary php.ini files (including valid symlinks)
find_php_ini_files() {
    local roots
    read -r -a roots <<< "$(get_search_roots)"
    [[ ${#roots[@]} -eq 0 ]] && return 0
    find -H "${roots[@]}" \( -type f -o -type l \) -name "php.ini" 2>/dev/null | sort -u | dedup_realpaths
}

# Find drop-in .ini files (e.g. conf.d/*.ini, php.d/*.ini) that explicitly configure session.upload_progress.enabled
find_override_ini_files() {
    local roots
    read -r -a roots <<< "$(get_search_roots)"
    [[ ${#roots[@]} -eq 0 ]] && return 0
    find -H "${roots[@]}" \( -type f -o -type l \) -name "*.ini" ! -name "php.ini" -print0 2>/dev/null \
        | xargs -0 -r grep -ilE "^[[:space:]]*session\.upload_progress\.enabled[[:space:]]*=" 2>/dev/null \
        | sort -u | dedup_realpaths || true
}

# Find PHP-FPM pool configuration files (including valid symlinks)
find_fpm_pool_files() {
    local roots
    read -r -a roots <<< "$(get_search_roots)"
    [[ ${#roots[@]} -eq 0 ]] && return 0
    find -H "${roots[@]}" \( -type f -o -type l \) -name "*.conf" 2>/dev/null \
        | grep -E "(fpm/pool\.d|php-fpm\.d)" \
        | sort -u | dedup_realpaths || true
}

# Normalize an INI value (strips CRLF, inline comments, whitespace, surrounding single/double quotes)
clean_ini_rhs() {
    tr -d '\r' | sed -E '
        s/^[^=]*=[[:space:]]*//
        s/[;#].*$//
        s/[[:space:]]+$//
        s/^"(.*)"$/\1/
        s/^'\''(.*)'\''$/\1/
        s/^[[:space:]]+//
        s/[[:space:]]+$//
    '
}

# Extract all active values of an INI directive in a file (one per line)
get_all_ini_values() {
    local file="$1"
    local key="$2"
    grep -iE "^[[:space:]]*${key}[[:space:]]*=" "$file" 2>/dev/null \
        | clean_ini_rhs || true
}

is_disabled_value() {
    local val="${1,,}" # lowercase
    [[ "$val" == "off" || "$val" == "0" || "$val" == "false" || "$val" == "no" || "$val" == "none" ]]
}

# Audit session.upload_progress.enabled in a php.ini file (accounting for [HOST=...] and [PATH=...] sections)
# Prints:
#   "ok:<val>"       - disabled globally and not re-enabled in any [HOST=]/[PATH=] section
#   "default_on"     - omitted in global scope (defaults to On)
#   "enabled:<val>"  - explicitly enabled in global or [HOST=]/[PATH=] scope
check_ini_upload_progress() {
    local ini="$1"
    awk '
        function trim(s) {
            sub(/^[ \t\r]+/, "", s)
            sub(/[ \t\r]+$/, "", s)
            return s
        }
        function is_off(v,    lv) {
            lv = tolower(v)
            return (lv == "off" || lv == "0" || lv == "false" || lv == "no" || lv == "none")
        }
        BEGIN {
            in_host_path = 0
            global_val = ""
            bad_override = ""
        }
        {
            sub(/\r$/, "", $0)
            low = tolower($0)
            if (low ~ /^[ \t]*\[(host|path)[ \t]*=/) {
                in_host_path = 1
                next
            }
            if (low ~ /^[ \t]*session\.upload_progress\.enabled[ \t]*=/) {
                val = $0
                sub(/^[^=]*=/, "", val)
                sub(/[;#].*$/, "", val)
                val = trim(val)
                gsub(/^["'\'']|["'\'']$/, "", val)
                val = trim(val)
                if (!in_host_path) {
                    global_val = val
                } else if (!is_off(val) && bad_override == "") {
                    bad_override = val
                }
            }
        }
        END {
            if (global_val == "") {
                print "default_on"
            } else if (!is_off(global_val)) {
                print "enabled:" global_val
            } else if (bad_override != "") {
                print "enabled:" bad_override
            } else {
                print "ok:" global_val
            }
        }
    ' "$ini"
}

# Audit pm.max_requests across every [pool] section in a PHP-FPM .conf file
# Prints:
#   "no_pools"      - file contains no [pool] sections (e.g. comments-only or [global]-only)
#   "ok:<max_val>"  - all [pool] sections have 0 < pm.max_requests <= TARGET_MAX_REQUESTS
#   "unset"         - at least one [pool] section has pm.max_requests unset or 0
#   "exceeds:<val>" - at least one [pool] section has pm.max_requests > TARGET_MAX_REQUESTS
check_pool_max_requests() {
    local pool="$1"
    awk -v target="$TARGET_MAX_REQUESTS" '
        function trim(s) {
            sub(/^[ \t\r]+/, "", s)
            sub(/[ \t\r]+$/, "", s)
            return s
        }
        BEGIN {
            in_pool = 0
            pool_count = 0
            has_unset = 0
            exceeds_val = ""
            max_ok = 0
        }
        /^[ \t]*\[[^]]+\]/ {
            if (in_pool) {
                if (cur_val == "" || cur_val !~ /^[0-9]+$/ || cur_val + 0 == 0) {
                    has_unset = 1
                } else if (cur_val + 0 > target + 0 && exceeds_val == "") {
                    exceeds_val = cur_val
                } else if (cur_val + 0 > max_ok) {
                    max_ok = cur_val + 0
                }
            }
            line = $0
            sub(/^[ \t]*\[/, "", line)
            sub(/\].*$/, "", line)
            sec = tolower(trim(line))
            if (sec != "global") {
                in_pool = 1
                pool_count++
                cur_val = ""
            } else {
                in_pool = 0
            }
            next
        }
        {
            line = $0
            sub(/\r$/, "", line)
            if (in_pool && tolower(line) ~ /^[ \t]*pm\.max_requests[ \t]*=/) {
                sub(/^[^=]*=/, "", line)
                sub(/[;#].*$/, "", line)
                line = trim(line)
                gsub(/^["'\'']|["'\'']$/, "", line)
                cur_val = trim(line)
            }
        }
        END {
            if (in_pool) {
                if (cur_val == "" || cur_val !~ /^[0-9]+$/ || cur_val + 0 == 0) {
                    has_unset = 1
                } else if (cur_val + 0 > target + 0 && exceeds_val == "") {
                    exceeds_val = cur_val
                } else if (cur_val + 0 > max_ok) {
                    max_ok = cur_val + 0
                }
            }
            if (pool_count == 0) {
                print "no_pools"
            } else if (has_unset) {
                print "unset"
            } else if (exceeds_val != "") {
                print "exceeds:" exceeds_val
            } else {
                print "ok:" max_ok
            }
        }
    ' "$pool"
}

# Patch pm.max_requests across all [pool] sections in a PHP-FPM .conf file.
# Never modifies lines before the first [section] or inside [global].
patch_pool_max_requests() {
    local pool="$1"
    local tmp_out
    tmp_out=$(make_temp_file) || return 1

    if ! awk -v target="$TARGET_MAX_REQUESTS" '
        function trim(s) {
            sub(/^[ \t\r]+/, "", s)
            sub(/[ \t\r]+$/, "", s)
            return s
        }
        function flush_section(    i, line, val, patched_active, patched_comment) {
            if (sec_len == 0) return
            if (!is_pool) {
                for (i = 1; i <= sec_len; i++) print sec_lines[i]
                sec_len = 0
                return
            }
            patched_active = 0
            for (i = 1; i <= sec_len; i++) {
                line = sec_lines[i]
                if (tolower(line) ~ /^[ \t]*pm\.max_requests[ \t]*=/) {
                    val = line
                    sub(/^[^=]*=/, "", val)
                    sub(/[;#].*$/, "", val)
                    val = trim(val)
                    gsub(/^["'\'']|["'\'']$/, "", val)
                    val = trim(val)
                    if (val == "" || val !~ /^[0-9]+$/ || val + 0 == 0 || val + 0 > target + 0) {
                        sec_lines[i] = "pm.max_requests = " target
                    }
                    patched_active = 1
                }
            }
            if (!patched_active) {
                patched_comment = 0
                for (i = 1; i <= sec_len; i++) {
                    line = sec_lines[i]
                    if (!patched_comment && tolower(line) ~ /^[ \t]*;[ \t]*pm\.max_requests[ \t]*=/) {
                        sec_lines[i] = "pm.max_requests = " target
                        patched_comment = 1
                    }
                }
                if (!patched_comment) {
                    sec_lines[++sec_len] = "; PHP2Shell mitigation"
                    sec_lines[++sec_len] = "pm.max_requests = " target
                }
            }
            for (i = 1; i <= sec_len; i++) print sec_lines[i]
            sec_len = 0
        }
        BEGIN {
            sec_len = 0
            is_pool = 0
        }
        {
            sub(/\r$/, "", $0)
        }
        /^[ \t]*\[[^]]+\]/ {
            flush_section()
            hdr = $0
            sub(/^[ \t]*\[/, "", hdr)
            sub(/\].*$/, "", hdr)
            if (tolower(trim(hdr)) != "global") {
                is_pool = 1
            } else {
                is_pool = 0
            }
            sec_lines[++sec_len] = $0
            next
        }
        {
            sec_lines[++sec_len] = $0
        }
        END {
            flush_section()
        }
    ' "$pool" > "$tmp_out"; then
        rm -f "$tmp_out"
        return 1
    fi

    write_file_preserving_target "$tmp_out" "$pool"
    local rc=$?
    rm -f "$tmp_out"
    return $rc
}

# Safely disable pool-level php_admin_value/php_flag overrides for session.upload_progress.enabled
patch_pool_upload_progress_override() {
    local pool="$1"
    local tmp_out
    tmp_out=$(make_temp_file) || return 1

    if ! awk '
        {
            sub(/\r$/, "", $0)
            line = $0
            if (tolower(line) ~ /^[ \t]*php(_admin)?_(value|flag)\[session\.upload_progress\.enabled\][ \t]*=/) {
                sub(/=.*/, "= 0", $0)
            }
            print $0
        }
    ' "$pool" > "$tmp_out"; then
        rm -f "$tmp_out"
        return 1
    fi

    write_file_preserving_target "$tmp_out" "$pool"
    local rc=$?
    rm -f "$tmp_out"
    return $rc
}

# Validate PHP-FPM configuration for a systemd service unit before reloading it
test_fpm_service_config() {
    local svc="$1"
    local exec_start fpm_bin
    exec_start=$(systemctl show -p ExecStart --value "$svc" 2>/dev/null || true)
    fpm_bin=$(echo "$exec_start" | sed -nE 's/.*path=([^ ;]+).*/\1/p' | head -n 1)
    if [[ -n "$fpm_bin" && -x "$fpm_bin" ]]; then
        if ! "$fpm_bin" -t &>/dev/null; then
            log_err "Configuration test failed: $fpm_bin -t (service: $svc)"
            return 1
        fi
    fi
    return 0
}

# Reload active PHP-FPM and web server services gracefully.
# Returns non-zero if any active PHP-FPM service failed config validation or reload.
reload_active_services() {
    if ! command -v systemctl &>/dev/null; then
        log_warn "systemctl not found. Please reload your PHP-FPM or web server manually."
        return 0
    fi

    local reload_failed=0
    local running_units
    running_units=$(systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print $1}' || true)

    local fpm_services
    fpm_services=$(echo "$running_units" | grep -E "php.*fpm" || true)

    if [[ -n "$fpm_services" ]]; then
        local svc
        # Phase 1: Validate all running PHP-FPM services with 'php-fpm -t' before touching any running daemon
        while IFS= read -r svc; do
            [[ -z "$svc" ]] && continue
            if ! test_fpm_service_config "$svc"; then
                reload_failed=1
            fi
        done <<< "$fpm_services"

        if [[ $reload_failed -ne 0 ]]; then
            return 1
        fi

        # Phase 2: Gracefully reload (preferring zero-downtime reload over restart)
        while IFS= read -r svc; do
            [[ -z "$svc" ]] && continue
            if systemctl reload "$svc" 2>/dev/null || systemctl reload-or-restart "$svc" 2>/dev/null; then
                log_ok "Reloaded active PHP-FPM service: $svc"
            else
                log_err "Failed to reload service: $svc"
                reload_failed=1
            fi
        done <<< "$fpm_services"
    else
        log_info "No running PHP-FPM systemd services detected."
    fi

    # Gracefully reload Apache if running (in case mod_php is used)
    local web_services
    web_services=$(echo "$running_units" | grep -E "^(apache2|httpd)\.service$" || true)
    if [[ -n "$web_services" ]]; then
        local wsvc
        while IFS= read -r wsvc; do
            [[ -z "$wsvc" ]] && continue
            if systemctl reload "$wsvc" 2>/dev/null; then
                log_ok "Gracefully reloaded web server: $wsvc"
            fi
        done <<< "$web_services"
    fi

    return $reload_failed
}

# -----------------------------------------------------------------------------
# 1. CHECK MODE (--check)
# -----------------------------------------------------------------------------
run_check() {
    print_banner

    local found_any=0
    local vulnerable=0
    local found_pools=0

    # 1. Check main php.ini files
    while IFS= read -r ini; do
        [[ -z "$ini" ]] && continue
        found_any=1

        local ini_status
        ini_status=$(check_ini_upload_progress "$ini")

        case "$ini_status" in
            ok:*)
                local ok_ini_val="${ini_status#ok:}"
                log_ok "$ini: session.upload_progress.enabled = $ok_ini_val (Protected)"
                ;;
            enabled:*)
                local en_ini_val="${ini_status#enabled:}"
                log_warn "$ini: session.upload_progress.enabled = $en_ini_val (VULNERABLE)"
                vulnerable=1
                ;;
            *)
                log_warn "$ini: session.upload_progress.enabled = On (default) (VULNERABLE)"
                vulnerable=1
                ;;
        esac
    done < <(find_php_ini_files)

    # 2. Check drop-in .ini files (conf.d / php.d) for overrides
    while IFS= read -r dropin; do
        [[ -z "$dropin" ]] && continue
        found_any=1

        local dropin_vals
        dropin_vals=$(get_all_ini_values "$dropin" "session\.upload_progress\.enabled")
        local dropin_bad=""
        local dval last_dval="Off"
        while IFS= read -r dval; do
            [[ -z "$dval" ]] && continue
            last_dval="$dval"
            if ! is_disabled_value "$dval"; then
                dropin_bad="$dval"
                break
            fi
        done <<< "$dropin_vals"

        if [[ -n "$dropin_bad" ]]; then
            log_warn "$dropin: overrides session.upload_progress.enabled = $dropin_bad (VULNERABLE)"
            vulnerable=1
        else
            log_ok "$dropin: session.upload_progress.enabled = $last_dval (Protected)"
        fi
    done < <(find_override_ini_files)

    # 3. Check PHP-FPM pool files
    while IFS= read -r pool; do
        [[ -z "$pool" ]] && continue

        local pool_status
        pool_status=$(check_pool_max_requests "$pool")

        # Skip .conf files that do not define any [pool] section
        [[ "$pool_status" == "no_pools" ]] && continue
        found_any=1
        found_pools=1

        case "$pool_status" in
            ok:*)
                local ok_val="${pool_status#ok:}"
                log_ok "$pool: pm.max_requests = $ok_val (<= ${TARGET_MAX_REQUESTS}, Protected)"
                ;;
            exceeds:*)
                local ex_val="${pool_status#exceeds:}"
                log_warn "$pool: pm.max_requests = $ex_val (Exceeds target ${TARGET_MAX_REQUESTS})"
                vulnerable=1
                ;;
            *)
                log_warn "$pool: pm.max_requests = 0 / unlimited (Workers do not recycle)"
                vulnerable=1
                ;;
        esac

        # Also check if the pool file forces session.upload_progress.enabled via php_admin_value/php_value
        local pool_overrides
        pool_overrides=$(get_all_ini_values "$pool" "php(_admin)?_(value|flag)\[session\.upload_progress\.enabled\]")
        if [[ -n "$pool_overrides" ]]; then
            local ov
            while IFS= read -r ov; do
                [[ -z "$ov" ]] && continue
                if ! is_disabled_value "$ov"; then
                    log_warn "$pool: overrides session.upload_progress.enabled = $ov (VULNERABLE)"
                    vulnerable=1
                    break
                fi
            done <<< "$pool_overrides"
        fi
    done < <(find_fpm_pool_files)

    if [[ $found_pools -eq 1 && "$TARGET_MAX_REQUESTS" -gt 1 ]]; then
        log_info "Note: pm.max_requests=${TARGET_MAX_REQUESTS} prevents persistent memory leaks with minimal CPU overhead."
        log_info "      For strict per-request worker isolation against multi-request exploit chains, use: --max-requests 1"
    fi

    echo "-----------------------------------------------------"
    if [[ $found_any -eq 0 ]]; then
        log_warn "No PHP or PHP-FPM configuration files found in standard paths."
    elif [[ $vulnerable -eq 1 ]]; then
        log_err "Vulnerable settings detected. Run: sudo bash $(basename "$0") --apply"
        return 1
    else
        log_ok "All detected PHP configurations are protected against PHP2Shell."
    fi
}

# -----------------------------------------------------------------------------
# 2. APPLY MODE (--apply)
# -----------------------------------------------------------------------------
patch_ini_upload_progress() {
    local ini="$1"
    backup_file "$ini" || return 1

    local tmp_out
    tmp_out=$(make_temp_file) || return 1

    if ! awk '
        BEGIN {
            n = 0
            has_global_active = 0
            has_global_commented = 0
            has_global_session_sec = 0
            first_host_path_idx = 0
        }
        {
            sub(/\r$/, "", $0)
            lines[++n] = $0
            low = tolower($0)
            if (low ~ /^[ \t]*\[(host|path)[ \t]*=/) {
                if (!first_host_path_idx) first_host_path_idx = n
            }
            if (!first_host_path_idx) {
                if (low ~ /^[ \t]*session\.upload_progress\.enabled[ \t]*=/) {
                    has_global_active = 1
                } else if (low ~ /^[ \t]*;[ \t]*session\.upload_progress\.enabled[ \t]*=/) {
                    if (!has_global_commented) has_global_commented = n
                } else if (low ~ /^[ \t]*\[session\]/) {
                    if (!has_global_session_sec) has_global_session_sec = n
                }
            }
        }
        END {
            for (i = 1; i <= n; i++) {
                low = tolower(lines[i])
                # 1. Always neutralize any active directive (both global and inside [HOST=]/[PATH=])
                if (low ~ /^[ \t]*session\.upload_progress\.enabled[ \t]*=/) {
                    print "session.upload_progress.enabled = Off"
                    continue
                }
                # 2. If no global active directive existed, uncomment the first global commented one
                if (!has_global_active && has_global_commented && i == has_global_commented) {
                    print "session.upload_progress.enabled = Off"
                    continue
                }
                # 3. If neither active nor commented existed globally, and no [Session] section existed,
                #    insert before the first [HOST=]/[PATH=] section if present
                if (!has_global_active && !has_global_commented && !has_global_session_sec && first_host_path_idx && i == first_host_path_idx) {
                    print "[Session]"
                    print "; PHP2Shell mitigation"
                    print "session.upload_progress.enabled = Off"
                    print ""
                }
                print lines[i]
                # 4. If inserting under existing global [Session] section
                if (!has_global_active && !has_global_commented && has_global_session_sec && i == has_global_session_sec) {
                    print "session.upload_progress.enabled = Off"
                }
            }
            # 5. If no global directive, no [Session], and no [HOST=]/[PATH=] section existed, append at EOF
            if (!has_global_active && !has_global_commented && !has_global_session_sec && !first_host_path_idx) {
                print ""
                print "[Session]"
                print "; PHP2Shell mitigation"
                print "session.upload_progress.enabled = Off"
            }
        }
    ' "$ini" > "$tmp_out"; then
        rm -f "$tmp_out"
        return 1
    fi

    write_file_preserving_target "$tmp_out" "$ini"
    local rc=$?
    rm -f "$tmp_out"
    return $rc
}

run_apply() {
    print_banner
    log_warn "Reminder: Always keep an external backup of your configurations before applying changes."
    log_info "Applying PHP2Shell mitigations..."

    local patched_count=0
    local found_pools=0

    # 1. Disable session.upload_progress.enabled in main php.ini files
    while IFS= read -r ini; do
        [[ -z "$ini" ]] && continue
        local ini_status
        ini_status=$(check_ini_upload_progress "$ini")
        if [[ "$ini_status" == ok:* ]]; then
            local ok_ini_val="${ini_status#ok:}"
            log_ok "$ini already has session.upload_progress.enabled = $ok_ini_val"
        else
            if patch_ini_upload_progress "$ini"; then
                log_ok "Patched $ini (Backup: ${ini}${BACKUP_EXT})"
                patched_count=$((patched_count + 1))
            fi
        fi
    done < <(find_php_ini_files)

    # 2. Disable session.upload_progress.enabled in any overriding drop-in .ini files
    while IFS= read -r dropin; do
        [[ -z "$dropin" ]] && continue
        local dropin_vals
        dropin_vals=$(get_all_ini_values "$dropin" "session\.upload_progress\.enabled")
        local needs_dropin_patch=0
        local dval
        while IFS= read -r dval; do
            [[ -z "$dval" ]] && continue
            if ! is_disabled_value "$dval"; then
                needs_dropin_patch=1
                break
            fi
        done <<< "$dropin_vals"

        if [[ $needs_dropin_patch -eq 1 ]]; then
            if patch_ini_upload_progress "$dropin"; then
                log_ok "Patched override INI $dropin (Backup: ${dropin}${BACKUP_EXT})"
                patched_count=$((patched_count + 1))
            fi
        fi
    done < <(find_override_ini_files)

    # 3. Ensure PHP-FPM workers recycle periodically (pm.max_requests)
    while IFS= read -r pool; do
        [[ -z "$pool" ]] && continue

        local pool_modified=0
        local pool_status
        pool_status=$(check_pool_max_requests "$pool")

        # Do not touch .conf files that contain no [pool] definitions
        [[ "$pool_status" == "no_pools" ]] && continue
        found_pools=1

        if [[ "$pool_status" != ok:* ]]; then
            if backup_file "$pool" && patch_pool_max_requests "$pool"; then
                log_ok "Configured pm.max_requests = ${TARGET_MAX_REQUESTS} in $pool"
                pool_modified=1
            fi
        else
            local ok_val="${pool_status#ok:}"
            log_ok "$pool already has pm.max_requests = $ok_val (<= ${TARGET_MAX_REQUESTS})"
        fi

        # Neutralize any pool-level php_admin_value/php_value enabling session.upload_progress.enabled
        if grep -qiE "^[[:space:]]*php(_admin)?_(value|flag)\[session\.upload_progress\.enabled\][[:space:]]*=" "$pool"; then
            local pool_overrides
            pool_overrides=$(get_all_ini_values "$pool" "php(_admin)?_(value|flag)\[session\.upload_progress\.enabled\]")
            local needs_pool_override_fix=0
            local ov
            while IFS= read -r ov; do
                [[ -z "$ov" ]] && continue
                if ! is_disabled_value "$ov"; then
                    needs_pool_override_fix=1
                    break
                fi
            done <<< "$pool_overrides"

            if [[ $needs_pool_override_fix -eq 1 ]]; then
                if backup_file "$pool" && patch_pool_upload_progress_override "$pool"; then
                    log_ok "Disabled pool-level session.upload_progress.enabled override in $pool"
                    pool_modified=1
                fi
            fi
        fi

        if [[ $pool_modified -eq 1 ]]; then
            patched_count=$((patched_count + 1))
        fi
    done < <(find_fpm_pool_files)

    if [[ $found_pools -eq 1 && "$TARGET_MAX_REQUESTS" -gt 1 ]]; then
        log_info "Note: pm.max_requests=${TARGET_MAX_REQUESTS} recycles workers periodically with minimal CPU overhead."
        log_info "      For strict per-request worker isolation against multi-request exploit chains, run with: --max-requests 1"
    fi

    # 4. Create Nginx protection snippet and validate with nginx -t
    if [[ -d "/etc/nginx/conf.d" ]] && command -v nginx &>/dev/null; then
        local desired_nginx_snippet
        desired_nginx_snippet=$(cat << 'EOF'
# PHP2Shell Mitigation Snippet (CVE-2026-109618 / CVE-2026-109619)
# Blocks anomalous double chunked Transfer-Encoding headers.
map $http_transfer_encoding $p2s_blocked_te {
    default 0;
    "~*chunked.*chunked" 1;
}

# Optional: inside your server {} blocks, add:
# if ($p2s_blocked_te) { return 400; }
EOF
)
        if [[ -f "$NGINX_SNIPPET" ]] && [[ "$(cat "$NGINX_SNIPPET" 2>/dev/null)" == "$desired_nginx_snippet" ]]; then
            log_ok "Nginx snippet already up to date: $NGINX_SNIPPET"
        elif ! nginx -t &>/dev/null; then
            log_warn "Skipping Nginx snippet because existing Nginx configuration already fails 'nginx -t'."
        else
            printf "%s\n" "$desired_nginx_snippet" > "$NGINX_SNIPPET"
            chmod 0644 "$NGINX_SNIPPET"
            restore_selinux_context "$NGINX_SNIPPET"
            if nginx -t &>/dev/null; then
                log_ok "Created and verified Nginx snippet: $NGINX_SNIPPET"
                if command -v systemctl &>/dev/null && systemctl is-active --quiet nginx 2>/dev/null; then
                    systemctl reload nginx 2>/dev/null && log_ok "Reloaded active Nginx service" || true
                fi
            else
                rm -f "$NGINX_SNIPPET"
                log_warn "Removed $NGINX_SNIPPET because 'nginx -t' reported a configuration conflict."
            fi
        fi
    fi

    # 5. Reload/restart active PHP-FPM and web services if changes were made
    if [[ $patched_count -gt 0 ]]; then
        log_info "Reloading active services..."
        if reload_active_services; then
            log_ok "Mitigation successfully applied ($patched_count file(s) updated)!"
        else
            log_err "A PHP-FPM service failed to reload! Performing emergency rollback while preserving *${BACKUP_EXT} files..."
            run_rollback "keep"
            return 1
        fi
    else
        log_info "No configuration changes were needed (or no PHP config files found)."
    fi
}

# -----------------------------------------------------------------------------
# 3. ROLLBACK MODE (--rollback)
# -----------------------------------------------------------------------------
run_rollback() {
    local emergency_mode="${1:-}"
    local preserve_backups="$KEEP_BACKUPS"
    if [[ "$emergency_mode" == "keep" ]]; then
        preserve_backups=1
    else
        print_banner
    fi

    log_info "Searching for backups (*${BACKUP_EXT}) to restore..."
    local restored=0

    while IFS= read -r bak; do
        [[ -z "$bak" ]] && continue
        local orig="${bak%"${BACKUP_EXT}"}"
        # Write through existing file/symlink first to preserve symlink chains and inodes; fall back to cp -p
        cat "$bak" > "$orig" 2>/dev/null || cp -p "$bak" "$orig"
        restore_selinux_context "$orig"
        if [[ "$preserve_backups" -eq 0 ]]; then
            rm -f "$bak"
            log_ok "Restored: $orig"
        else
            log_ok "Restored: $orig (Backup preserved: $bak)"
        fi
        restored=$((restored + 1))
    done < <(find_backup_files)

    if [[ -f "$NGINX_SNIPPET" ]]; then
        local tmp_nginx_bak
        tmp_nginx_bak=$(make_temp_file)
        cp -p "$NGINX_SNIPPET" "$tmp_nginx_bak"
        rm -f "$NGINX_SNIPPET"
        if command -v nginx &>/dev/null && ! nginx -t &>/dev/null; then
            cp -p "$tmp_nginx_bak" "$NGINX_SNIPPET"
            chmod 0644 "$NGINX_SNIPPET"
            restore_selinux_context "$NGINX_SNIPPET"
            rm -f "$tmp_nginx_bak"
            log_warn "Kept $NGINX_SNIPPET because a server{} block still references \$p2s_blocked_te."
        else
            rm -f "$tmp_nginx_bak"
            log_ok "Removed Nginx snippet: $NGINX_SNIPPET"
            if command -v systemctl &>/dev/null && systemctl is-active --quiet nginx 2>/dev/null; then
                systemctl reload nginx 2>/dev/null || true
            fi
        fi
    fi

    if [[ $restored -gt 0 ]]; then
        log_info "Reloading active services after rollback..."
        reload_active_services || true
        log_ok "Rollback complete. Restored $restored file(s)."
    else
        log_warn "No backup files (*${BACKUP_EXT}) found."
    fi
}

case "$MODE" in
    --check)
        run_check
        ;;
    --apply)
        run_apply
        ;;
    --rollback)
        run_rollback
        ;;
esac
