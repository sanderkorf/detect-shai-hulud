#!/usr/bin/env bash
set -euo pipefail
# IoC Detection Script for malicious NPM package attack (Linux/macOS)
# Scans repositories and common locations for the supplied indicators.
# Usage:
#   ./detect_iocs.sh
#   SCAN_PATH=/path/to/scan ./detect_iocs.sh
OS="$(uname -s)"
case "$OS" in
  Linux*) MACHINE=Linux ;;
  Darwin*) MACHINE=Mac ;;
  *) MACHINE="UNKNOWN:$OS" ;;
esac
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'
log() { printf "%b[%s]%b %s\n" "$BLUE" "$(date '+%Y-%m-%d %H:%M:%S')" "$NC" "$*"; }
warning() { printf "%b[WARNING]%b %s\n" "$YELLOW" "$NC" "$*"; }
critical() { printf "%b[CRITICAL]%b %s\n" "$RED" "$NC" "$*"; }
success() { printf "%b[OK]%b %s\n" "$GREEN" "$NC" "$*"; }
total_checks=0
findings=0
scan_path="${SCAN_PATH:-$(pwd)}"
echo "=========================================="
echo "IoC Detection Script"
echo "Scanning for malicious NPM package indicators"
echo "Scan path: ${scan_path}"
echo "=========================================="
echo
check_file() {
  local file_path="$1"
  local description="$2"
  total_checks=$((total_checks + 1))
  if [[ -f "$file_path" ]]; then
    critical "FOUND: $file_path - $description"
    findings=$((findings + 1))
    ls -la "$file_path" 2>/dev/null || true
    echo
    if [[ "$file_path" == *.js ]]; then
      echo "File contents preview:"
      head -20 "$file_path" 2>/dev/null | sed 's/^/  /' || true
      echo
    fi
  else
    success "NOT FOUND: $file_path"
  fi
}
check_directory() {
  local dir_path="$1"
  local description="$2"
  total_checks=$((total_checks + 1))
  if [[ -d "$dir_path" ]]; then
    critical "FOUND: $dir_path - $description"
    findings=$((findings + 1))
    echo "Directory contents:"
    ls -la "$dir_path" 2>/dev/null | sed 's/^/  /' || true
    echo
  else
    success "NOT FOUND: $dir_path"
  fi
}
check_processes() {
  local pattern="$1"
  local description="$2"
  total_checks=$((total_checks + 1))
  log "Checking for processes: $description"
  local process_found=false
  if command -v pgrep >/dev/null 2>&1; then
    if pgrep -fa "$pattern" >/dev/null 2>&1; then
      process_found=true
      echo "Process details:"
      pgrep -fa "$pattern" | sed 's/^/  /' || true
    fi
  else
    if ps aux | grep -v grep | grep -q "$pattern" 2>/dev/null; then
      process_found=true
      echo "Process details:"
      ps aux | grep -v grep | grep "$pattern" | sed 's/^/  /' || true
    fi
  fi
  if [[ "$process_found" == true ]]; then
    critical "FOUND RUNNING PROCESS: $description"
    findings=$((findings + 1))
    echo
  else
    success "NO SUSPICIOUS PROCESSES: $description"
  fi
}
check_command_history() {
  local pattern="$1"
  local description="$2"
  total_checks=$((total_checks + 1))
  log "Checking command history: $description"
  local found_in_history=false
  local history_sources=("$HOME/.bash_history" "$HOME/.zsh_history" "$HOME/.history")
  for dir in "$HOME/.zsh_sessions" "$HOME/.bash_sessions"; do
    if [[ -d "$dir" ]]; then
      while IFS= read -r session_file; do
        [[ -f "$session_file" ]] && history_sources+=("$session_file")
      done < <(find "$dir" -type f -name "history" -o -name "*.history" 2>/dev/null)
    fi
  done
  for history_file in "${history_sources[@]+"${history_sources[@]}"}"; do
    if [[ -f "$history_file" ]] && grep -qE "$pattern" "$history_file" 2>/dev/null; then
      critical "FOUND IN HISTORY ($history_file): $description"
      findings=$((findings + 1))
      found_in_history=true
      echo "Matching commands:"
      grep -E "$pattern" "$history_file" | tail -5 | sed 's/^/  /' || true
      echo
    fi
  done
  if [[ "$found_in_history" == false ]]; then
    success "NOT FOUND IN HISTORY: $description"
  fi
}
scan_node_modules() {
  log "Recursively scanning all repositories for malicious files..."
  local found_files=()
  local scanned_repos=()
  local total_node_modules=0
  log "Scanning from: $scan_path"
  log "Discovering repositories..."
  local repo_dirs=()
  while IFS= read -r repo_dir; do
    [[ -z "$repo_dir" ]] && continue
    [[ ! -d "$repo_dir" ]] && continue
    repo_dirs+=("$repo_dir")
  done < <(
    find "$scan_path" -maxdepth 4 \( -name ".git" -o -name "package.json" -o -name "pnpm-workspace.yaml" -o -name "lerna.json" \) -type f 2>/dev/null |
      while read -r file; do dirname "$file"; done | sort -u
  )
  for repo_dir in "${repo_dirs[@]+"${repo_dirs[@]}"}"; do
    [[ -z "$repo_dir" ]] && continue
    [[ ! -d "$repo_dir" ]] && continue
    scanned_repos+=("$repo_dir")
    log "Scanning repository: $(basename "$repo_dir")"
    local repo_node_modules_count
    repo_node_modules_count=$(find "$repo_dir" -name "node_modules" -type d 2>/dev/null | wc -l | tr -d ' ')
    repo_node_modules_count=${repo_node_modules_count:-0}
    total_node_modules=$((total_node_modules + repo_node_modules_count))
    if [[ "$repo_node_modules_count" -gt 0 ]]; then
      echo "  Found ${repo_node_modules_count} node_modules directories"
      while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        found_files+=("$file")
      done < <(find "$repo_dir" -path "*/node_modules/*" -name "bun_environment.js" -type f 2>/dev/null)
    else
      echo "  No node_modules directories found"
    fi
  done
  if [[ ${#scanned_repos[@]} -eq 0 ]]; then
    warning "No repositories detected, scanning all node_modules directories..."
    while IFS= read -r node_modules_dir; do
      [[ -z "$node_modules_dir" ]] && continue
      total_node_modules=$((total_node_modules + 1))
      if [[ -f "$node_modules_dir/bun_environment.js" ]]; then
        found_files+=("$node_modules_dir/bun_environment.js")
      fi
      while IFS= read -r file; do
        [[ -z "$file" ]] && continue
        found_files+=("$file")
      done < <(find "$node_modules_dir" -name "bun_environment.js" -type f 2>/dev/null)
    done < <(find "$scan_path" -name "node_modules" -type d 2>/dev/null)
  fi
  log "Scan summary:"
  echo "  - Repositories scanned: ${#scanned_repos[@]}"
  echo "  - Total node_modules directories: $total_node_modules"
  if [[ ${#found_files[@]} -gt 0 ]]; then
    critical "FOUND ${#found_files[@]} malicious bun_environment.js files:"
    findings=$((findings + ${#found_files[@]}))
    for file in "${found_files[@]+"${found_files[@]}"}"; do
      echo "  - $file"
      ls -la "$file" 2>/dev/null | sed 's/^/    /' || true
      for repo in "${scanned_repos[@]+"${scanned_repos[@]}"}"; do
        if [[ "$file" == "$repo"* ]]; then
          echo "    Repository: $(basename "$repo")"
          break
        fi
      done
    done
    echo
  else
    success "NO malicious bun_environment.js files found in $total_node_modules node_modules directories"
  fi
  total_checks=$((total_checks + 1))
}
echo "1. SCANNING FOR MALICIOUS FILES"
echo "================================"
scan_node_modules
for location in "." "$HOME" "/tmp" "/var/tmp"; do
  check_file "$location/bun_environment.js" "Malicious post-install script"
done
echo
echo "2. SCANNING FOR MALICIOUS DIRECTORIES"
echo "====================================="
check_directory "$HOME/.truffler-cache" "Hidden directory for Trufflehog binary storage"
check_directory "$HOME/.truffler-cache/extract" "Temporary directory for binary extraction"
for temp_dir in "/tmp" "/var/tmp" "$PWD"; do
  check_directory "$temp_dir/.truffler-cache" "Truffler cache in $temp_dir"
done
echo
echo "3. SCANNING FOR MALICIOUS BINARIES"
echo "=================================="
check_file "$HOME/.truffler-cache/trufflehog" "Downloaded Trufflehog binary (Linux/Mac)"
check_file "$HOME/.truffler-cache/trufflehog.exe" "Downloaded Trufflehog binary (Windows)"
IFS=':' read -ra PATH_DIRS <<<"$PATH"
for dir in "${PATH_DIRS[@]+"${PATH_DIRS[@]}"}"; do
  [[ -n "$dir" ]] && check_file "$dir/trufflehog" "Trufflehog binary in PATH ($dir)"
done
echo
echo "4. SCANNING FOR SUSPICIOUS PROCESSES"
echo "===================================="
check_processes "del /F /Q /S" "Windows destructive payload command"
check_processes "shred -uvz -n 1" "Linux/Mac destructive payload command"
check_processes "cipher /W:" "Windows secure deletion command"
check_processes "trufflehog" "Trufflehog process"
echo
echo "5. SCANNING COMMAND HISTORY"
echo "=========================="
check_command_history "curl.*bun.sh/install" "Suspicious Bun installation via curl"
check_command_history "irm bun.sh/install.ps1" "Windows Bun installation via PowerShell"
check_command_history "del /F /Q /S" "Windows destructive commands"
check_command_history "shred -uvz" "Linux destructive shred commands"
check_command_history "cipher /W:" "Windows cipher commands"
check_command_history "trufflehog" "Trufflehog usage"
echo
echo "6. ADDITIONAL SECURITY CHECKS"
echo "============================="
if [[ "${SKIP_ADDITIONAL:-0}" == "1" ]]; then
  warning "Skipping additional security checks (SKIP_ADDITIONAL=1)"
else
  log "Checking for recently modified suspicious files..."
  total_checks=$((total_checks + 1))
  suspicious_recent_files=()
  count=0
  while IFS= read -r -d '' file; do
    [[ -z "$file" ]] && continue
    suspicious_recent_files+=("$file")
    count=$((count + 1))
    [[ $count -ge 100 ]] && break
  done < <(find "$scan_path" -maxdepth 10 -type f \( -name "bun_environment.js" -o -name "*trufflehog*" \) -mtime -7 -print0 2>/dev/null)
  if [[ ${#suspicious_recent_files[@]} -gt 0 ]]; then
    warning "Found ${#suspicious_recent_files[@]} recently modified suspicious files:"
    findings=$((findings + ${#suspicious_recent_files[@]}))
    for file in "${suspicious_recent_files[@]+"${suspicious_recent_files[@]}"}"; do
      ls -la "$file" | sed 's/^/  /' || true
    done
    echo
  else
    success "No recently modified suspicious files found"
  fi
  log "Checking system logs for Bun installation attempts..."
  total_checks=$((total_checks + 1))
  log_files=()
  if [[ "$MACHINE" == "Mac" ]]; then
    log_files+=("/var/log/system.log" "/var/log/install.log")
    if [[ -d "$HOME/Library/Logs" ]]; then
      while IFS= read -r lf; do log_files+=("$lf"); done < <(find "$HOME/Library/Logs" -type f -name "*.log" 2>/dev/null)
    fi
  else
    log_files+=("/var/log/auth.log" "/var/log/syslog" "/var/log/messages")
  fi
  log_files+=("$HOME/.bash_history" "$HOME/.zsh_history")
  found_log_entries=false
  for log_file in "${log_files[@]+"${log_files[@]}"}"; do
    if [[ -r "$log_file" ]] && grep -qE "bun.sh|trufflehog" "$log_file" 2>/dev/null; then
      warning "Found suspicious entries in $log_file:"
      findings=$((findings + 1))
      found_log_entries=true
      grep -E "bun.sh|trufflehog" "$log_file" | tail -5 | sed 's/^/  /' || true
      echo
    fi
  done
  if [[ "$found_log_entries" == false ]]; then
    success "No suspicious entries found in accessible log files"
  fi
fi
echo
echo "=========================================="
echo "SCAN COMPLETE"
echo "=========================================="
echo "Total checks performed: $total_checks"
echo "Total findings: $findings"
echo
if [[ $findings -gt 0 ]]; then
  critical "SECURITY ALERT: $findings indicators of compromise detected!"
  echo
  echo "RECOMMENDED ACTIONS:"
  echo "1. Immediately disconnect from the network if possible"
  echo "2. Run a full antivirus scan"
  echo "3. Check and rotate all credentials/API keys"
  echo "4. Review recent npm package installations"
  echo "5. Consider reinstalling npm packages from clean sources"
  echo "6. Monitor system for unusual activity"
  echo "7. Report to security team if in a corporate environment"
  exit 1
else
  success "No indicators of compromise detected"
  echo "System appears clean, but continue monitoring for suspicious activity."
  exit 0
fi
