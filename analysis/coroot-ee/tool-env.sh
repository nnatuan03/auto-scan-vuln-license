# Source this file before running the reverse-engineering toolchain:
#   source /Users/itsmac/Desktop/auto-scan-vuln-lic/analysis/coroot-ee/tool-env.sh

export PATH="/Users/itsmac/go/bin:/opt/homebrew/bin:/opt/homebrew/sbin:/opt/homebrew/opt/binutils/bin:$PATH"

# Common tool locations:
# - GoReSym, redress, govulncheck: /Users/itsmac/go/bin
# - rizin/rz-bin/rz-asm, yara, osv-scanner, syft, grype, go, ghidraRun: /opt/homebrew/bin
# - greadelf/gobjdump/gstrings: /opt/homebrew/opt/binutils/bin
