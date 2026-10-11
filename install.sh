#!/data/data/com.termux/files/usr/bin/bash
# TermuxSentinel installer - sets up Python and a "sentinel" launcher.
set -e

GREEN='\033[1;32m'; YELLOW='\033[1;33m'; RED='\033[1;31m'; NC='\033[0m'
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo -e "${GREEN}[*] TermuxSentinel installer${NC}"

if [ -z "$PREFIX" ] || [ ! -d "$PREFIX/bin" ]; then
  echo -e "${YELLOW}[!] Termux not detected. Continuing with a local install only.${NC}"
  PREFIX="${PREFIX:-$HOME/.local}"
  mkdir -p "$PREFIX/bin"
fi

if command -v pkg >/dev/null 2>&1; then
  echo -e "${GREEN}[*] Updating packages...${NC}"
  pkg update -y && pkg upgrade -y
  echo -e "${GREEN}[*] Installing Python...${NC}"
  pkg install -y python
else
  echo -e "${YELLOW}[!] 'pkg' not found; make sure python3 is installed.${NC}"
fi

# No third-party pip packages needed (standard library only).
if ! command -v python3 >/dev/null 2>&1 && ! command -v python >/dev/null 2>&1; then
  echo -e "${RED}[-] Python not found. Aborting.${NC}"; exit 1
fi

chmod +x "$DIR/main.py" "$DIR/install.sh"

LAUNCHER="$PREFIX/bin/sentinel"
cat > "$LAUNCHER" <<LAUNCH
#!/usr/bin/env bash
exec python3 "$DIR/main.py" "\$@"
LAUNCH
chmod +x "$LAUNCHER"

echo -e "${GREEN}[+] Done! Start the tool with:  sentinel${NC}"
echo -e "    or: python3 $DIR/main.py"
