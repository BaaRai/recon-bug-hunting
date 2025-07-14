#!/bin/bash
# set -euo pipefail  # Désactivé pour debug, voir comportement sans arrêt automatique
NC='\033[0m'
RED='\033[1;38;5;196m'
GREEN='\033[1;38;5;040m'
ORANGE='\033[1;38;5;202m'
BLUE='\033[1;38;5;012m'
BLUE2='\033[1;38;5;032m'
PINK='\033[1;38;5;013m'
GRAY='\033[1;38;5;004m'
NEW='\033[1;38;5;154m'
YELLOW='\033[1;38;5;214m'
CG='\033[1;38;5;087m'
CP='\033[1;38;5;221m'
CPO='\033[1;38;5;205m'
CN='\033[1;38;5;247m'
CNC='\033[1;38;5;051m'

# === Variables de configuration ===
TOOLS_DIR="$HOME/tools"
CORSY="$TOOLS_DIR/Corsy/corsy.py"
OPENREDIREX="$TOOLS_DIR/OpenRedireX/openredirex.py"
OPENREDIREX_PAYLOADS="$TOOLS_DIR/OpenRedireX/payloads.txt"
LFI_PAYLOADS="$TOOLS_DIR/lfipayloads.txt"
RESOLVERS="$TOOLS_DIR/resolvers/resolver.txt"
NUCLEI_TEMPLATES="$TOOLS_DIR/nuclei-templates/"
SECLISTS_DNS="/usr/share/seclists/Discovery/DNS/deepmagic.com-prefixes-top50000.txt"
# Fichiers temporaires à nettoyer
TMP_FILES=()

# === Option de log global ===
LOG_FILE=""
if [[ "${1:-}" == "--log" && -n "${2:-}" ]]; then
  LOG_FILE="$2"
  exec > >(tee -a "$LOG_FILE") 2>&1
  echo -e "\033[1;38;5;214m[+] Toute la sortie sera loggée dans : $LOG_FILE\033[0m"
fi

# Affichage de l'aide
if [[ "${1:-}" == "--help" ]]; then
  echo -e "\nUsage : $0 [options]\n"
  echo "Options :"
  echo "  --log fichier.log      Log toute la sortie dans fichier.log"
  echo "  --help                Affiche cette aide et quitte"
  echo "  --no-xss              Désactive la détection XSS"
  echo "  --no-sqli             Désactive la détection SQLi"
  echo "  --no-lfi              Désactive la détection LFI"
  echo "  --no-nuclei           Désactive le scan Nuclei"
  echo "  --no-cors             Désactive la détection CORS misconfig"
  echo "  --no-openredirect     Désactive la détection Open Redirect"
  echo "  --no-gf               Désactive l'analyse Gf patterns"
  echo "  --no-ffuf             Désactive le scan FFUF"
  echo "  --no-wordlist         Désactive la génération de wordlist cible"
  echo "  --no-service          Désactive la détection des services (httpx)"
  echo "  --no-urls             Désactive la collecte d'URLs (gau)"
  echo ""
  echo "Exemple : $0 --no-xss --no-nuclei --log recon.log"
  echo ""
  echo "The script automates the reconnaissance for the bug bounty."
  echo "It checks dependencies, performs reconnaissance on a domain or scope, and organizes results."
  echo "A final summary is written in summary.txt in the domain's directory."
  exit 0
fi

# === Vérification de l'OS ===
if [[ "$(uname -s)" != "Linux" ]]; then
  echo -e "${RED}[!] This script is intended for Linux only. Abandon.${NC}"
  exit 1
fi

# Séparateur visuel
step_separator() {
  echo -e "\n${YELLOW}=====================[ Start of step : $1 ]=====================${NC}\n"
}

# Vérification d'un outil avant usage
check_tool() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo -e "${RED}[!] Tool '$1' is missing. Install it before continuing.${NC}"
    exit 1
  fi
}

# Vérification des dépendances
check_dependencies() {
    local missing=0
    local deps=(httpx gau ffuf nuclei python3 curl jq subfinder assetfinder amass shuffledns subzy subjack kxss dalfox gf qsreplace unfurl sqlmap)
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" >/dev/null 2>&1; then
            echo -e "${RED}[!] Missing dependency: $dep. Please install it before running this script.${NC}"
            missing=1
        fi
    done
    # Vérification des scripts Python spécifiques
    if [ ! -f "$CORSY" ]; then
        echo -e "${RED}[!] $CORSY is missing. Please install Corsy.${NC}"
        missing=1
    fi
    if [ ! -f "$OPENREDIREX" ]; then
        echo -e "${RED}[!] $OPENREDIREX is missing. Please install OpenRedireX.${NC}"
        missing=1
    fi
    if [ ! -f "$OPENREDIREX_PAYLOADS" ]; then
        echo -e "${RED}[!] $OPENREDIREX_PAYLOADS is missing. Please add payloads.txt to OpenRedireX.${NC}"
        missing=1
    fi
    if [ ! -f "$LFI_PAYLOADS" ]; then
        echo -e "${RED}[!] $LFI_PAYLOADS is missing. Please generate or download this file.${NC}"
        missing=1
    fi
    if [ $missing -eq 1 ]; then
        exit 1
    fi
}

function bounty_recon(){
echo -e ${RED}"################################################################## \n "
echo -e ${CP}" $$$$$$            $$\                            $$$$$$  $$\                          "
echo -e ${CP}"$$  __$$\           $$ |                          $$  __$$\ $$ |                         "
echo -e ${CP}"$$ /  \__|$$\   $$\ $$$$$$$\   $$$$$$\   $$$$$$\  $$ /  \__|$$ | $$$$$$\  $$\  $$\  $$\ "
echo -e ${CP}"$$ |      $$ |  $$ |$$  __$$\ $$  __$$\ $$  __$$\ $$$$\     $$ |$$  __$$\ $$ | $$ | $$ |"
echo -e ${CP}"$$ |      $$ |  $$ |$$ |  $$ |$$$$$$$$ |$$ |  \__|$$  _|    $$ |$$ /  $$ |$$ | $$ | $$ |"
echo -e ${CP}"$$ |  $$\ $$ |  $$ |$$ |  $$ |$$   ____|$$ |      $$ |      $$ |$$ |  $$ |$$ | $$ | $$ |"
echo -e ${CP}"\$$$$$$  |\$$$$$$$ |$$$$$$$  |\$$$$$$$\ $$ |      $$ |      $$ |\$$$$$$  |\$$$$$\$$$$  |"
echo -e ${CP}" \______/  \____$$ |\_______/  \_______|\__|      \__|      \__| \______/  \_____\____/ "
echo -e ${CP}"          $$\   $$ |                                                                    "
echo -e ${CP}"          \$$$$$$  |                                                                    "
echo -e ${CP}"           \______/                                                                     "
echo -e ${CP}"                  Complete Recon Automation Framework                                   "
echo -e ${RED}"################################################################## \n "
}
d=$(date +"%b-%d-%y %H:%M")

# === Fonctions modulaires pour chaque étape du recon ===
service_check() {
  local input_file="$1"
  step_separator "Service Check"
  check_tool httpx
  local start=$(date +%s)
  echo -e ${CP}"[+] Checking services on target:- \n"
  echo "$domain" | httpx -threads 30 -o "$input_file"
  local end=$(date +%s)
  echo -e "${GRAY}Duration: $((end-start)) seconds${NC}"
}

cors_scan() {
  local input_file="$1"
  local output_file="$2"
  echo -e ${GREEN}"\n[+] CORS misconfiguration search:- "
  python3 "$CORSY" -i "$input_file" -t 15 | tee "$output_file" || { echo -e "${RED}[!] Error during Corsy execution.${NC}"; exit 1; }
}

ffuf_scan() {
  local input_file="$1"
  local valid_tmp="$2"
  local valid_file="$3"
  step_separator "FFUF Scan"
  check_tool ffuf
  local start=$(date +%s)
  echo -e ${CNC}"\n[+] FFUF started on URLs:- "
  ffuf -c -u "FUZZ" -w "$input_file" -of csv -o "$valid_tmp" || echo "[WARN] FFUF returned an error, see output above."
  cat "$valid_tmp" | grep http | awk -F "," '{print $1}'  >>  "$valid_file"
  local end=$(date +%s)
  echo -e "${GRAY}Duration: $((end-start)) seconds${NC}"
}

generate_wordlists() {
  local input_file="$1"
  local paths_file="$2"
  local param_file="$3"
  echo -e ${PINK}"\n[+] Generating target keyword wordlist:- "
  cat "$input_file" | unfurl -unique paths > "$paths_file"
  cat "$input_file" | unfurl -unique keys > "$param_file"
}

gf_patterns() {
  local input_file="$1"
  local gf_dir="$2"
  echo -e ${BLUE}"\n[+] Starting Gf models on valid URLs:- "
  gf xss "$input_file" | tee "$gf_dir/xss.txt" &
  gf ssrf "$input_file" | tee "$gf_dir/ssrf.txt" &
  gf sqli "$input_file" | tee "$gf_dir/sql.txt" &
  gf lfi "$input_file" | tee "$gf_dir/lfi.txt" &
  gf ssti "$input_file" | tee "$gf_dir/ssti.txt" &
  gf aws-keys "$input_file" | tee "$gf_dir/awskeys.txt" &
  gf redirect "$input_file" | tee "$gf_dir/redirect.txt" &
  gf idor "$input_file" | tee "$gf_dir/idor.txt" &
  wait
  cat "$gf_dir/redirect.txt" | sed 's/\=.*/=/' | tee "$gf_dir/purered.txt"
}

nuclei_scan() {
  local input_file="$1"
  local output_file="$2"
  step_separator "Nuclei Scan"
  check_tool nuclei
  local start=$(date +%s)
  echo -e ${CP}"\n [+] Starting Nuclei scanner "
  cat "$input_file" | nuclei -t "$NUCLEI_TEMPLATES" -c 50 -o "$output_file" || echo "[WARN] Nuclei returned an error, see output above."
  [ ! -s "$output_file" ] && rm "$output_file"
  local end=$(date +%s)
  echo -e "${GRAY}Duration: $((end-start)) seconds${NC}"
}

openredirect_scan() {
  local input_file="$1"
  local output_file="$2"
  echo -e ${ORANGE}"\n[+] Open Redirect search:- "
  echo "[DEBUG] Number of URL candidates for OpenRedirect: $(wc -l < "$input_file")"
  cat "$input_file" | qsreplace FUZZ | tee "$output_file" || { echo -e "${RED}[!] Error generating fuzzredirect.txt.${NC}"; exit 1; }
  # Automatic generation of one URL per FUZZ parameter for OpenRedireX (bash+sed version)
  input="$output_file"
  output="$output_file" # Use the same file for input and output
  > "$output"
  while IFS= read -r url; do
    n=$(grep -o "FUZZ" <<< "$url" | wc -l)
    if [ "$n" -le 1 ]; then
      echo "$url" >> "$output"
    else
      for i in $(seq 1 $n); do
        tmp="$url"
        c=1
        while [[ $c -le $n ]]; do
          if [ $c -eq $i ]; then
            tmp="${tmp/FUZZ/FUZZ_ONLY}"
          else
            tmp="${tmp/FUZZ/FIXED}"
          fi
          c=$((c+1))
        done
        tmp="${tmp//FIXED/FIXEDVAL}"
        tmp="${tmp/FUZZ_ONLY/FUZZ}"
        tmp="${tmp//FIXEDVAL/FIXED}"
        echo "$tmp" >> "$output"
      done
    fi
  done < "$input"

  grep 'FUZZ' "$output" | \
  python3 "$OPENREDIREX" -p "$OPENREDIREX_PAYLOADS" --keyword FUZZ | tee "$output_file" || { echo -e "${RED}[!] Error during OpenRedireX execution.${NC}"; exit 1; }
}

xss_scan() {
  local gf_dir="$1"
  local xss_dir="$2"
  echo -e ${GREEN}"\n[+] XSS search:- "
  cat "$gf_dir/xss.txt" | kxss  | tee "$xss_dir/kxss.txt"
  cat "$xss_dir/kxss.txt" | awk '{print $9}' | sed 's/=.*/=/' | tee "$xss_dir/kxss1.txt"
  awk '{print $1}' "$xss_dir/kxss1.txt" | dalfox pipe | tee "$xss_dir/dalfoxss.txt"
  cat "$gf_dir/xss.txt" | grep "=" | qsreplace "'><sCriPt class=khan>prompt(1)</script>" | while read host; do curl --silent --path-as-is --insecure "$host" | grep -qs "'><sCriPt class=khan>prompt(1)" && echo "$host \033[0;31mVulnerable\n"; done | tee "$xss_dir/vulnxss.txt"
}

sqli_scan() {
  local gf_dir="$1"
  local sqli_dir="$2"
  step_separator "SQLi (sqlmap) Scan"
  check_tool sqlmap
  local start=$(date +%s)
  echo -e ${CG}"\n[+] SQL injection search:- "
  sqlmap -m "$gf_dir/sql.txt" --batch --random-agent --level 1 | tee "$sqli_dir/sqlmap.txt" || echo "[WARN] sqlmap returned an error, see output above."
  local end=$(date +%s)
  echo -e "${GRAY}Duration: $((end-start)) seconds${NC}"
}

lfi_scan() {
  local gf_dir="$1"
  local lfi_dir="$2"
  step_separator "LFI Scan"
  check_tool ffuf
  local start=$(date +%s)
  echo -e ${BLUE}"\n[+] LFI vulnerability search:- "
  cat "$gf_dir/lfi.txt" | qsreplace FUZZ | while read url; do ffuf -u "$url" -mr "root:x" -w "$LFI_PAYLOADS" -of csv -o "$lfi_dir/lfi.txt" -t 50 -c || echo "[WARN] FFUF (LFI) returned an error, see output above."; done
  local end=$(date +%s)
  echo -e "${GRAY}Duration: $((end-start)) seconds${NC}"
}

# Gestion des options pour désactiver toutes les étapes principales
NO_XSS=0
NO_SQLI=0
NO_LFI=0
NO_NUCLEI=0
NO_CORS=0
NO_OPENREDIRECT=0
NO_GF=0
NO_FFUF=0
NO_WORDLIST=0
NO_SERVICE=0
NO_URLS=0
for arg in "$@"; do
  case $arg in
    --no-xss) NO_XSS=1 ;;
    --no-sqli) NO_SQLI=1 ;;
    --no-lfi) NO_LFI=1 ;;
    --no-nuclei) NO_NUCLEI=1 ;;
    --no-cors) NO_CORS=1 ;;
    --no-openredirect) NO_OPENREDIRECT=1 ;;
    --no-gf) NO_GF=1 ;;
    --no-ffuf) NO_FFUF=1 ;;
    --no-wordlist) NO_WORDLIST=1 ;;
    --no-service) NO_SERVICE=1 ;;
    --no-urls) NO_URLS=1 ;;
  esac
done

function single_recon(){
clear
bounty_recon
echo -n -e ${ORANGE}"\n[+] Enter target domain (e.g evil.com) : " 
read -r domain
# Sécurisation du nom de domaine (alphanum, tiret, point)
domain=$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]//g')
if [[ -z "$domain" ]]; then
    echo -e "${RED}[-] No domain entered or invalid domain. Abandon." >&2
    exit 1
fi
mkdir -p "$domain" "$domain/vulnerabilities" "$domain/vulnerabilities/cors" "$domain/target_wordlist" "$domain/gf" "$domain/vulnerabilities/openredirect/" "$domain/vulnerabilities/xss_scan" "$domain/nuclei_scan" "$domain/vulnerabilities/LFI" "$domain/vulnerabilities/sqli"
echo -e ${BLUE}"\n[+] Starting reconnaissance on $d: \n"
sleep 1
if [ $NO_SERVICE -eq 0 ]; then service_check "$domain/httpx.txt"; fi
sleep 1
if [ $NO_CORS -eq 0 ]; then cors_scan "$domain/httpx.txt" "$domain/vulnerabilities/cors/cors_misconfig.txt"; fi
sleep 1
# ffuf_scan, gf_patterns, etc. utilisent maintenant "$domain/httpx.txt" comme source
if [ $NO_FFUF -eq 0 ]; then ffuf_scan "$domain/httpx.txt" "$domain/ffuf-valid-tmp.txt" "$domain/ffuf-valid.txt"; fi
sleep 1
if [ $NO_GF -eq 0 ]; then gf_patterns "$domain/httpx.txt" "$domain/gf"; fi
sleep 1
if [ $NO_NUCLEI -eq 0 ]; then nuclei_scan "$domain/httpx.txt" "$domain/nuclei_scan/all.txt"; fi
sleep 1
if [ $NO_OPENREDIRECT -eq 0 ]; then openredirect_scan "$domain/gf/redirect.txt" "$domain/vulnerabilities/openredirect/confirmopenred.txt"; fi
sleep 1
if [ $NO_XSS -eq 0 ]; then xss_scan "$domain/gf" "$domain/vulnerabilities/xss_scan"; fi
sleep 1
if [ $NO_SQLI -eq 0 ]; then sqli_scan "$domain/gf" "$domain/vulnerabilities/sqli"; fi
sleep 1
if [ $NO_LFI -eq 0 ]; then lfi_scan "$domain/gf" "$domain/vulnerabilities/LFI"; fi
# Résumé final dans un fichier
SUMMARY_FILE="$domain/summary.txt"
echo "================ Summary of results for $domain ================" > "$SUMMARY_FILE"
[ -f "$domain/vulnerabilities/xss_scan/vulnxss.txt" ] && echo "XSS found: $(grep -c 'Vulnerable' $domain/vulnerabilities/xss_scan/vulnxss.txt) ($domain/vulnerabilities/xss_scan/vulnxss.txt)" >> "$SUMMARY_FILE" || echo "XSS: None or step not run" >> "$SUMMARY_FILE"
[ -f "$domain/vulnerabilities/sqli/sqlmap.txt" ] && echo "SQLi found: $(grep -ci 'sql injection' $domain/vulnerabilities/sqli/sqlmap.txt) ($domain/vulnerabilities/sqli/sqlmap.txt)" >> "$SUMMARY_FILE" || echo "SQLi: None or step not run" >> "$SUMMARY_FILE"
[ -f "$domain/vulnerabilities/LFI/lfi.txt" ] && echo "LFI found: $(grep -c 'root:x' $domain/vulnerabilities/LFI/lfi.txt) ($domain/vulnerabilities/LFI/lfi.txt)" >> "$SUMMARY_FILE" || echo "LFI: None or step not run" >> "$SUMMARY_FILE"
[ -f "$domain/vulnerabilities/openredirect/confirmopenred.txt" ] && echo "Open Redirects: $(grep -c 'Vulnerable' $domain/vulnerabilities/openredirect/confirmopenred.txt) ($domain/vulnerabilities/openredirect/confirmopenred.txt)" >> "$SUMMARY_FILE" || echo "Open Redirect: None or step not run" >> "$SUMMARY_FILE"
[ -f "$domain/vulnerabilities/cors/cors_misconfig.txt" ] && echo "CORS misconfig: $(grep -c 'Potentially' $domain/vulnerabilities/cors/cors_misconfig.txt) ($domain/vulnerabilities/cors/cors_misconfig.txt)" >> "$SUMMARY_FILE" || echo "CORS: None or step not run" >> "$SUMMARY_FILE"
[ -f "$domain/nuclei_scan/all.txt" ] && echo "Nuclei findings: $(wc -l < $domain/nuclei_scan/all.txt) ($domain/nuclei_scan/all.txt)" >> "$SUMMARY_FILE" || echo "Nuclei: None or step not run" >> "$SUMMARY_FILE"
echo -e "\n${GREEN}Summary written to $SUMMARY_FILE${NC}"
}

function massive_recon(){
clear
bounty_recon
echo -n -e ${BLUE2}"\n[+] Complete reconnaissance with subdomains (e.g *.example.com): "
read -r domain
# Sécurisation du nom de domaine (alphanum, tiret, point)
domain=$(echo "$domain" | sed 's/[^a-zA-Z0-9.-]//g')
if [[ -z "$domain" ]]; then
    echo -e "${RED}[-] No domain entered or invalid domain. Abandon." >&2
    exit 1
fi
mkdir -p "$domain" "$domain/domain_enum" "$domain/final_domains" "$domain/takeovers" "$domain/vulnerabilities" "$domain/vulnerabilities/xss_scan" "$domain/vulnerabilities/sqli" "$domain/vulnerabilities/cors"  "$domain/nuclei_scan" "$domain/target_wordlist" "$domain/gf"  "$domain/vulnerabilities/LFI" "$domain/vulnerabilities/openredirect"
echo -e ${RED}"\n[+] Starting massive reconnaissance on $d:  "
sleep 1
# Parallelization of subdomain enumeration
{
  echo -e ${CPO}"\n[+] crt.sh enumeration started:- "
  curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | tee "$domain/domain_enum/crt.txt"
} &
{
  echo -e ${CP}"\n[+] subfinder enumeration started:- "
  subfinder -d "$domain" -o "$domain/domain_enum/subfinder.txt"
} &
{
  echo -e ${PINK}"\n[+] Assetfinder enumeration started:- "
  assetfinder -subs-only "$domain" | tee "$domain/domain_enum/assetfinder.txt"
} &
{
  echo -e ${ORANGE}"\n[+] Amass enumeration started:- "
  amass enum -passive -d "$domain" -o "$domain/domain_enum/amass.txt"
} &
{
  echo -e ${CN}"\n[+] Shuffledns enumeration started:- "
  shuffledns -d "$domain" -w "$SECLISTS_DNS" -r "$RESOLVERS" -o "$domain/domain_enum/shuffledns.txt"
} &
wait
echo -e ${CP}"\n[+] Collecting all subdomains into a single file:- "
cat "$domain/domain_enum/"*.txt > "$domain/domain_enum/all.txt"
echo -e ${BLUE}"\n[+] Resolving all subdomains:- "
shuffledns -d "$domain" -list "$domain/domain_enum/all.txt" -o "$domain/final_domains/domains.txt" -r "$RESOLVERS"
echo -e ${PINK}"\n[+] Checking services on subdomains:- "
cat "$domain/final_domains/domains.txt" | httpx -threads 30 -o "$domain/final_domains/httpx.txt"
echo -e ${CP}"\n[+] Subdomain takeover check:- "
subzy -hide_fails -targets "$domain/domain_enum/all.txt" | tee "$domain/takeovers/subzy.txt"
subjack -w "$domain/domain_enum/all.txt" -t 100 -timeout 30 -o "$domain/takeovers/take.txt" -ssl
echo -e ${GREEN}"\n[+] CORS misconfiguration search:- "
cors_scan "$domain/final_domains/httpx.txt" "$domain/vulnerabilities/cors/cors_misconfig.txt"
echo -e ${CP}"\n[+] Starting Nuclei scanner:- "
nuclei_scan "$domain/final_domains/httpx.txt" "$domain/nuclei_scan/all.txt"
echo -e ${CPO}"\n[+] Collecting URLs:- "
# collect_urls "$domain/final_domains/domains.txt" "$domain/waybackurls/tmp.txt" "$domain/waybackurls/wayback.txt" # Removed as per edit hint
echo -e ${CNC}"\n[+] FFUF started on URLs:- "
ffuf_scan "$domain/final_domains/domains.txt" "$domain/ffuf-valid-tmp.txt" "$domain/ffuf-valid.txt"
echo -e ${PINK}"\n[+] Generating target keyword wordlist:- "
generate_wordlists "$domain/final_domains/domains.txt" "$domain/target_wordlist/paths.txt" "$domain/target_wordlist/param.txt"
echo -e ${BLUE}"\n[+] Starting Gf models on valid URLs:- "
gf_patterns "$domain/final_domains/domains.txt" "$domain/gf"
echo -e ${ORANGE}"\n[+] Open Redirect search:- "
openredirect_scan "$domain/gf/redirect.txt" "$domain/vulnerabilities/openredirect/confirmopenred.txt"
echo -e ${GREEN}"\n[+] XSS search:- "
xss_scan "$domain/gf" "$domain/vulnerabilities/xss_scan"
echo -e ${CG}"\n[+] SQL injection search:- "
sqli_scan "$domain/gf" "$domain/vulnerabilities/sqli"
echo -e ${BLUE}"\n[+] LFI vulnerability search:- "
lfi_scan "$domain/gf" "$domain/vulnerabilities/LFI"
# Final summary
step_separator "Final Summary"
echo -e "${GREEN}Summary of results for $domain :${NC}"
[ -f "$domain/vulnerabilities/xss_scan/vulnxss.txt" ] && echo "XSS found: $(grep -c 'Vulnerable' $domain/vulnerabilities/xss_scan/vulnxss.txt) ($domain/vulnerabilities/xss_scan/vulnxss.txt)" || echo "XSS: None or step not run"
[ -f "$domain/vulnerabilities/sqli/sqlmap.txt" ] && echo "SQLi found: $(grep -ci 'sql injection' $domain/vulnerabilities/sqli/sqlmap.txt) ($domain/vulnerabilities/sqli/sqlmap.txt)" || echo "SQLi: None or step not run"
[ -f "$domain/vulnerabilities/LFI/lfi.txt" ] && echo "LFI found: $(grep -c 'root:x' $domain/vulnerabilities/LFI/lfi.txt) ($domain/vulnerabilities/LFI/lfi.txt)" || echo "LFI: None or step not run"
[ -f "$domain/vulnerabilities/openredirect/confirmopenred.txt" ] && echo "Open Redirects: $(grep -c 'Vulnerable' $domain/vulnerabilities/openredirect/confirmopenred.txt) ($domain/vulnerabilities/openredirect/confirmopenred.txt)" || echo "Open Redirect: None or step not run"
[ -f "$domain/vulnerabilities/cors/cors_misconfig.txt" ] && echo "CORS misconfig: $(grep -c 'Potentially' $domain/vulnerabilities/cors/cors_misconfig.txt) ($domain/vulnerabilities/cors/cors_misconfig.txt)" || echo "CORS: None or step not run"
[ -f "$domain/nuclei_scan/all.txt" ] && echo "Nuclei findings: $(wc -l < $domain/nuclei_scan/all.txt) ($domain/nuclei_scan/all.txt)" || echo "Nuclei: None or step not run"
}

menu(){
clear
bounty_recon
while true; do
    echo -e -n ${YELLOW}"\n[*] What type of reconnaissance would you like to perform ?\n "
    echo -e "  ${NC}[${CG}"1"${NC}]${CNC} Single target reconnaissance"
    echo -e "   ${NC}[${CG}"2"${NC}]${CNC} Complete reconnaissance with subdomains "
    echo -e "   ${NC}[${CG}"3"${NC}]${CNC} Exit"
    echo -n -e ${RED}"\n[+] Select: "
    read -r bounty_play
    if [ "$bounty_play" = "1" ]; then
        single_recon
        break
    elif [ "$bounty_play" = "2" ]; then
        massive_recon
        break
    elif [ "$bounty_play" = "3" ]; then
        exit
    else
        echo -e "${RED}[!] Invalid entry. Please choose 1, 2, or 3.${NC}"
    fi
  done
}

check_dependencies
menu

# Nettoyage automatique à la sortie
temp_cleanup() {
  for f in "${TMP_FILES[@]}"; do
    [ -f "$f" ] && rm -f "$f"
  done
}
trap temp_cleanup EXIT
