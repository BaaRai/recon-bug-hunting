#!/usr/bin/env bash
set -euo pipefail
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

# Vérification des dépendances de base
for cmd in go git python3 pip3 sudo; do
    command -v "$cmd" >/dev/null 2>&1 || { echo "$cmd n'est pas installé. Installe-le d'abord."; exit 1; }
done

# Création des dossiers nécessaires
mkdir -p ~/.gf
mkdir -p ~/tools
mkdir -p ~/tools/resolvers

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

sleep 2
d=$(date +"%b-%d-%y %H:%M")
echo -e ${CP}"[+]Installation Started On: $d \n"
sleep 1
echo -e ${BLUE}"[+]Checking Go Installation\n"
if [[ -z "${GOPATH:-}" ]]; then
  echo -e ${RED}"[+]Go n'est pas installé ou GOPATH n'est pas défini. Veuillez l'installer/configurer et relancer le script."
  echo -e ${CP}"[+]Pour l'installation, consultez la partie pré-requis du repo recon-automation !"
  exit 1
else
  echo -e ${BLUE}"..........Go est installé..............\n"
fi
echo -e ${GREEN}"[+]Installing Assetfinder\n"
sleep 1
assetfinder_checking(){
command -v "assetfinder" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then 
        go install github.com/tomnomnom/assetfinder@latest
        echo -e ".............assetfinder installé avec succès..............\n"
    else
        echo -e ".......assetfinder déjà installé...........\n"
    fi
sleep 1
echo -e ${CP}"[+]Installing gau\n"
command -v "gau" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
            
            go install github.com/lc/gau@latest
            echo -e ".........gau successfully installed................\n"
            else
            echo -e "...........gau already exists..................... \n"
       fi
sleep 1
echo -e ${CPO}"[+]Installing qsreplace\n"
command -v "qsreplace" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
            
            go install github.com/tomnomnom/qsreplace@latest
            echo -e ".........qsreplace successfully installed............\n"
            else
            echo -e "...........qsreplace already exists.................. \n"
       fi
}
assetfinder_checking
sleep 1
echo -e ${PINK}"[+]Installing gf tool\n"
checking_gf(){
command -v "gf" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
         go install github.com/tomnomnom/gf@latest
         # Ajout dans .bashrc si absent
         if ! grep -q 'gf-completion.zsh' ~/.bashrc; then
           echo 'source "$GOPATH"/pkg/mod/github.com/tomnomnom/gf*/gf-completion.zsh' >> ~/.bashrc
         fi
         cp -r "$GOPATH"/pkg/mod/github.com/tomnomnom/gf*/examples ~/.gf
         echo -e "..............Gf tool installé avec succès..............\n"
     else
         echo -e "................Gf tool déjà existant....................\n"
    fi
sleep 1
echo -e ${BLUE}"[+]Installing Gf Patterns\n"
if [[ ! -d ~/Gf-Patterns  ]]; then       
        cd ~
        git clone https://github.com/1ndianl33t/Gf-Patterns.git
        sudo mv ~/Gf-Patterns/*.json ~/.gf
        echo -e "...........Gf Patterns installés avec succès............\n"
        cd - >/dev/null
    else
        echo -e "...........Gf Patterns déjà existants.....................\n"
    fi    
}
checking_gf
sleep 1
echo -e ${CP}"[+]Installing Amass\n"
amass_checking(){
command -v "amass" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
         
         
         sudo apt-get install amass -y
         echo -e "................Amass successfully installed..............\n"
         else
         echo -e "...............Amass is already installed.................\n"
   fi
}
amass_checking
sleep 1

echo -e ${CP}"[+]Installing Jq\n"
jq_checking(){
command -v "jq" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
         
         
         sudo apt-get install jq -y
         echo -e ".................jq successfully installed..............\n"
         else
         echo -e ".............jq is already installed.....................\n"
   fi

}
jq_checking
sleep 1
echo -e ${CP}"[+]Installing sqlmap\n"
sqlmap_checking(){
command -v "sqlmap" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
    sudo apt-get install sqlmap -y
    echo -e ".................sqlmap successfully installed..............\n"
else
    echo -e ".............sqlmap is already installed.....................\n"
fi
}
sqlmap_checking
sleep 1
echo -e ${CG}"[+]Installing subfinder\n"
subfinder_checking(){
command -v "subfinder" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
         
         GO111MODULE=on go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 
         echo -e "................subfinder successfully installed.............\n"
         else
         echo -e "............subfinder is already installed...................\n"
   fi
}
subfinder_checking
sleep 1
echo -e ${CN}"[+]Installing Massdns\n"
massdns_checking(){
mkdir -p ~/tools
command -v "massdns" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
        mkdir -p ~/tools
         cd ~/tools
         git clone https://github.com/blechschmidt/massdns.git
         cd massdns
          make
          cd bin
          sudo mv massdns /usr/local/bin
          echo -e "............massdns installé avec succès..............\n"
         else
         echo -e "..............massdns is already installed................\n"
    fi
}
massdns_checking
sleep 1
echo -e ${CP}"[+]Installing Nuclei\n"
command -v "nuclei" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
         GO111MODULE=on go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest   
         echo -e "...........Nuclei tool successfully installed...................\n"   
          else
          echo -e "...........Nuclei tool already exists...................\n"
       fi
sleep 1
echo -e ${NEW}"[+]Installing Nuclei Templates\n"
if [[ ! -d ~/tools/nuclei-templates ]]; then
         mkdir -p ~/tools
         cd ~/tools
         git clone https://github.com/projectdiscovery/nuclei-templates.git
         echo -e "...............Nuclei templates installation done..............\n"
         else
         echo -e "................nuclei templates already exists................\n"
  fi
sleep 1
echo -e ${CP}"[+]Installing dnsvalidator\n"
dnsvalidator_installing(){
mkdir -p ~/tools
mkdir -p ~/tools/resolvers
command -v "dnsvalidator" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
        cd ~/tools
       git clone  https://github.com/vortexau/dnsvalidator.git
       cd dnsvalidator
       sudo apt-get install python3-pip -y
       sudo python3 setup.py install 
       dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 25 -o resolvers.txt
       cat resolvers.txt | tail -n 60 > ~/tools/resolvers/resolver.txt
       else
        echo -e ".......dnsvalidator already exist.........\n"
fi

}

dnsvalidator_installing
sleep 1
other_tools(){
echo -e ${CPO}"[+]Installing httpx\n"
command -v "httpx" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then       
        go install github.com/projectdiscovery/httpx/cmd/httpx@latest
        echo -e ".................httpx successfully installed..............\n"
         else
         echo -e "...............httpx is already installed.............\n"
   fi
sleep 1
echo -e ${CP}"[+]Installing httprobe\n"
command -v "httprobe" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then        
         go install github.com/tomnomnom/httprobe@latest 
         echo -e ".............httprobe successfully installed..............\n"
         else
         echo -e "...........httprobe is already installed...............\n"
   fi  
sleep 1
echo -e ${CP}"[+]Installing shuffledns\n"
command -v "shuffledns" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then       
        mkdir -p ~/tools
        cd ~/tools
  wget https://github.com/projectdiscovery/shuffledns/releases/download/v1.0.4/shuffledns_1.0.4_linux_amd64.tar.gz >/dev/null 2>&1
        tar -xvzf shuffledns_1.0.4_linux_amd64.tar.gz     
        sudo mv shuffledns /usr/local/bin
         rm -f shuffledns_1.0.4_linux_amd64.tar.gz
        echo -e "................shuffledns installé avec succès..............\n"        
    else
        echo -e "..............shuffledns déjà installé..................\n"
   fi
sleep 1
echo -e ${GREEN}"[+]Installing Seclists\n"
if [[ ! -d /usr/share/seclists ]]; then 
        
        sudo apt install seclists -y
        echo -e "....................Seclists Successfully Installed.................\n"    
        else
        echo -e ".................Seclists Already Exists.................\n"
fi
sleep 1      
echo -e ${CNC}"[+]Downloading LFI payloads\n"   
if [[ ! -f ~/tools/dotdotpwn.txt ]]; then
         cd ~/tools
         wget https://raw.githubusercontent.com/swisskyrepo/PayloadsAllTheThings/master/Directory%20Traversal/Intruder/dotdotpwn.txt 
         cat dotdotpwn.txt | head -n 120 > ~/tools/lfipayloads.txt
         echo -e "..............LFI Payloads téléchargés avec succès..........
"
         cd - >/dev/null
    else
        echo -e ".................LFI Payloads déjà existants.................\n"
fi  
sleep 1
echo -e ${CP}"[+]Installing Corsy\n"
if [[ ! -d ~/tools/Corsy ]]; then
        cd ~/tools
        git clone  https://github.com/s0md3v/Corsy.git
        cd Corsy
        sudo apt install python3-pip -y
        pip3 install --user -r requirements.txt
        echo -e "....................Corsy installation terminée...................\n"
        cd - >/dev/null
    else
        echo -e ".............Corsy déjà installé.................\n"
    fi
sleep 1
echo -e ${CNC}"[+]Installing waybackurls\n"
command -v "waybackurls" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
        go install github.com/tomnomnom/waybackurls@latest
        echo -e "......waybackurls installed successfully......\n"
        else
        echo -e ${CNC}"........waybackurls already exists...........\n"
    fi
sleep 1
echo -e ${PINK}"[+]Installing Unfurl\n"
command -v "unfurl" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
         go install github.com/tomnomnom/unfurl@latest
        echo -e "......Unfurl installed successfully..........\n"
        else
        echo -e "........Unfurl already exists................\n"   
    fi
sleep 1
echo -e ${CNC}"[+]Installing ffuf\n"
command -v "ffuf" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
    go install github.com/ffuf/ffuf@latest 
    echo -e ".......ffuf successfully installed........\n"
    else
    echo -e ".......ffuf already exists................\n"
    fi
sleep 1
echo -e ${CNC}"[+]Installing OpenRedireX\n"
if [ -d ~/tools/OpenRedireX ]; then
     echo -e "..................OpenRedireX already exists...............\n"
     else    
    cd ~/tools
    git clone https://github.com/devanshbatham/OpenRedireX
    echo "...............OpenRedireX Installed successfully..............\n"
fi
sleep 1
echo -e ${BLUE}"[+]Installing kxss\n"
command -v "kxss" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
    echo "........installing kxss............"
    go install github.com/tomnomnom/hacks/kxss@latest 
    echo -e "........kxss installed successfully...........\n"
    else
    echo -e ".........kxss already exists.................\n"
    fi
sleep 1
echo -e ${GREEN}"[+]Installing dalfox\n"
command -v "dalfox" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
    GO111MODULE=on go install github.com/hahwul/dalfox/v2@latest
    echo -e ".........dalfox installed successfully...........\n"
    else
    echo -e "...........dalfox already exists...............\n"
    fi
sleep 1
}
other_tools
sleep 1
subdomain_takeover(){
echo -e ${GREEN}"[+]Installing subzy\n"
command -v "subzy" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
         go install github.com/PentestPad/subzy@latest
         echo -e "..........Subzy takeover tool Installation done........\n"
         else
         echo -e "............subzy is already installed.............\n"
    fi
sleep 1
echo -e ${CP}"[+]Installing subjack\n"
command -v "subjack" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then         
          go install github.com/haccer/subjack@latest
          cd ~/go/pkg/mod/github.com/haccer/
          sudo mv subjack@* subjack
          cd ~/go/
          mkdir -p src
          mkdir -p src/github.com
          sudo mv ~/go/pkg/mod/github.com/haccer ~/go/src/github.com/
          
         echo -e ".........Subjack takeover tool installation done.........\n"
          else
          echo -e "...........subjack is already installed.............\n"
    fi
sleep 1
}
subdomain_takeover
sleep 1
echo -e ${CN}"[+]Installing Gxss\n"
xss_tools(){
command -v "Gxss" >/dev/null 2>&1
if [[ $? -ne 0 ]]; then
        go install github.com/KathanP19/Gxss@latest
        echo -e "...............Gxss successfully installed..................\n"
        else
        echo -e "..................Gxss already installed..................\n"
     fi
sleep 1
echo -e ${CPO}"[+]Installing ParamSpider\n"
if [[ ! -d ~/tools/ParamSpider ]]; then
       cd ~/tools
        git clone https://github.com/devanshbatham/ParamSpider
       cd ParamSpider
       pip3 install --user -r requirements.txt
       echo -e "............ParamSpider installé avec succès................\n"
       cd - >/dev/null
    else
       echo -e "............ParamSpider déjà installé.....................\n"
    fi
sleep 1
echo -e ${BLUE}"[+]Installing Arjun\n"
if [[ ! -d ~/tools/Arjun ]]; then
       cd ~/tools
      git clone https://github.com/s0md3v/Arjun.git
       cd Arjun
       sudo python3 setup.py install 
       echo -e "............Arjun installé avec succès................\n"
       cd - >/dev/null
    else
       echo -e "............Arjun déjà installé.....................\n"
    fi
}
xss_tools
echo -e ${RED}"[+]***************All Done************************[+]\n"

# Ajout automatique de $HOME/go/bin au PATH selon le shell
if [ -n "${ZSH_VERSION-}" ]; then
  if ! grep -Fxq 'export PATH="$PATH:$HOME/go/bin"' ~/.zshrc; then
    echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.zshrc
    echo "Ajout de \$HOME/go/bin au PATH dans .zshrc (ouvre un nouveau terminal ou fais 'source ~/.zshrc')"
  fi
elif [ -n "${BASH_VERSION-}" ]; then
  if ! grep -Fxq 'export PATH="$PATH:$HOME/go/bin"' ~/.bashrc; then
    echo 'export PATH="$PATH:$HOME/go/bin"' >> ~/.bashrc
    echo "Ajout de \$HOME/go/bin au PATH dans .bashrc (ouvre un nouveau terminal ou fais 'source ~/.bashrc')"
  fi
fi
