#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_VOLUME_PATH="$SCRIPT_DIR/Output"
CONTAINER_VOLUME_PATH="/usr/src/app/Output"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
cd $SCRIPT_DIR

check_and_install_requirements() {
    # Check for iptables or ufw
    if ! command -v iptables &> /dev/null && ! command -v ufw &> /dev/null; then
        echo "iptables or ufw is required but not installed. Please install one of them."
        exit 1
    fi

    # Check for python3 and pip
    if ! command -v python3 &> /dev/null; then
        echo "python3 is required but not installed. Installing python3..."
        sudo apt-get update
        sudo apt-get install -y python3
    fi

    if ! command -v pip &> /dev/null; then
        echo "pip is required but not installed. Installing pip..."
        sudo apt-get install -y python3-pip
    fi

    # Check for docker
    if ! command -v docker &> /dev/null; then
        echo "docker is required but not installed. Please install docker."
        exit 1
    fi

    # Check for docker-compose
    if ! command -v docker compose &> /dev/null; then
        echo "docker-compose is required but not installed. Please install docker-compose."
        exit 1
    fi

    # Install Python dependencies
    echo "Installing Python dependencies..."
    pip install -r requirements.txt
}

# Fonction pour détecter la méthode de pare-feu à utiliser
detect_firewall() {
    if command -v iptables &>/dev/null; then
        FIREWALL="iptables"
    elif command -v ufw &>/dev/null; then
        FIREWALL="ufw"
    else
        echo "Ni iptables ni ufw n'ont été trouvés. Veuillez installer un pare-feu."
        exit 1
    fi
}

# Fonction pour bloquer le trafic sortant
block_outgoing() {
    case $FIREWALL in
        ufw)
            ufw default deny outgoing 
	    ufw reload
            echo "Outgoing trafic blocked with ufw."
            ;;
        iptables)
            iptables -A OUTPUT -j DROP
            echo "Outgoing trafic blocked with iptables."
            ;;
    esac
}

# Fonction pour débloquer le trafic sortant
unblock_outgoing() {
    case $FIREWALL in
        ufw)
            ufw default allow outgoing
            ufw reload
            echo "Outgoing trafic restored with ufw."
            ;;
        iptables)
            iptables -D OUTPUT -j DROP
            echo "Outgoing trafic restored with iptables."
            ;;
    esac
}

# Fonction pour gérer l'image et le conteneur Docker
manage_docker() {

    # Vérifie si le fichier docker-compose.yml existe
    if [ ! -f "$COMPOSE_FILE" ]; then
        echo -e "\nDocker Compose file not found. Please ensure $COMPOSE_FILE exists."
        exit 1
    fi

    echo -e "\nStarting NetProbe using Docker Compose..."
    docker compose -f $COMPOSE_FILE up -d --build

    # Set the network interface to promiscuous mode
    docker compose -f $COMPOSE_FILE exec netprobe ip link set enp0s2 promisc
    echo -e '\nNetProbe started.'
}

# Fonction principale pour interagir avec l'utilisateur
catch_entry() {
    echo -e "
███╗   ██╗███████╗████████╗██████╗ ██████╗  ██████╗ ██████╗ ███████╗
████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
██╔██╗ ██║█████╗     ██║   ██████╔╝██████╔╝██║   ██║██████╔╝█████╗  
██║╚██╗██║██╔══╝     ██║   ██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝  
██║ ╚████║███████╗   ██║   ██║     ██║  ██║╚██████╔╝██████╔╝███████╗
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝ 

To use NetProbe, following paquets must be installed:
- iptables or ufw
- python3 and pip
- docker and docker-compose

\n Commands list: \n n: Start NetProbe application \n b: Block outgoing network trafic with firewall (debug) \n d: Delete container and image \n u: Unblock outgoing network trafic with firewall (debug) \n r: Generate report of the informations gathered until now \n q: Quit NetProbe. Attention: Leaving by any other mean will keep NetProbe running in background and won't restore network trafic on the machine."
    while true; do
        read -n 1 -s key  # Lecture d'une seule touche sans besoin de validation avec Entrée
        case $key in
            b)
                block_outgoing
                ;;
            d)
            	echo -e "\nRemove NetProbe container and image..."
            	docker compose down
            	echo -e "\nNetProbe container and image removed successfully."
            	;;
            u)
                unblock_outgoing
                ;;
            n)
                check_and_install_requirements
            	block_outgoing
                manage_docker
                ;;
            q)
            	echo -e "\nStopping NetProbe ..."
            	docker compose stop
            	unblock_outgoing
                break
                ;;
            r) 
            	echo -e "\nCreating report ..."
                docker compose exec netprobe kill -SIGUSR1 1
             	sudo -u $SUDO_USER python3 $SCRIPT_DIR/Rapport/Generate-Report.py $SCRIPT_DIR/Output/hosts.json $SCRIPT_DIR/Output/Report  # Il faudra vérifier le path
             	echo -e "\nReport created."
             	;;
            *)
                echo -e "\nUnknown command. Commands list: \n n: Start NetProbe application \n b: Block outgoing network trafic with firewall (debug) \n d: Delete container and image \n u: Unblock outgoing network trafic with firewall (debug) \n r: Generate report of the informations gathered until now \n q: Quit NetProbe. Attention: Leaving by any other mean will keep NetProbe running in background and won't restore network trafic on the machine."
                ;;
        esac
    done
}

# Vérifie si l'utilisateur a les droits nécessaires
if [[ $EUID -ne 0 ]]; then
    echo "Please start program with root privileges (sudo)."
    exit 1
fi

# Détecte le pare-feu et lance l'interaction
detect_firewall
catch_entry

