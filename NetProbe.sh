#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_VOLUME_PATH="$SCRIPT_DIR/Output"
CONTAINER_VOLUME_PATH="/usr/src/app/Output"
COMPOSE_FILE="$SCRIPT_DIR/docker-compose.yml"
cd $SCRIPT_DIR

# Vérification de la commande docker compose
if docker compose version >/dev/null 2>&1; then
    echo "Docker Compose v2 est disponible."
    DOCKER_COMPOSE_VERSION=false
elif docker-compose -v >/dev/null 2>&1; then
    echo "Docker Compose v1 est disponible."
    DOCKER_COMPOSE_VERSION=true
else
    echo "Aucune version de Docker Compose n'est disponible sur ce système."
    exit 1
fi

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

# Fonction pour gérer l'image et le conteneur Docker
manage_docker() {

    if [ "$DOCKER_COMPOSE_VERSION" = true ]; then
    	if [ ! -f "$COMPOSE_FILE" ]; then
	    echo -e "\nDocker Compose file not found. Please ensure $COMPOSE_FILE exists."
	    exit 1
    	fi
    	
    	echo -e "\nStarting NetProbe using Docker Compose..."
    	docker-compose -f $COMPOSE_FILE build
    	docker-compose -f $COMPOSE_FILE up -d
    	
    	# Set the network interface to promiscuous mode
    	#docker-compose -f $COMPOSE_FILE exec netprobe ip link set enp0s2 promisc
    	echo -e '\nNetProbe started.'
    else
    	# Vérifie si le fichier docker-compose.yml existe
        if [ ! -f "$COMPOSE_FILE" ]; then
	    echo -e "\nDocker Compose file not found. Please ensure $COMPOSE_FILE exists."
	    exit 1
    	fi

    	echo -e "\nStarting NetProbe using Docker Compose..."
    	docker compose -f $COMPOSE_FILE up -d --build

    	# Set the network interface to promiscuous mode
    	#docker compose -f $COMPOSE_FILE exec netprobe ip link set enp0s2 promisc
    	echo -e '\nNetProbe started.'
    fi
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
- docker

\n Commands list: \n n: Start NetProbe application \n d: Delete container and image \n r: Generate report of the informations gathered until now \n q: Quit NetProbe. Attention: Leaving by any other mean will keep NetProbe running in background and won't restore network trafic on the machine."
    while true; do
        read -n 1 -s key  # Lecture d'une seule touche sans besoin de validation avec Entrée
        case $key in
            d)
            	echo -e "\nRemove NetProbe container and image..."
            	if [ "$DOCKER_COMPOSE_VERSION" = true ]; then
            	    docker-compose down
            	else
            	    docker compose down
            	fi
            	docker rmi netprobe-image
            	echo -e "\nNetProbe container and image removed successfully."
            	;;
            n)
                check_and_install_requirements
                manage_docker
                ;;
            q)
            	echo -e "\nStopping NetProbe ..."
            	if [ "$DOCKER_COMPOSE_VERSION" = true ]; then
            	    docker-compose stop
            	else
            	    docker compose stop
            	fi
                break
                ;;
            r) 
            	echo -e "\nCreating report ..."
            	if [ "$DOCKER_COMPOSE_VERSION" = true ]; then
            	    docker-compose exec netprobe kill -SIGUSR1 1
            	else
            	    docker compose exec netprobe kill -SIGUSR1 1
            	fi
             	sudo -u $SUDO_USER python3 $SCRIPT_DIR/Rapport/Generate-Report.py $SCRIPT_DIR/Output/hosts.json $SCRIPT_DIR/Output/Report  # Il faudra vérifier le path
             	echo -e "\nReport created."
             	;;
            *)
                echo -e "\nUnknown command. Commands list: \n n: Start NetProbe application \n d: Delete container and image \n r: Generate report of the informations gathered until now \n q: Quit NetProbe. Attention: Leaving by any other mean will keep NetProbe running in background and won't restore network trafic on the machine."
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
