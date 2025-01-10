#!/bin/bash

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HOST_VOLUME_PATH="$SCRIPT_DIR/Output"
CONTAINER_VOLUME_PATH="/usr/src/app/Output"
cd $SCRIPT_DIR

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
    IMAGE_NAME="netprobe"

    # Vérifie si l'image existe
    if ! docker image inspect $IMAGE_NAME &>/dev/null; then
        echo -e "\n$IMAGE_NAME image do not exist. Creation in progress..."

        docker build -t $IMAGE_NAME -f $SCRIPT_DIR/Dockerfile . &&
        echo -e "\nImage $IMAGE_NAME created." &&
        echo 'Starting NetProbe...'
        docker run --name $IMAGE_NAME-container --network host --privileged --cpus="4" -v "$HOST_VOLUME_PATH:$CONTAINER_VOLUME_PATH" -d $IMAGE_NAME &>/dev/null
        docker exec -it netprobe-container ip link set enp0s2 promisc
        echo -e '\nNetProbe started'
    else
        docker rm -f $IMAGE_NAME-container &>/dev/null
        echo -e "\n$IMAGE_NAME image already exist. Starting container..."
        docker run --name $IMAGE_NAME-container --network host --privileged --cpus="4" -v "$HOST_VOLUME_PATH:$CONTAINER_VOLUME_PATH" -d $IMAGE_NAME &>/dev/null
        docker exec -it netprobe-container ip link set enp0s2 promisc
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

\n Commands list: \n n: Start NetProbe application \n b: Block outgoing network trafic with firewall (debug) \n d: Delete container and image \n u: Unblock outgoing network trafic with firewall (debug) \n r: Generate report of the informations gathered until now \n q: Quit NetProbe. Attention: Leaving by any other mean will keep NetProbe running in background and won't restore network trafic on the machine."
    while true; do
        read -n 1 -s key  # Lecture d'une seule touche sans besoin de validation avec Entrée
        case $key in
            b)
                block_outgoing
                ;;
            d)
            	echo -e "\nRemove NetProbe container and image..."
            	docker remove netprobe-container
            	docker rmi netprobe
            	echo -e "\nNetProbe container and image removed successfully."
            	;;
            u)
                unblock_outgoing
                ;;
            n)
            	block_outgoing
                manage_docker
                ;;
            q)
            	echo -e "\nStopping NetProbe ..."
            	docker stop netprobe-container &>/dev/null
            	unblock_outgoing
                break
                ;;
            r) 
            	echo -e "\nInstalling dependency ..."
            	sudo -u $SUDO_USER pip install -r requirements.txt
            	echo -e "\nDependency installed. \nCreating report ..."
            	docker exec -it netprobe-container kill -SIGUSR1 1
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

