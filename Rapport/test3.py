import json
import os
import sys
from datetime import datetime
import plotly.graph_objects as go

def generate_device_report(host, output_dir, menu_file_name="menu.html"):
    """Génère un fichier HTML pour un appareil donné."""
    device_file = os.path.join(output_dir, f"device_{host['MAC'].replace(':', '')}.html")
    
    hostname = host.get('HOSTNAME', 'Inconnu')
    ip_address = host.get('IP', 'Non renseignée')
    first_seen = host['FIRST SEEN']
    last_seen = host.get('LAST SEEN', 'Non renseignée')

    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Détails de l'appareil {hostname}</title>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 800px; margin: 0 auto; padding: 20px; }}
            h1, h2, h3 {{ color: #2c3e50; }}
            .protocol {{ background-color: #e9ecef; border-left: 3px solid #007bff; padding: 10px; margin-top: 10px; }}
            table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
            th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
            th {{ background-color: #f2f2f2; }}
            .button {{ background-color: #007bff; color: white; border: none; padding: 10px 20px; text-align: center; text-decoration: none; display: inline-block; font-size: 14px; border-radius: 5px; }}
            .button:hover {{ background-color: #0056b3; }}
        </style>
    </head>
    <body>
        <h1>Détails de l'appareil {hostname} ({host['MAC']})</h1>
        <table>
            <tr><th>Adresse MAC</th><td>{host['MAC']}</td></tr>
    """
    if 'HOSTNAME' in host:
        html_content += f"<tr><th>Nom de domaine</th><td>{host['HOSTNAME']}</td></tr>"
    html_content += f"""
            <tr><th>Adresse IP</th><td>{ip_address}</td></tr>
            <tr><th>Première apparition</th><td>{first_seen}</td></tr>
            <tr><th>Dernière apparition</th><td>{last_seen}</td></tr>
        </table>
        <h2>Protocoles détectés</h2>
    """

    protocols = host.get('PROTOCOLS', {})
    if protocols:
        for protocol_name, protocol_entries in protocols.items():
            html_content += f"<div class=\"protocol\"><h3>{protocol_name}</h3>"
            for entry in protocol_entries:
                html_content += "<table>"
                for key, value in entry.items():
                    html_content += f"<tr><th>{key}</th><td>{value}</td></tr>"
                html_content += "</table>"
            html_content += "</div>"
    else:
        html_content += "<p>Aucun protocole détecté.</p>"

    html_content += f"""
        <a href="{menu_file_name}" class="button">Retour au menu</a>
    </body>
    </html>
    """

    with open(device_file, 'w') as f:
        f.write(html_content)

    return os.path.basename(device_file)

def generate_menu_report(json_file, output_dir):
    """Génère un fichier HTML principal avec un tableau interactif des appareils détectés."""
    
    current_datetime = datetime.now().strftime("%d-%m-%Y %H:%M:%S")
    with open(json_file, 'r') as f:
        data = json.load(f)

    os.makedirs(output_dir, exist_ok=True)

    # Préparer les données pour le graphique
    mac_addresses = [host['MAC'] for host in data]
    first_seen_dates = [datetime.strptime(host['FIRST SEEN'], "%d-%m-%Y %H:%M:%S") for host in data]

    # Trier les données pour afficher les appareils par date de première apparition
    sorted_data = sorted(zip(first_seen_dates, mac_addresses), key=lambda x: x[0])

    sorted_mac_addresses = [mac for _, mac in sorted_data]
    sorted_first_seen_dates = [dt for dt, _ in sorted_data]

    # Créer le graphique avec une échelle de temps
    fig = go.Figure()
    fig.add_trace(go.Scatter(x=sorted_first_seen_dates, y=sorted_mac_addresses, mode='markers', name='Appareils détectés'))
    fig.update_layout(title="Ordre de détection des appareils", xaxis_title="Date", yaxis_title="Adresse MAC",
                      xaxis=dict(type="date"), height=600, width=1200)
    plot_html = fig.to_html(full_html=False)

    # Générer les fichiers HTML individuels
    links = []
    for host in data:
        file_name = generate_device_report(host, output_dir)
        mac = host.get("MAC", "Non renseignée")
        ip = host.get("IP", None)
        hostname = host.get("HOSTNAME", None)
        
        # Construire le display_name dynamiquement
        display_name_parts = [part for part in [mac, ip, hostname] if part]  # Exclut les valeurs `None` ou vides
        display_name = " - ".join(display_name_parts)
        
        links.append((display_name, file_name))

    # Préparer les données pour le tableau
    table_rows = ""
    for display_name, file_name in links:
        # Gestion des colonnes dynamiquement (split en fonction des colonnes existantes)
        parts = display_name.split(" - ")
        mac = parts[0]
        ip = parts[1] if len(parts) > 1 else ""
        hostname = parts[2] if len(parts) > 2 else ""
        
        table_rows += f"<tr onclick=\"window.location.href='{file_name}';\" style=\"cursor: pointer;\">"
        table_rows += f"<td>{mac}</td><td>{ip}</td><td>{hostname}</td></tr>"

    # Générer le contenu HTML principal avec tableau interactif
    menu_html = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Menu de cartographie réseau</title>
        <link rel="stylesheet" href="https://cdn.datatables.net/1.13.5/css/jquery.dataTables.min.css">
        <script src="https://code.jquery.com/jquery-3.6.0.min.js"></script>
        <script src="https://cdn.datatables.net/1.13.5/js/jquery.dataTables.min.js"></script>
        <style>
            body {{ font-family: Arial, sans-serif; line-height: 1.6; color: #333; max-width: 1200px; margin: 0 auto; padding: 20px; }}
            header {{ background-color: #2c3e50; color: white; padding: 20px 10px; display: flex; align-items: center; justify-content: space-between; border-bottom: 3px solid #007bff; }}
            header img {{ height: 150px; object-fit: contain; }}
            header h1 {{ margin: 0; font-size: 24px; }}
            header p {{ margin: 5px 0; font-size: 14px; }}
            table {{ width: 100%; margin-top: 20px; }}
        </style>
    </head>
    <body>
        <header>
            <div style="flex: 1; text-align: left;">
                <img src="../Rapport/images/confiance-et-securite-numerique.png" alt="Logo CNS">
            </div>
            <div style="flex: 2; text-align: center;">
                <h1>NetProbe</h1>
                <p>Rapport généré le : {current_datetime}</p>
                <p style="font-style: italic;">Découvrez les appareils connectés et leurs activités réseau</p>
            </div>
            <div style="flex: 1; text-align: right;">
                <img src="../Rapport/images/Logo-NetProbe-detoure.webp" alt="Logo NetProbe">
            </div>
        </header>
        <h2>Chronologie des appareils détectés</h2>
        {plot_html}
        <h2>Appareils détectés</h2>
        <table id="devices" class="display">
            <thead>
                <tr>
                    <th>Adresse MAC</th>
                    <th>Adresse IP</th>
                    <th>Hostname</th>
                </tr>
            </thead>
            <tbody>
                {table_rows}
            </tbody>
        </table>
        <script>
            $(document).ready(function() {{
                $('#devices').DataTable();
            }});
        </script>
    </body>
    </html>
    """

    # Écrire le fichier principal
    menu_file = os.path.join(output_dir, "menu.html")
    with open(menu_file, 'w') as f:
        f.write(menu_html)

    print(f"Rapport principal généré : {menu_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python generate_reports.py <input_json_file> <output_directory>")
        sys.exit(1)

    image_path_cns = os.path.abspath("../Rapport/images/confiance-et-securite-numerique.png")
    image_path_netprobe = os.path.abspath("../Rapport/images/Logo-NetProbe-detoure.webp")
    input_file = sys.argv[1]
    output_directory = sys.argv[2]
    generate_menu_report(input_file, output_directory)


