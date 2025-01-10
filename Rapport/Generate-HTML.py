#                                                           ,,                 
#   `7MN.   `7MF'         mm   `7MM"""Mq.                  *MM                 
#     MMN.    M           MM     MM   `MM.                  MM                 
#     M YMb   M  .gP"Ya mmMMmm   MM   ,M9 `7Mb,od8 ,pW"Wq.  MM,dMMb.   .gP"Ya  
#     M  `MN. M ,M'   Yb  MM     MMmmdM9    MM' "'6W'   `Wb MM    `Mb ,M'   Yb 
#     M   `MM.M 8M""""""  MM     MM         MM    8M     M8 MM     M8 8M"""""" 
#     M     YMM YM.    ,  MM     MM         MM    YA.   ,A9 MM.   ,M9 YM.    , 
#   .JML.    YM  `Mbmmd'  `Mbmo.JMML.     .JMML.   `Ybmd9'  P^YbmdP'   `Mbmmd' 
                                                                           
                                                                           

# This python file is used to create an HTML
# file as a rapport by using the data contained
# in the Json file created by the NetProbe
# application. As this script does not modify
# the Json file, it can be used while NetProbe
# is running

import json
import sys
import plotly.express as px
from datetime import datetime

def generate_html_from_json(json_file):
    # Load JSON file
    try:
        with open(json_file, 'r') as f:
            hosts_data = json.load(f)
    except FileNotFoundError:
        print(f"Error: File {json_file} not found.")
        return
    except json.JSONDecodeError:
        print(f"Error: Incorrect JSON format in file {json_file}.")
        return
    
    # Extract data for the timelapse
    first_seen_dates = []
    mac_addresses = []
    for host in hosts_data:
        mac = host.get("MAC", "Unknown MAC address")
        first_seen = host.get("FIRST SEEN", None)

        if first_seen:
            # Convert date to datetime format
            first_seen_datetime = datetime.strptime(first_seen, "%d-%m-%Y %H:%M:%S")
            first_seen_dates.append(first_seen_datetime)
            mac_addresses.append(mac)

    # Create the interactive timelapse using Plotly
    fig = px.scatter(
        x=first_seen_dates, 
        y=mac_addresses, 
        labels={'x': 'First Seen Date', 'y': 'MAC Address'},
        title='Timelapse of First Seen Machines',
        template='plotly_dark'
    )
    plot_html = fig.to_html(full_html=False)  # Extract the HTML part of the plot

    # Start building HTML content
    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Detected hosts</title>
        <style>
            body {{
                font-family: 'Arial', sans-serif;
                background-color: #f4f7f9;
                color: #333;
                margin: 0;
                padding: 20px;
            }}
            h1 {{
                text-align: center;
                color: #2c3e50;
                font-size: 48px;
            }}
            .host {{
                margin: 20px 0;
                margin-bottom: 20px;
                padding: 20px;
                border-radius: 8px;
                background-color: #ffffff;
                border: 1px solid #ddd;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 4px 8px rgba(0, 0, 0, 0.1);
                transition: box-shadow 0.3s ease;
            }}
            .host:hover {{
                transform: translateY(-5px);
                box-shadow: 0 8px 16px rgba(0, 0, 0, 0.2);
                background-color: #87ffd5;
                transition: background-color 0.5s;
            }}
            .host-header {{
                font-size: 18px;
                font-weight: bold;
                color: #2980b9;
                cursor: pointer;
                display: flex;
                justify-content: space-between;
                align-items: center;
            }}
            .toggle-btn {{
                cursor: pointer;
                background-color: #3498db;
                color: #2c3e50;
                padding: 5px 10px;
                border-radius: 5px;
                font-size: 14px;
                transition: background-color 0.3s;
            }}
            
            .toggle-btn:hover {{
                background-color: #19fc9a;
            }}
            .toggle-content {{
                display: none;
                margin-top: 10px;
                padding-left: 10px;
                border-left: 3px solid #2980b9;
                background-color: #ecf6ff;
                border-radius: 4px;
            }}
            .protocol {{
                margin-top: 15px;
                padding: 10px;
                background-color: #fafafa;
                border-radius: 4px;
                border-left: 4px solid #7f8c8d;
            }}
            .protocol-header {{
                font-size: 16px;
                color: #16a085;
                cursor: pointer;
                font-weight: bold;
            }}
            .protocol-content {{
                display: none;
                margin-top: 10px;
                padding-left: 15px;
            }}
            p {{
                margin: 5px 0;
            }}
        </style>
        <script>
            function toggleDisplay(id) {{
                var content = document.getElementById(id);
                if (content.style.display === "none" || content.style.display === "") {{
                    content.style.display = "block";
                }} else {{
                    content.style.display = "none";
                }}
            }}
        </script>
    </head>
    <body>
        <figure class="table" style="width:100%;">
            <table class="ck-table-resized">
                <colgroup>
                    <col style="width:20%;">
                    <col style="width:60%;">
                    <col style="width:20%;">
                </colgroup>
                <tbody>
                    <tr>
                        <td>
                            <figure class="image image_resized image-style-align-left" style="width:100%;" data-ckbox-resource-id="ieckPnkjlCUn"><a href="https://www.esiea.fr/pedagogie/laboratoires/cns/" target="_blank" rel="noopener noreferrer"><img style="aspect-ratio:700/350;" src="../Rapport/images/confiance-et-securite-numerique.png" alt="Logo laboratoire CNS" width="350" height="175"></a></figure>
                            <p>&nbsp;</p>
                        </td>
                        <td>
                            <h1 style="text-align:center;">Host seen on network</h1>
                            <p style="text-align:center;">NetProbe</p>
                            <p>&nbsp;</p>
                        </td>
                        <td>
                            <figure class="image" data-ckbox-resource-id="5P-mhJ_roo8p"><img style="aspect-ratio:'400/400;" src="../Rapport/images/Logo-NetProbe-detoure.webp" alt="Logo NetProbe" width="200" height="200"></figure>
                        </td>
                    </tr>
                </tbody>
            </table>
        </figure>
        <hr>
        <p>&nbsp;</p>

        <!-- Timelapse Graph -->
        <div id="timelapse-graph">
            {plot_html}
        </div>
    """

    # For each host
    for index, host in enumerate(hosts_data):
        mac = host.get("MAC", "Unknown MAC address")
        ip = host.get("IP", "Unknown IP address")
        hostname = host.get("HOSTNAME", "Unknown hostname")
        first_seen = host.get("FIRST SEEN", "Error with timestamp")
        last_seen = host.get("LAST SEEN", "Error with timestamp")

        # For one host
        html_content += f"""
        <div class="host">
            <div class="host-header" onclick="toggleDisplay('host-{index}')">
                {mac} - {ip} - {hostname}
                <span class="toggle-btn">See details</span>
            </div>
            <div class="toggle-content" id="host-{index}">
                <p><strong>IP :</strong> {ip}</p>
                <p><strong>Hostname :</strong> {hostname}</p>
                <p><strong>First seen :</strong> {first_seen}</p>
                <p><strong>Last seen :</strong> {last_seen}</p>
        """

        # For each protocol
        protocols = host.get("PROTOCOLS", {})
        for protocol_name, protocol_data in protocols.items():
            html_content += f"""
            <div class="protocol">
                <div class="protocol-header" onclick="toggleDisplay('protocol-{protocol_name}-{index}')">
                    {protocol_name}
                </div>
                <div class="protocol-content" id="protocol-{protocol_name}-{index}">
            """
            # For each property in protocol
            for key, value in protocol_data.items():
                html_content += f"<p><strong>{key}:</strong> {value}</p>"

            html_content += "</div></div>"

        html_content += "</div></div>"

    # End of HTML file
    html_content += """
    </body>
    </html>
    """

    # Saving in HTML file
    with open(sys.argv[2], 'w') as output_file:
        output_file.write(html_content)

    print("HTML file created successfully")


# Main function
if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python Generate-HTML.py <json_file> <destination_file.html>")
    else:
        json_file = sys.argv[1]
        generate_html_from_json(json_file)

