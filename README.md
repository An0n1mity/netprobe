# NetProbe

**NetProbe** is a network mapping application designed to passively capture and analyze network traffic. The application utilizes various protocol analyzers to gather information about devices and their interactions on the network.

## Features

- **Packet Capture**: Captures network packets using the PcapPlusPlus library.
- **Protocol Analysis**: Supports analysis for multiple protocols including ARP, DHCP, STP, and more.
- **Host Management**: Maintains a database of hosts and updates their information based on captured packets.
- **Signal Handling**: Dumps host information to a file upon receiving specific signals.

## Components

- **CaptureManager**: Manages packet capture and distribution to analyzers.
- **Analyzers**: Abstract base class for analyzing network packets. Derived classes implement specific protocol analysis.
- **HostManager**: Manages host information and updates the JSON representation of hosts.

## Getting Started

### Prerequisites

- CMake 3.5.0 or higher
- Docker
- PcapPlusPlus
- Boost
- JSONCPP

### Build the Project from Source

1. Clone the repository:
    ```sh
    git clone https://github.com/an0n1mity/cartographie-passive.git
    cd cartographie-passive
    ```

2. Create a build directory and navigate into it:
    ```sh
    mkdir build
    cd build
    ```

3. Run CMake to configure the project:
    ```sh
    cmake ..
    ```

4. Build the project:
    ```sh
    make
    ```

### Run the Application using Docker Compose

1. Ensure Docker is installed and running on your system.

2. Use Docker Compose to build and run the application:
    ```sh
    docker-compose up
    ```

## Documentation

- **[Process of the Application](docs/process.md)**: Overview of the application components and process flow.

For more information, visit the [GitHub repository](https://github.com/an0n1mity/cartographie-passive).

## License

This project is licensed under the MIT License - see the LICENSE file for details.