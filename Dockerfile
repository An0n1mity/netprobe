# Stage 1: Build Stage
FROM alpine:latest AS build

# Install build dependencies
RUN apk add --no-cache \
    g++ \
    cmake \
    make \
    libpcap-dev \
    linux-headers \
    git \
    wget \
    curl \
    jsoncpp-dev \
    boost-dev

# Install glibc
RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub \
    && wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.35-r1/glibc-2.35-r1.apk \
    && apk add --no-cache --allow-untrusted glibc-2.35-r1.apk \
    && rm glibc-2.35-r1.apk

# Install PcapPlusPlus
RUN wget https://github.com/seladb/PcapPlusPlus/archive/v24.09.tar.gz \
    && tar -xf v24.09.tar.gz \
    && rm v24.09.tar.gz \
    && cd PcapPlusPlus-24.09 \
    && cmake -S . -B build \
    && cmake --build build \
    && cmake --install build --prefix /usr/local

# Define the working directory
WORKDIR /netprobe

# Copy the project files into the container
COPY Analyzers /netprobe/Analyzers
COPY Layers /netprobe/Layers
COPY Hosts /netprobe/Hosts
COPY CaptureManager.hpp /netprobe/CaptureManager.hpp
COPY main.cpp /netprobe/main.cpp
COPY CMakeLists.txt /netprobe/CMakeLists.txt
COPY FindPCAP.cmake /netprobe/FindPCAP.cmake

# Build the application
RUN mkdir build \
    && cd build \
    && cmake -DCMAKE_PREFIX_PATH=/usr/local .. \
    && cmake --build .

# Stage 2: Runtime Stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache \
    libpcap \
    jsoncpp \
    boost-system \
    boost-thread

# Install glibc
RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub \
    && wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.35-r1/glibc-2.35-r1.apk \
    && apk add --no-cache --allow-untrusted glibc-2.35-r1.apk \
    && rm glibc-2.35-r1.apk

# Copy the built application from the build stage
COPY --from=build /netprobe/Hosts/manuf /netprobe/build/manuf
COPY --from=build /netprobe/build /netprobe/build

# Define the working directory
WORKDIR /netprobe

# Create output directory
RUN mkdir output

# Run the application
CMD ["./build/netprobe"]