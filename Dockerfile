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
WORKDIR /cartographie-passive

# Copy the project files into the container
COPY Analyzers /cartographie-passive/Analyzers
COPY Layers /cartographie-passive/Layers
COPY Hosts /cartographie-passive/Hosts
COPY CaptureManager.hpp /cartographie-passive/CaptureManager.hpp
COPY main.cpp /cartographie-passive/main.cpp
COPY CMakeLists.txt /cartographie-passive/CMakeLists.txt
COPY FindPCAP.cmake /cartographie-passive/FindPCAP.cmake

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
COPY --from=build /cartographie-passive/Hosts/manuf /cartographie-passive/build/manuf
COPY --from=build /cartographie-passive/build /cartographie-passive/build

# Define the working directory
WORKDIR /cartographie-passive

# Run the application
CMD ["./build/cartographie-passive"]