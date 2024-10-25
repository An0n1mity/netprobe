# Utiliser Alpine comme image de base
FROM alpine:latest

# Installer les dépendances de base
RUN apk add --no-cache \
    g++ \
    cmake \
    make \
    libpcap-dev \
    linux-headers \
    git \
    wget \
    curl \
    jsoncpp-dev

# Installer glibc
RUN wget -q -O /etc/apk/keys/sgerrand.rsa.pub https://alpine-pkgs.sgerrand.com/sgerrand.rsa.pub \
    && wget https://github.com/sgerrand/alpine-pkg-glibc/releases/download/2.35-r1/glibc-2.35-r1.apk \
    && apk add --no-cache --allow-untrusted glibc-2.35-r1.apk \
    && rm glibc-2.35-r1.apk

# Installer PcapPlusPlus
RUN wget https://github.com/seladb/PcapPlusPlus/archive/v24.09.tar.gz \
    && tar -xf v24.09.tar.gz \
    && rm v24.09.tar.gz \
    && cd PcapPlusPlus-24.09 \
    && cmake -S . -B build \
    && cmake --build build \
    && cmake --install build --prefix /usr/local

# Définir le répertoire de travail
WORKDIR /cartographie-passive

# Copier les fichiers du projet dans le conteneur
COPY Analyzers /cartographie-passive/Analyzers
COPY Layers /cartographie-passive/Layers
COPY Hosts /cartographie-passive/Hosts
COPY CaptureManager.hpp /cartographie-passive/CaptureManager.hpp
COPY main.cpp /cartographie-passive/main.cpp

COPY CMakeLists.txt /cartographie-passive/CMakeLists.txt
COPY FindPCAP.cmake /cartographie-passive/FindPCAP.cmake

# Construire l'application
RUN mkdir build \
    && cd build \
    && cmake -DCMAKE_PREFIX_PATH=/usr/local .. \
    && cmake --build .

# Lancer l'application
CMD ["./build/cartographie-passive"]