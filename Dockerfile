################################################################################
# Dockerfile — Recon Manager
# Immagine pronta all'uso con tutte le dipendenze pre-installate
#
# AUTORE: Scotti Davide - Università Statale degli Studi di Milano
# VERSIONE: 2.0
#
# USO: docker build -t recon-manager .
#       docker run --rm -it --net=host -v $(pwd)/output:/app/output recon-manager
################################################################################

FROM kalilinux/kali-rolling:latest

LABEL maintainer="Scotti Davide - Università Statale di Milano"
LABEL description="Recon Manager - Strumento di ricognizione per pentesting etico"
LABEL version="2.0"

# Evita prompt interattivi durante l'installazione
ENV DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Rome

# Layer 1: apt update (cache layer separato)
RUN apt-get update -qq && \
    apt-get install -y -qq \
        nmap \
        curl \
        wget \
        python3 \
        python3-pip \
        graphviz \
        dnsutils \
        netcat-openbsd \
        iputils-ping \
        nikto \
        enum4linux \
        snmp \
        whois \
        hydra \
        git \
        openssh-client \
        --no-install-recommends && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Layer 2: Python dipendenze
RUN pip3 install --quiet reportlab pyyaml

# Layer 3: testssl.sh + nmap scripts
RUN wget -q "https://github.com/drwetter/testssl.sh/releases/latest/download/testssl.sh" \
    -O /usr/local/bin/testssl.sh && \
    chmod +x /usr/local/bin/testssl.sh && \
    nmap --script-updatedb > /dev/null 2>&1 || true && \
    wget -q "https://raw.githubusercontent.com/vulnersCom/nmap-vulners/master/vulners.nse" \
    -O /usr/share/nmap/scripts/vulners.nse 2>/dev/null || echo "Warning: vulners.nse download failed (non-blocking)"

# Layer 4: Directory di lavoro
RUN mkdir -p /app/sessioni /app/output /root/.cache/recognize_nvd && \
    echo '{}' > /root/.cache/recognize_nvd/cvss_cache.json

WORKDIR /app

# Layer 5: Codice (ultimo per caching massimo)
COPY *.sh /app/
RUN chmod +x /app/*.sh

# Copia config se presente (non bloccante se assente)
COPY recon.conf* /app/

# Entrypoint flessibile: bash di default, manager.sh come comando
ENTRYPOINT ["/bin/bash"]
CMD ["/app/manager.sh"]