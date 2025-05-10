FROM debian:8

RUN : \
    && echo "deb http://archive.debian.org/debian jessie main" > /etc/apt/sources.list \
    && echo "deb http://archive.debian.org/debian-security jessie/updates main" >> /etc/apt/sources.list \
    # Add jessie-backports, needed for newer libssl for python \
    && echo "deb http://archive.debian.org/debian jessie-backports main" >> /etc/apt/sources.list \
    && echo "Acquire::Check-Valid-Until \"false\";" > /etc/apt/apt.conf \
    \
    # Update \
    && apt-get update \
    \
    # Python 3.8 \
    && apt-get -yq install --force-yes wget build-essential libreadline-gplv2-dev \
                   libncursesw5-dev libssl1.0.0=1.0.2\* libssl-dev=1.0.2\* \
                   libsqlite3-dev tk-dev libgdbm-dev libc6-dev libbz2-dev \
                   libffi-dev zlib1g-dev \
    && ( \
        cd /tmp \
        && wget --no-check-certificate https://www.python.org/ftp/python/3.8.12/Python-3.8.12.tgz \
                -O Python-3.8.12.tgz \
        && tar xzf Python-3.8.12.tgz \
        && rm Python-3.8.12.tgz \
        && ( \
            cd Python-3.8.12 \
            && ./configure --prefix=/usr --enable-optimizations --enable-shared \
            && make install -j $(nproc) \
            && ldconfig \
        ) \
        && rm -rf Python-3.8.12 \
    ) \
    \
    # Other stuff \
    && apt-get -yq --force-yes install \
        git \
        # For headless rendering \
        xvfb \
        # For Kivy \
        libmtdev1 \
    \
    # Hacking libgl: replacing libgl1-mesa-glx -> libgl1-mesa-swx11 \
    && apt-get -yq --force-yes install mesa-common-dev \
    && dpkg -r --force-depends libgl1-mesa-glx libgl1-mesa-dev \
    && ( \
        cd /tmp \
        && apt-get download libgl1-mesa-swx11 libgl1-mesa-swx11-dev libosmesa6 \
        && dpkg -i *.deb \
    ) \
    \
    # Cleanup \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
