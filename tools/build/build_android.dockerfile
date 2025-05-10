FROM debian:11

RUN : \
    && apt-get update \
    \
    # Buildozer \
    && apt-get install -y --no-install-recommends autoconf automake build-essential \
               ccache cmake openjdk-17-jdk gettext git libffi-dev libltdl-dev libssl-dev \
               libtool patch pkg-config unzip zip zlib1g-dev \
    \
    # Python 3.8 \
    && apt-get -yq install wget build-essential libreadline-dev \
                   libncursesw5-dev libssl-dev libsqlite3-dev tk-dev \
                   libgdbm-dev libc6-dev libbz2-dev libffi-dev zlib1g-dev \
    && ( \
        cd /tmp \
        && wget https://www.python.org/ftp/python/3.8.12/Python-3.8.12.tgz \
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
    # Cleanup \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

RUN echo "#################################################"
RUN echo "Copy the GitHub repo to the Docker container"
RUN echo "COPY . ${env_workspace_directory}"
COPY . ${env_workspace_directory}
