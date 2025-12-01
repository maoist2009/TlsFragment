# 使用 Python 3.11 Slim 版本
FROM python:3.11-slim

# 关键步骤：安装编译工具 AND 加密/开发库依赖
# build-essential: 基础编译器 (gcc等)
# libssl-dev: OpenSSL 开发库 (cryptography 必须)
# libffi-dev: 外部函数接口库 (cffi 必须)
# python3-dev: Python 头文件 (编译 Python 扩展必须)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# 复制依赖文件
COPY pyproject.toml poetry.lock ./

# 安装 Poetry
RUN pip install poetry

# 关键配置：禁用 Poetry 的虚拟环境创建
# 让依赖直接安装在容器的系统 Python 环境中，避免路径问题
RUN poetry config virtualenvs.create false

# 安装项目依赖
RUN poetry install --only main --no-interaction

# 复制其余项目代码
COPY . .

# 暴露端口
EXPOSE 2500

# 启动命令
CMD ["python", "run.py"]
