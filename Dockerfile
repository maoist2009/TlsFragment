# 使用一个轻量级的 Python 镜像作为基础
FROM python:3.11-slim

# 设置容器内的工作目录
WORKDIR /app

# 复制 Poetry 配置文件和依赖锁文件
COPY pyproject.toml poetry.lock ./

# 安装 Poetry 包管理器
RUN pip install poetry

# 确保 Poetry 缓存不影响构建速度，并解决所有依赖
# --only main 只安装主要依赖，不安装开发依赖
RUN poetry install --only main --no-interaction

# 复制所有项目代码和配置文件
COPY . .

# 暴露端口 (TlsFragment 默认代理端口为 2500)
EXPOSE 2500

# 定义容器启动时的默认命令
# run.py 是该项目的主要启动文件
# 注意：配置（如 TLSfrag 模式）将在 docker-compose.yml 中传入
CMD ["python", "run.py"]
