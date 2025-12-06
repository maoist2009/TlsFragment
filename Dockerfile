# -----------------------------------------------------------
# 第一阶段：构建环境 (Builder)
# 用于编译和安装依赖，体积较大，最终会被丢弃
# -----------------------------------------------------------
FROM python:3.11-slim as builder

WORKDIR /app

# 安装编译所需的系统工具 (gcc, ssl, ffi等)
# 这一步是为了解决之前的报错
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

# 只复制配置文件，忽略旧的 lock 文件
COPY pyproject.toml ./

# 安装 Poetry
RUN pip install poetry

# 配置 Poetry 将虚拟环境创建在项目目录内 (.venv)
# 这样方便我们在下一个阶段直接复制整个文件夹
RUN poetry config virtualenvs.in-project true

# 安装依赖
RUN poetry install --no-interaction --no-root

# -----------------------------------------------------------
# 第二阶段：运行环境 (Final)
# 最终产出的镜像，基于 slim 版本，仅包含运行所需文件
# -----------------------------------------------------------
FROM python:3.11-slim

WORKDIR /app

# 关键步骤：从第一阶段复制生成的虚拟环境 (.venv)
COPY --from=builder /app/.venv /app/.venv

# 复制源代码
COPY . .

# 设置环境变量：将虚拟环境的 bin 目录加入 PATH
# 这样直接输入 python 就是使用虚拟环境里的 python
ENV PATH="/app/.venv/bin:$PATH"

# 暴露端口
EXPOSE 2500

# 启动命令
CMD ["python", "run.py"]
