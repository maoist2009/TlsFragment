# 1. 使用完整版 Python 镜像 (预装 gcc, git, openssl 等所有工具)
# 这会增加镜像体积，但能解决绝大多数编译错误
FROM python:3.11

WORKDIR /app

# 2. 只复制配置文件，【不要】复制 poetry.lock
# 这样 Poetry 会忽略旧的锁定文件，重新为 Linux 环境解析依赖
COPY pyproject.toml ./

# 3. 安装 Poetry
RUN pip install poetry

# 4. 禁用虚拟环境
RUN poetry config virtualenvs.create false

# 5. 安装依赖 (不再使用 lock 文件)
# 注意：这里去掉了 --only main，以防万一缺少某些隐式依赖
# 增加了 -v (verbose) 参数，如果万一再报错，我们能看到具体错误原因
RUN poetry install --no-interaction --no-root -v

# 6. 复制项目代码
COPY . .

# 暴露端口
EXPOSE 2500

# 启动命令
CMD ["python", "run.py"]
