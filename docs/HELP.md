# TLSFragment使用指南

## TLSFragment原理

将TCP连接Client的第一个包（这个包一般来说是TLS ClientHello，一般应用层不会分片）在TLS层和TCP层分别进行分片，将sni拆入多个包以绕过gfw。

## 异步方式

使用`threading`（多线程），有一个`asyncio`协程版本于`asyncio`分支，但无明显优势，疑似有劣势。

桌面端直接使用`threading`版，android酌情使用`asyncio`（android体验都不好）

## 安装使用

### 运行

```bash
git clone git@github.com:maoist2009/TlsFragment.git
pip install -r requirements.txt
python server.py
```

也可以编译后开机自启动：

```bash
BUILD_WINDOWS
```

之后请为`/dist/proxy.exe`创建快捷方式，复制到`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`

### 浏览器使用

建议分流

安装`Proxy SwitchOmega`和`Gooreplacer`，分别导入配置文件`OmegaOptions.bak`和`gooreplacer.json`（android请使用kiwi浏览器等）

## 配置方式

有如下配置项


| 项名                | 简单解释                    | 是否可以域名自定义 |
| ------------------- | --------------------------- | ------------------ |
| `output_data`       | 是否输出包内容              | 否                 |
| `listen_PORT`       | 代理运行端口                | 否                 |
| `DOH_PORT`          | 代理使用DoH代理端口         | 否                 |
| `num_TCP_fragment`  | 无sni段TCP分块数            | 是                 |
| `num_TLS_fragment`  | 无sni段TLS分块数            | 是                 |
| `TCP_frag`          | sni所在tcp层大致段分块长度  | 是                 |
| `TLS_frag`          | sni在tls层分块长度          | 是                 |
| `my_socket_timeout` | 接/发包超时时间             | 否                 |
| `doh_server`        | doh服务器                   | 否                 |
| `DNS_log_every`     | dns缓存频率                 | 否                 |
| `IPtype`            | dns查询ip默认类型（无则换） | 是                 |

其中，域名自定义指的是在`domians.xxxx.com`下也有此配置项，且该处配置优先。

特别的，`domains`下有其他项：


| 项名      | 简单解释            |
| --------- | ------------------- |
| `IP`      | IP地址              |
| `port`    | 端口（不填默认443） |
| `IPcache` | 是否缓存            |

## 域名匹配规则

如果特定域名（若有多个取最长的，再有多个问python的sort）为sni的子串，则取。（使用AC自动机实现以应对巨大列表）

## IP查找

建议使用[HTTPS_IP_finder](https://github.com/maoist2009/HTTPS_IP_finder)
我本人也会维护已知的被ip封锁的网站。

## 细节看`server.py`
