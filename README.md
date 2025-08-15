# TLSFragment使用指南

[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/maoist2009/TlsFragment)

[![F-Droid Version](https://img.shields.io/f-droid/v/org.maoist2009.tlsfragment)](https://f-droid.org/packages/org.maoist2009.tlsfragment/)

## 交流群

可用discussions

[matrix反馈空间](https://matrix.to/#/#tlsp_public:matrix.org)
也可直接加入公开群

+ 配置优化（如可用ip查找，mode变更等）： <https://matrix.to/#/!WvZLqiyvvsVSCrsuWt:matrix.org?via=matrix.org>
+ tlsp程序本身问题：<https://matrix.to/#/!GvJhmmjpGqeNCPyMyE:matrix.org?via=matrix.org>
+ 关于代理配置问题： <https://matrix.to/#/!bRNRPJmWSBrWyuQbCd:matrix.org?via=matrix.org>

有一个私密群

## 安装

可以作为模块安装：

```shell
python -m build --wheel --no-isolation
python -m installer dist/*.whl
```

## 运行

作为模块安装后可以直接运行 `tls_fragment`。（暂不支持）

或者将仓库克隆下来之后运行 `run.py`。

### TLSFragment原理

#### TLSfrag

将TCP连接Client的第一个包（这个包一般来说是TLS ClientHello，一般应用层不会分片）在TLS层和TCP层分别进行分片，将sni拆入多个包以绕过gfw。

#### FAKEdesync

利用ttl发送假包，扰乱gfw的DPI。

为了避免管理员/root权限的需要。

+ 在Windows上，使用`TransmitFile`函数（由于TransmitFIle被限制最多同时运行2个，性能较差）
+ 在linux上，使用管道

通过重传机制发送。

### 异步方式

使用`threading`（多线程），有一个`asyncio`协程版本目前废弃，原因是默认版本无法支持自代理DoH。

### 安装使用

#### 运行

```bash
git clone git@github.com:maoist2009/TlsFragment.git
pip install poetry
poetry init
python run.py
```

也可以编译后开机自启动：

```bash
BUILD_WINDOWS
```

之后请为`/dist/proxy.exe`创建快捷方式，复制到`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`

#### 浏览器使用

建议分流

安装`Proxy SwitchyOmega`和`Gooreplacer`，分别导入配置文件`OmegaOptions.bak`和`gooreplacer.json`（android请使用kiwi浏览器等）

### 配置方式

#### 全局选项

##### 公共


| 项名                | 简单解释                            | 是否可以域名自定义 |
| ------------------- | ----------------------------------- | ------------------ |
| `output_data`       | 是否输出包内容                      | 否                 |
| `listen_PORT`       | 代理运行端口                        | 否                 |
| `DOH_PORT`          | 代理使用DoH代理端口                 | 否                 |
| `my_socket_timeout` | 接/发包超时时间                     | 否                 |
| `doh_server`        | doh服务器（请在 domains 里指定 ip） | 否                 |
| `DNS_log_every`     | dns缓存频率                         | 否                 |
| `TTL_log_every`     | ttl缓存频率                         | 否                 |
| `num_TCP_fragment`  | 无sni段TCP分块数                    | 是                 |
| `TCP_frag`          | sni所在tcp层大致段分块长度          | 是                 |
| `method`            | 操作方法，见下文模式                | 是                 |
| `IPtype`            | dns查询ip默认类型（无则换）         | 是                 |

##### `TLSfrag`模式


| 项名               | 简单解释           | 是否可以域名自定义 |
| ------------------ | ------------------ | ------------------ |
| `num_TLS_fragment` | 无sni段TLS分块数   | 是                 |
| `TLS_frag`         | sni在tls层分块长度 | 是                 |

##### `FAKEdesync`模式


| 项名                    | 简单解释                                 | 是否可以域名自定义 |
| ----------------------- | ---------------------------------------- | ------------------ |
| `FAKE_packet`           | 发送的假包内容                           | 是                 |
| `FAKE_ttl`              | 假包使用的ttl，填`query`表示自动二分查询 | 是                 |
| `FAKE_ttl_auto_timeout` | cookie缓存时间                           | 是                 |
| `FAKE_sleep`            | 发送假包后改为真包的间隔时间             | 是                 |

其中，域名自定义指的是在`domians.xxxx.com`下也有此配置项，且该处配置优先。

#### `domains`下有其他项：


| 项名       | 简单解释            |
| ---------- | ------------------- |
| `IP`       | IP地址              |
| `port`     | 端口（不填默认443） |
| `IPcache`  | 是否缓存            |
| `TTLcache` | 是否缓存IP对应TTL   |

### 域名匹配规则

如果特定域名（若有多个取最长的，再有多个问python的sort）为sni的子串，则取。（使用AC自动机实现以应对巨大列表）
支持首尾匹配，实际上塞入AC自动机的是：`^www.domain.genshin.mihoyo.com$`

### IP查找

建议使用[HTTPS_IP_finder](https://github.com/maoist2009/HTTPS_IP_finder)
我本人也会维护已知的被ip封锁的网站。

### IP重定向

支持IP（段）重定向到ip，默认链式跳转，如果要求配置不链式，在结果ip字符串前添加`^`。
