# [English](/README-en.md) [Russian](/README-ru.md) [Chinese](/README.md)

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

有一个私密群，或许可以私信我尝试加入？

## 安装

<!-- 暂不支持
可以作为模块安装：

```shell
python -m build --wheel --no-isolation
python -m installer dist/*.whl
```
-->

## 运行

作为模块安装后可以直接运行 `tls_fragment`。（暂不支持）

或者将仓库克隆下来之后运行 `run.py`。

Windows和Android提供GUI客户端，Windows客户端在[隔壁](https://github.com/maoist2009/TlsFragment_Windows)

### TlsFragment原理

#### TLSfrag

将TCP连接Client的第一个包（这个包一般来说是TLS ClientHello，一般应用层不会分片）在TLS层和TCP层分别进行分片，将sni拆入多个包以绕过gfw。

#### FAKEdesync

利用ttl发送假包，扰乱gfw的DPI。

为了避免管理员/root权限的需要。

+ 在Windows上，使用`TransmitFile`函数（由于TransmitFIle被限制最多同时运行2个，性能较差）
+ 在linux上，使用管道

通过重传机制发送。

### 异步方式

使用`threading`（多线程），有一个`asyncio`协程版本目前废弃，原因是当初默认版本无法支持自代理DoH。现在懒得改了，个人使用不会有明显性能差距。

### 安装使用

#### 运行

```bash
git clone git@github.com:maoist2009/TlsFragment.git
pip install poetry
poetry init
python run.py
```

下载依赖也可`pip install -r requirements.txt`。

也可以编译后开机自启动：

```bash
cd tools
BUILD_WINDOWS
```

之后请为`/dist/proxy.exe`创建快捷方式，复制到`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`

#### 浏览器使用

建议分流,内置了一个黑/白名单pac生成器。使用和本程序相同的匹配方式（见下）。pac规则存放在`config_pac.pac`里。

安装`ZeroOmega`，导入配置文件`OmegaOptions.bak`和`gooreplacer.json`（android请使用Mises/ultimatum浏览器等）。

或者自行通过各种方式分流。

其他可以看[Releases](https://github.com/maoist2009/TlsFragment/releases)
### 配置方式

程序使用JSON格式配置，主要包含全局配置和连接策略配置。

本程序本身不行，~~但是作者喜欢作，~~喜欢乱改配置行为为自己认为优美的写法。**因此具体行为以代码为准。**

**配置文件优先级**：
- 程序默认配置文件：`config.json`
- 本地覆盖配置文件：`config_extra.json`（会覆盖`config.json`中的对应项目）

#### 全局配置

全局配置项控制程序行为，包括：

| 项名                        | 简单解释                                                                 |
| --------------------------- | -------------------------------------------------------------------------- |
| `loglevel`                  | 日志级别，可选值：DEBUG, INFO, WARNING, ERROR                             |
| `port`                      | 代理运行端口（默认2500）                                                   |
| `DOH_port`                  | DoH代理使用端口（默认2500）                                                |
| `my_socket_timeout`         | 套接字超时时间（秒），控制连接/数据传输超时                                |
| `FAKE_ttl_auto_timeout`     | FAKEdesync模式中cookie缓存时间（秒）                                       |
| `doh_server`                | DoH服务器地址，如`https://example.com/dns-query?dns=`， 后接域名发送查询。支持`udp://`，进行udp dns|
| `DNS_cache_update_interval` | DNS缓存更新间隔（秒）                                                      |
| `TTL_cache_update_interval` | TTL缓存更新间隔（秒）                                                      |
| `UDPfakeDNS`                | 是否启用UDP假DNS功能                                                       |
| `BySNIfirst`                | 是否优先通过SNI匹配域名                                                    |
| `TransmitFile_Limit`        | Windows下TransmitFile函数并发限制（默认2）                                 |
| `redirect_when_ip`          | 如果上游指定了IP是否进行重定向                                                 |
| `default_policy`            | 默认连接策略，包含具体模式配置（见下文）                                   |

#### 连接策略配置

所有连接策略配置都在`default_policy`对象中定义，包括以下内容：

##### 通用配置

| 项名                 | 简单解释                                                                 |
| --------------------- | -------------------------------------------------------------------------- |
| `mode`                | 操作模式，可选值：`TLSfrag`或`FAKEdesync`或`DIRECT`或者`GFWlike`                   |
| `safety_check`        | 如果是http(s)连接，是否只允许TLS1.3（不要乱关，被dpi了有时候容易死ip）|

##### TLSfrag模式配置

| 项名               | 简单解释                                                                 |
| ------------------ | -------------------------------------------------------------------------- |
| `num_tls_pieces`   | 无SNI段的TLS分块数量                                                       |
| `len_tls_sni`      | SNI在TLS层的分块长度（字节）                                               |
| `send_interval`    | tcp分块发送间隔（秒）                                 |
| `num_tcp_pieces`   | 无SNI段的TCP分块数量   |
| `len_tcp_sni`      | SNI在TCP层的分块长度（字节）    |

##### FAKEdesync模式配置

| 项名           | 简单解释                                                                 |
| ---------------- | -------------------------------------------------------------------------- |
| `fake_packet`    | 发送的假包内容，如HTTP请求，会截取前缀                                                 |
| `fake_ttl`       | 假包使用的TTL值，支持复杂模式（如`q0-1;3=3;5-1;8-2;20=18`表示查询模式）   |
| `fake_sleep`     | 发送假包后改为真包的间隔时间（秒）       |
| `send_interval`    | tcp分块发送间隔（秒）                                 |
| `num_tcp_pieces`   | 无假包区域TCP分块数量   |
| `len_tcp_sni`      | 假包长度 |
| `TTL_cache`        | 是否缓存查询到的达到服务器所需最低ttl |
会在握手包开头和sni开头各进行一次ttl假包操作。

查询模式字符串中，`q`开头，接下来`a-b`表示查询的到达服务器最低ttl超过a（但是不超过下一个`a'`），假包ttl为真包最低ttl-b,若为`=则直接取b.

#### 域名配置

域名配置通过`domains`下对象定义，可以为特定域名设置不同的连接策略。每个域名配置可以包含以下项目：

| 项名       | 简单解释            |
| ---------- | ------------------- |
| `IP`       | 目标IP地址          |
| `IPtype`   | 首选ip dns类型      |
| `DNS_cache`           | 是否缓存DNS查询结果 |
| `DNS_cache_TTL`       | DNS缓存TTL（秒），默认3天（259200秒）                                      |


##### 域名匹配规则

域名匹配使用AC自动机实现，以应对大规模域名列表：
- 如果特定域名是SNI的子串，则匹配成功
- 当多个配置域名匹配时，优先选择最长的配置域名
- 若长度相同，则按Python的字典序规则选择
- 支持首尾匹配，配置域名会自动添加`^`和`$`符号确保精确匹配
- 支持通配符模式（如`example.(com|net)`），系统会自动展开为多个具体域名

#### 单连接配置优先级

单连接配置的优先级顺序为：**IP配置 > 域名配置 > 默认配置**。当处理一个连接请求时，系统会按此顺序匹配配置：

1. **IP配置**：检查目标IP是否在IP重定向规则中匹配
2. **域名配置**：若IP未匹配，则检查SNI域名是否匹配域名配置
3. **默认配置**：若以上均未匹配，则使用`default_policy`指定的配置

#### IP查找

建议使用[HTTPS_IP_finder](https://github.com/maoist2009/HTTPS_IP_finder)工具获取有效IP地址。该工具支持：
- 扫描IP和端口
- 通过反DPI代理进行探测
- 并发扫描提高效率

#### IP重定向

IP重定向支持将目标IP（或IP段）重定向到新IP，主要特性如下：

- **链式重定向**：默认情况下，系统会递归应用重定向规则，直到无匹配或遇到终止标记。例如，IP A→B→C，最终会使用C。
  
- **终止链式**：在重定向目标IP前添加`^`符号（如`^1.2.3.4`），则停止递归。例如，IP A→^B，最终会使用B，不再继续重定向。
  
- **IP段处理**：支持CIDR表示法（如`1.2.3.0/24`）。系统会保留原始IP的后缀部分，只替换前缀。例如，将`1.2.3.4`重定向到`10.0.0.0/24`，结果为`10.0.0.4`。

- **精确匹配**：支持单个IP的精确重定向，如`1.2.3.4`→`10.0.0.1`。

重定向功能主要用于优选（将被封锁ip改为可用ip也是一种特殊的优选）。

#### 注意事项

- Windows用户：由于TransmitFile函数的限制，建议不要设置过高的并发数
- Android用户：程序仅为代理，需配合浏览器使用
  - 推荐使用Kiwibrowser + Switch Proxy Omega
  - 或使用SocksTun设置代理（Address: 127.0.0.1, Port: 2500）
- 安全提示：本程序无法保证SNI完全不泄露，高风险用户建议结合其他安全工具使用
