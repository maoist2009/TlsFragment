# [English](/README-en.md) [Russian](/README-ru.md) [Chinese](/README.md)
## TLSFragment User Guide

### Community

- **Discussions**: available on the repository.  
- **Matrix feedback rooms**:  
  - General issues: <https://matrix.to/#/#tlsp_public:matrix.org>  
  - Configuration & optimization (IP lookup, mode changes, etc.): <https://matrix.to/#/!WvZLqiyvvsVSCrsuWt:matrix.org?via=matrix.org>  
  - TLSFragment program bugs: <https://matrix.to/#/!GvJhmmjpGqeNCPyMyE:matrix.org?via=matrix.org>  
  - Proxy configuration questions: <https://matrix.to/#/!bRNRPJmWSBrWyuQbCd:matrix.org?via=matrix.org>  

A private room also exists for invited members.

---

### Installation

#### As a Python package

```bash
python -m build --wheel --no-isolation
python -m installer dist/*.whl
```

After installation you can run the command `tls_fragment` (currently not supported as a standalone entry point).

#### From source

```bash
git clone https://github.com/maoist2009/TlsFragment.git
cd TlsFragment
pip install poetry
poetry install
python run.py
```

You can also build a Windows executable and set it to start automatically:

```bash
# Build for Windows
BUILD_WINDOWS
```

Create a shortcut to `dist/proxy.exe` and place it in  
`%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup`.

---

### How TLSFragment Works

#### TLSfrag

The first packet from a TCP client (normally the TLS **ClientHello**, which is usually not fragmented at the application layer) is split both at the TLS layer and the TCP layer. The SNI is broken into multiple packets to bypass GFW inspection.

#### FAKEdesync

Fake packets with crafted TTL values are sent to confuse GFW’s DPI. This avoids needing administrator/root privileges:

- **Windows** – uses the `TransmitFile` API (limited to two concurrent transfers, lower performance).  
- **Linux** – uses a pipe mechanism.  

The fake packets are retransmitted according to the normal TCP retransmission logic.

---

### Concurrency Model

- Primary implementation uses **threading** (multiple OS threads).  
- An `asyncio` version existed but was deprecated because the default build cannot support self‑proxy DoH.

---

### Browser Usage

1. Install **Proxy SwitchyOmega** and **Gooreplacer**.  
2. Import the provided configuration files:  
   - `OmegaOptions.bak` → SwitchyOmega  
   - `gooreplacer.json` → Gooreplacer (Android users can use Kiwi Browser, etc.)  

It is recommended to split traffic (e.g., route only target domains through the proxy).

---

## Configuration

### Global Options

| Option | Description | Domain‑specific override |
|--------|-------------|--------------------------|
| `output_data` | Log packet contents | No |
| `listen_PORT` | Port on which the proxy listens | No |
| `DOH_PORT` | Port for DoH proxy | No |
| `my_socket_timeout` | Socket send/receive timeout | No |
| `doh_server` | DoH server (specify IP in `domains`) | No |
| `DNS_log_every` | DNS cache logging interval | No |
| `TTL_log_every` | TTL cache logging interval | No |
| `num_TCP_fragment` | Number of TCP fragments **without** SNI | Yes |
| `TCP_frag` | Approximate TCP fragment size for the SNI segment | Yes |
| `method` | Operation mode (see below) | Yes |
| `IPtype` | Preferred IP type for DNS queries (fallback if none) | Yes |

### TLSfrag Mode

| Option | Description | Domain‑specific override |
|--------|-------------|--------------------------|
| `num_TLS_fragment` | Number of TLS fragments **without** SNI | Yes |
| `TLS_frag` | TLS fragment size for the SNI segment | Yes |

### FAKEdesync Mode

| Option | Description | Domain‑specific override |
|--------|-------------|--------------------------|
| `FAKE_packet` | Content of the fake packet | Yes |
| `FAKE_ttl` | TTL for the fake packet; use `query` for automatic binary search | Yes |
| `FAKE_ttl_auto_timeout` | Cookie cache timeout | Yes |
| `FAKE_sleep` | Delay between sending the fake packet and the real packet | Yes |

Domain‑specific overrides are defined under `domains.xxx.com` and take precedence over the global values.

### Domain‑Specific Settings (`domains` section)

| Field | Meaning |
|-------|---------|
| `IP` | Target IP address |
| `port` | Port (default 443 if omitted) |
| `IPcache` | Whether to cache the IP |
| `TTLcache` | Whether to cache the TTL associated with the IP |

### Domain Matching Rules

The SNI is matched against the longest domain suffix present in the configuration. If multiple candidates have the same length, Python’s sort order decides. Matching is performed with an Aho‑Corasick automaton for efficiency, e.g., the pattern stored is `^www.domain.genshin.mihoyo.com$`. Both prefix and suffix matches are supported.

### IP Lookup

It is recommended to use **HTTPS_IP_finder**: <https://github.com/maoist2009/HTTPS_IP_finder>. The author maintains a list of sites blocked by IP.

### IP Redirection

IP (or IP range) redirection to another IP is supported. By default redirects are chained; to disable chaining, prepend `^` to the target IP string.
