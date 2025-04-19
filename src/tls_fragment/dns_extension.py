import dns.query, dns.nameserver
import httpx


class ProxiedDohServer(dns.nameserver.DoHNameserver):
    proxy: str

    def __init__(
        self,
        proxy,
        url,
        bootstrap_address=None,
        verify=True,
        want_get=False,
        http_version=dns.query.HTTPVersion.DEFAULT,
    ):
        super().__init__(url, bootstrap_address, verify, want_get, http_version)
        self.proxy = proxy

    def query(
        self,
        request,
        timeout,
        source,
        source_port,
        max_size=False,
        one_rr_per_rrset=False,
        ignore_trailing=False,
    ):
        return dns.query.https(
            request,
            self.url,
            timeout=timeout,
            source=source,
            source_port=source_port,
            bootstrap_address=self.bootstrap_address,
            one_rr_per_rrset=one_rr_per_rrset,
            ignore_trailing=ignore_trailing,
            session=httpx.Client(proxy=self.proxy),
            verify=self.verify,
            post=(not self.want_get),
            http_version=self.http_version,
        )
