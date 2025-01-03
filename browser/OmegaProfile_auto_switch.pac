var FindProxyForURL = function(init, profiles) {
    return function(url, host) {
        "use strict";
        var result = init, scheme = url.substr(0, url.indexOf(":"));
        do {
            result = profiles[result];
            if (typeof result === "function") result = result(url, host, scheme);
        } while (typeof result !== "string" || result.charCodeAt(0) === 43);
        return result;
    };
}("+auto switch", {
    "+auto switch": function(url, host, scheme) {
        "use strict";
        if (/(?:^|\.)cookielaw\.org$/.test(host)) return "+proxy";
        if (/(?:^|\.)docker\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)discord\.gg$/.test(host)) return "+proxy";
        if (/(?:^|\.)discordapp\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)discord\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)blogger\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)redd\.it$/.test(host)) return "+proxy";
        if (/(?:^|\.)redditmedia\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)redditstatic\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)reddit\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)receiveasmsonline\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)good\.news$/.test(host)) return "+proxy";
        if (/(?:^|\.)bsky\.app$/.test(host)) return "+proxy";
        if (/(?:^|\.)bsky\.social$/.test(host)) return "+proxy";
        if (/(?:^|\.)pscp\.tv$/.test(host)) return "+proxy";
        if (/(?:^|\.)matrix\.org$/.test(host)) return "+proxy";
        if (/(?:^|\.)pixiv\.net$/.test(host)) return "+proxy";
        if (/(?:^|\.)imgur\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)gravatar\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)twitch\.tv$/.test(host)) return "+proxy";
        if (/(?:^|\.)bit\.ly$/.test(host)) return "+proxy";
        if (/(?:^|\.)raw\.githubusercontent\.com$/.test(host)) return "DIRECT";
        if (/(?:^|\.)duckduckgo\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)cdn-telegram\.org$/.test(host)) return "+proxy";
        if (/(?:^|\.)githubusercontent\.com$/.test(host)) return "DIRECT";
        if (/(?:^|\.)githubassets\.com$/.test(host)) return "DIRECT";
        if (/(?:^|\.)github\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)wikinews\.org$/.test(host)) return "+proxy";
        if (/(?:^|\.)wikipedia\.org$/.test(host)) return "+proxy";
        if (/(?:^|\.)wikimedia\.org$/.test(host)) return "+proxy";
        if (/(?:^|\.)instagram\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)dropbox\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)bu2021\.xyz$/.test(host)) return "+proxy";
        if (/(?:^|\.)cdninstagram\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)fbsbx\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)facebook\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)fbcdn\.net$/.test(host)) return "+proxy";
        if (/(?:^|\.)translate\.goog$/.test(host)) return "+proxy";
        if (/(?:^|\.)ggpht\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)telegram\.me$/.test(host)) return "+proxy";
        if (/(?:^|\.)t\.me$/.test(host)) return "+proxy";
        if (/(?:^|\.)v2ex\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)googleapis\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)x\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)twimg\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)twitter\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)withgoogle\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)telegram\.org$/.test(host)) return "+proxy";
        if (/(?:^|\.)youtube\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)ytimg\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)googlevideo\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)googleusercontent\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)google\.com\.hk$/.test(host)) return "+proxy";
        if (/(?:^|\.)google\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)workers\.dev$/.test(host)) return "+proxy";
        if (/(?:^|\.)xcancel\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)geph\.io$/.test(host)) return "+proxy";
        if (/(?:^|\.)1lib\.sk$/.test(host)) return "+proxy";
        if (/(?:^|\.)z-library\.sk$/.test(host)) return "+proxy";
        if (/(?:^|\.)freeweibo\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)odycdn\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)odysee\.com$/.test(host)) return "+proxy";
        if (/(?:^|\.)torproject\.org$/.test(host)) return "+proxy";
        if (/(?:^|\.)mastodon\.social$/.test(host)) return "+proxy";
        if (/(?:^|\.)freezhihu\.org$/.test(host)) return "+proxy";
        if (/^pages\.dev$/.test(host)) return "+proxy";
        if (/(?:^|\.)greatfire\.org$/.test(host)) return "+proxy";
        if (/^www\.gstatic\.com$/.test(host)) return "DIRECT";
        if (/^fonts\.gstatic\.com$/.test(host)) return "DIRECT";
        if (/(?:^|\.)gstatic\.com$/.test(host)) return "+proxy";
        return "DIRECT";
    },
    "+proxy": function(url, host, scheme) {
        "use strict";
        if (/^127\.0\.0\.1$/.test(host) || /^::1$/.test(host) || /^localhost$/.test(host)) return "DIRECT";
        return "PROXY 127.0.0.1:2500";
    }
});