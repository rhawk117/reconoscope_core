import socket
from types import MappingProxyType



UserAgentSpec = MappingProxyType({
    'chrome_windows': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36'
    ),
    'chrome_mac': (
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36'
    ),
    'chrome_linux': (
        'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36'
    ),
    'chrome_android': (
        'Mozilla/5.0 (Linux; Android 13; SM-G991B) AppleWebKit/537.36 '
        '(KHTML, like Gecko) Chrome/118.0.0.0 Mobile Safari/537.36'
    ),
    'chrome_ios': (
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) '
        'AppleWebKit/605.1.15 (KHTML, like Gecko) '
        'CriOS/118.0.0.0 Mobile/15E148 Safari/604.1'
    ),
    'firefox_windows': (
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) '
        'Gecko/20100101 Firefox/118.0'
    ),
    'firefox_mac': (
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7; rv:109.0) '
        'Gecko/20100101 Firefox/118.0'
    ),
    'firefox_linux': (
        'Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0'
    ),
    'firefox_android': ('Mozilla/5.0 (Mobile; rv:109.0) Gecko/118.0 Firefox/118.0'),
    'firefox_ios': (
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) '
        'AppleWebKit/605.1.15 (KHTML, like Gecko) FxiOS/118.0 '
        'Mobile/15E148 Safari/605.1.15'
    ),
})


MAGIC_TCP_KEEPIDLE = (socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
MAGIC_TCP_KEEPINTVL = (socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
MAGIC_TCP_KEEPCNT = (socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 5)

DEFAULT_MAX_CONNECTIONS = 100
DEFAULT_KEEPALIVE_CONNECTIONS = 20
DEFAULT_KEEPALIVE_EXPIRY = 15
DEFAULT_TIMEOUT = 5
