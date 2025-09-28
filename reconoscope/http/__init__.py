'''
**reconoscope._http**
---------

The HTTP utilities for Reconoscope, including a custom transport wrapped in `HttpClientPool`,
a retry policy decorator, and a user-agent generator. This is used internally throughout the
package, but you can also use it directly if needed considering it implements some useful
features like retries, SSL context generation, Socket options, etc.
'''
from reconoscope.http._client import (
    ReconoscopeTransport,
    UserAgent,
    ClientConfig,
    ReconoscopeClient,
    user_agent_middleware,
    verify_http_url,
    browser_like_ssl_context,
)
from reconoscope.http._retry import NoAttemptsLeftError, retry_policy

__all__ = [
    'ReconoscopeTransport',
    'UserAgent',
    'ClientConfig',
    'ReconoscopeClient',
    'user_agent_middleware',
    'verify_http_url',
    'browser_like_ssl_context',
    'NoAttemptsLeftError',
    'retry_policy',
]