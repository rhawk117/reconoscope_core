'''
**reconoscope._http**
---------

The HTTP utilities for Reconoscope, including a custom transport wrapped in `HttpClientPool`,
a retry policy decorator, and a user-agent generator. This is used internally throughout the
package, but you can also use it directly if needed considering it implements some useful
features like retries, SSL context generation, Socket options, etc.
'''
from reconoscope._http._pool import HttpClientPool, HttpOptions
from reconoscope._http._retry import NoAttemptsLeftError, retry_policy
from reconoscope._http._transport import HttpTransport, URLRejectedError
from reconoscope._http._user_agents import get_random_user_agent

__all__ = [
    "HttpClientPool",
    "HttpOptions",
    "HttpTransport",
    "URLRejectedError",
    "NoAttemptsLeftError",
    "retry_policy",
    "get_random_user_agent",
]