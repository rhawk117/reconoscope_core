from reconoscope.sdk.errors import ReconoscopeError


class TransportConfigurationError(ReconoscopeError):
    """
    raised when transport options are internally inconsistent.
    """


class URLRejectedError(ReconoscopeError):
    """
    Raised when a URL is rejected by the client URL normalizer.

    Parent: ValueError
    """
