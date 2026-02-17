from __future__ import annotations

import contextlib
import dataclasses as dc
import ssl
from typing import TYPE_CHECKING, Literal, NamedTuple, Self

if TYPE_CHECKING:
    from collections.abc import Sequence




# Common OpenSSL curve names used for ECDHE key agreement.
# Keep a string escape hatch in case someone is on a weird platform/build.
ECDHCurveName = Literal[
    'X25519',
    'X448',
    'prime256v1',  # a.k.a secp256r1
    'secp384r1',
    'secp521r1',
    'brainpoolP256r1',
    'brainpoolP384r1',
    'brainpoolP512r1',
]


class TLSCipherSuite(NamedTuple):
    """
    A split cipher policy for TLS 1.3 and TLS 1.2.

    TLS 1.3 uses different configuration semantics than TLS 1.2 on OpenSSL-based
    Python builds, so separating them avoids pretending the world is simpler
    than it is.

    Notes
    -----
    - If your OpenSSL build does not support `SSLContext.set_ciphersuites`,
      TLS 1.3 selection may be ignored (and the defaults win).
    - TLS 1.2 selection uses `SSLContext.set_ciphers` and is generally supported.

    See Also
    --------
    SSLContextOptions
    build_ssl_context
    """

    v1_3_ciphers: tuple[str, ...]
    v1_2_ciphers: tuple[str, ...]

    @classmethod
    def default(cls) -> Self:
        """
        Return a modern, safe-by-default cipher policy.

        The goal is boring crypto:
        - Forward secrecy (ECDHE in TLS 1.2, built-in in TLS 1.3)
        - AEAD-only (GCM/ChaCha20-Poly1305)
        - No legacy CBC suites, no RSA key exchange

        Returns
        -------
        TLSCipherSuite
                A pair of cipher name tuples: (TLS 1.3, TLS 1.2).

        Notes
        -----
        If you are hoping for a cipher suite that “fixes” a bad PKI or mitigates
        someone clicking through certificate warnings, you are asking for a
        fairy tale.
        """
        return cls(
            v1_3_ciphers=(
                'TLS_AES_128_GCM_SHA256',
                'TLS_AES_256_GCM_SHA384',
                'TLS_CHACHA20_POLY1305_SHA256',
            ),
            v1_2_ciphers=(
                'ECDHE-ECDSA-AES128-GCM-SHA256',
                'ECDHE-RSA-AES128-GCM-SHA256',
                'ECDHE-ECDSA-CHACHA20-POLY1305',
                'ECDHE-RSA-CHACHA20-POLY1305',
                'ECDHE-ECDSA-AES256-GCM-SHA384',
                'ECDHE-RSA-AES256-GCM-SHA384',
            ),
        )


@dc.dataclass(slots=True)
class SSLContextOptions:
    """
    Policy object for building a secure client-side `ssl.SSLContext`.

    This is where you define what “secure by default” means for your library,
    instead of re-encoding TLS policy in five different places and hoping they
    stay consistent. (They won’t.)

    Parameters
    ----------
    tls_min_version:
        Minimum TLS version to allow. Default is TLS 1.2.
    tls_max_version:
        Maximum TLS version to allow. Default is `MAXIMUM_SUPPORTED`.
    check_hostname:
        Whether the TLS layer validates the certificate hostname against the
        requested server name (SNI/hostname). You want this True.
    verify_mode:
        Certificate verification mode. Default is `CERT_REQUIRED`.
    cafile, capath, cadata:
        Optional trust store overrides. If all are None, system defaults are used.
    tls_ciphers:
        Cipher suite policy for TLS 1.3 and TLS 1.2.
    ecdh_curve:
        Preferred ECDH curve for ECDHE key agreement (where applicable).
    fallback_ecdh_curve:
        A backup curve if the preferred one is unavailable on this platform.
    alpn_protocols:
        Application Layer Protocol Negotiation values, e.g. ('h2', 'http/1.1').
    disable_compression:
        Disables TLS-level compression to avoid CRIME-style nonsense.
    disable_renegotiation:
        Disables renegotiation if supported by the runtime.
    disable_tlsv1, disable_tlsv1_1:
        Explicitly disables legacy protocols when option bits exist.
    disable_legacy_server_connect:
        Attempts to prevent legacy “unsafe renegotiation” compatibility mode.
    extra_options:
        Optional additional `ssl.OP_*` bits to OR into `SSLContext.options`.
    verify_flags:
        Optional `ssl.VerifyFlags` to control chain building behavior.
    enable_crl_check:
        Enable CRL checking (leaf). Requires CRLs to be available in trust store.
    client_certfile, client_keyfile, client_key_password:
        Optional mutual TLS credentials (client auth).
    keylog_filename:
        Exports session keys for debugging. Great for Wireshark.
        Horrific if you enable it in production.

    Notes
    -----
    - TLS settings are platform/OpenSSL-build dependent. Some knobs are best-effort.
    - “Secure defaults” are not “secure if you disable verification.” That’s not
      security, that’s cosplay.
    """

    tls_min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2
    tls_max_version: ssl.TLSVersion = ssl.TLSVersion.MAXIMUM_SUPPORTED

    check_hostname: bool = True
    verify_mode: ssl.VerifyMode = ssl.CERT_REQUIRED

    cafile: str | None = None
    capath: str | None = None
    cadata: str | bytes | None = None

    tls_ciphers: TLSCipherSuite = dc.field(default_factory=TLSCipherSuite.default)

    ecdh_curve: ECDHCurveName | str = 'X25519'
    fallback_ecdh_curve: ECDHCurveName | str = 'prime256v1'

    alpn_protocols: tuple[str, ...] = ('h2', 'http/1.1')

    disable_compression: bool = True
    disable_renegotiation: bool = True
    disable_tlsv1: bool = True
    disable_tlsv1_1: bool = True
    disable_legacy_server_connect: bool = True

    extra_options: Sequence[ssl.Options] | None = None

    verify_flags: ssl.VerifyFlags | None = None
    enable_crl_check: bool = False

    client_certfile: str | None = None
    client_keyfile: str | None = None
    client_key_password: str | bytes | None = None

    keylog_filename: str | None = None

    @classmethod
    def browser_like(cls) -> Self:
        """
        Return a “browser-ish” TLS posture.

        This aims for what you actually want in a modern client:
        - TLS 1.2+ (because the internet is a museum)
        - Strong AEAD suites
        - ALPN prefers HTTP/2, falls back to HTTP/1.1
        - Hostname verification and certificate validation enabled

        Returns
        -------
        SSLContextOptions
                A policy object suitable for typical HTTPS usage.
        """
        return cls(
            tls_min_version=ssl.TLSVersion.TLSv1_2,
            tls_max_version=ssl.TLSVersion.MAXIMUM_SUPPORTED,
            check_hostname=True,
            verify_mode=ssl.CERT_REQUIRED,
            tls_ciphers=TLSCipherSuite.default(),
            ecdh_curve='X25519',
            alpn_protocols=('h2', 'http/1.1'),
        )

@contextlib.contextmanager
def on_error_warn_user(
    *,
    catch: type[Exception] | tuple[type[Exception], ...],
    warning: str
):
    try:
        yield
    except catch:





def build_ssl_context(options: SSLContextOptions) -> ssl.SSLContext:
    """
    Build an `ssl.SSLContext` from `SSLContextOptions`.

    This function is intentionally boring. Boring is good here.
    TLS policy should be centralized, testable, and hard to “just tweak real quick”
    in a random call site.

    Parameters
    ----------
    options:
        Configuration policy for the SSL context.

    Returns
    -------
    ssl.SSLContext
        A configured client SSL context ready for HTTPS connections.

    Raises
    ------
    ssl.SSLError
        If the runtime rejects one of the configured parameters (cipher string,
        curve selection, cert chain loading, etc.).

    Notes
    -----
    Some APIs are best-effort and depend on your Python/OpenSSL build:
    - `set_ciphersuites` (TLS 1.3) may not exist.
    - `OP_NO_RENEGOTIATION` may not exist.
    - ECDH curve setting may be ignored depending on TLS version and backend.

    If that makes you uncomfortable, welcome to systems programming.
    """
    ssl_context = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=options.cafile,
        capath=options.capath,
        cadata=options.cadata,
    )
    ssl_context.minimum_version = options.tls_min_version
    ssl_context.maximum_version = options.tls_max_version

    ssl_context.check_hostname = options.check_hostname
    ssl_context.verify_mode = options.verify_mode

    if options.alpn_protocols:
        with contextlib.suppress(NotImplementedError):
            ssl_context.set_alpn_protocols(list(options.alpn_protocols))

    if options.disable_compression and hasattr(ssl, 'OP_NO_COMPRESSION'):
        ssl_context.options |= ssl.OP_NO_COMPRESSION

    if options.disable_renegotiation and hasattr(ssl, 'OP_NO_RENEGOTIATION'):
        ssl_context.options |= ssl.OP_NO_RENEGOTIATION

    if options.extra_options:
        for extra_option in options.extra_options:
            ssl_context.options |= extra_option

    set_tls13_ciphersuites = getattr(ssl_context, 'set_ciphersuites', None)
    if callable(set_tls13_ciphersuites) and options.tls_ciphers.v1_3_ciphers:
        with contextlib.suppress(ssl.SSLError, NotImplementedError):
            set_tls13_ciphersuites(':'.join(options.tls_ciphers.v1_3_ciphers))

    if options.tls_ciphers.v1_2_ciphers:
        with contextlib.suppress(ssl.SSLError):
            ssl_context.set_ciphers(':'.join(options.tls_ciphers.v1_2_ciphers))

    if hasattr(ssl_context, 'set_ecdh_curve'):
        with contextlib.suppress(ssl.SSLError, NotImplementedError):
            ssl_context.set_ecdh_curve(str(options.ecdh_curve))
        with contextlib.suppress(ssl.SSLError, NotImplementedError):
            ssl_context.set_ecdh_curve(str(options.fallback_ecdh_curve))

    if options.verify_flags is not None:
        with contextlib.suppress(AttributeError):
            ssl_context.verify_flags = options.verify_flags

    if options.enable_crl_check and hasattr(ssl, 'VERIFY_CRL_CHECK_LEAF'):
        with contextlib.suppress(AttributeError):
            ssl_context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF

    if options.client_certfile:
        ssl_context.load_cert_chain(
            certfile=options.client_certfile,
            keyfile=options.client_keyfile,
            password=options.client_key_password,
        )

    if options.keylog_filename and hasattr(ssl_context, 'keylog_filename'):
        with contextlib.suppress(Exception):
            ssl_context.keylog_filename = options.keylog_filename

    return ssl_context
