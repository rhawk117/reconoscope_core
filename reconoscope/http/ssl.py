# reconoscope/sdk/ssl/options.py
from __future__ import annotations

import dataclasses as dc
import ssl
from typing import TYPE_CHECKING, Literal, NamedTuple, Self

if TYPE_CHECKING:
    from collections.abc import Sequence


type ECDHCurveName = Literal[
    'X25519',
    'X448',
    'prime256v1',  # a.k.a secp256r1
    'secp384r1',
    'secp521r1',
    'brainpoolP256r1',
    'brainpoolP384r1',
    'brainpoolP512r1',
]
"""
common openssl curve names used for ecdhe key agreement.

this is here so callers stop passing in random strings like 'x25519 ' with a
trailing space and then acting surprised when tls does not care about their feelings.
"""


class TLSCipherSuite(NamedTuple):
    """
    a split cipher policy for tls 1.3 and tls 1.2.

    tls 1.3 and tls 1.2 use different configuration mechanisms in python's ssl
    module (and, depending on your openssl build, different levels of support),
    so keeping them separate avoids pretending the world is simpler than it is.
    """

    v1_3_ciphers: tuple[str, ...]
    v1_2_ciphers: tuple[str, ...]

    @classmethod
    def default(cls) -> Self:
        """
        return a modern, safe-by-default cipher policy.

        this is the "boring crypto" set:
        - aead only (gcm / chacha20-poly1305)
        - forward secrecy (ecdhe for tls 1.2, built-in for tls 1.3)
        - no legacy cbc suites, no rsa key exchange
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
    tls tuning policy intended to be applied to an existing `ssl.SSLContext`.

    this is deliberately *not* a "who owns verification" object anymore.
    httpx owns trust roots, hostname verification, and client cert loading
    via `verify=` and `cert=`, so we do not expose knobs that would fight it.

    parameters
    ----------
    tls_min_version:
        minimum tls version to allow. default is tls 1.2.
    tls_max_version:
        maximum tls version to allow. default is `MAXIMUM_SUPPORTED`.
    tls_ciphers:
        cipher suite policy for tls 1.3 and tls 1.2.
    ecdh_curve:
        preferred ecdh curve for ecdhe key agreement (where supported).
    fallback_ecdh_curve:
        a backup curve if the preferred curve is unavailable.
    alpn_protocols:
        alpn values, typically ('h2', 'http/1.1').
    disable_compression:
        disables tls compression (crime mitigation; also, just don't compress tls).
    disable_renegotiation:
        disables renegotiation where supported.
    disable_tlsv1, disable_tlsv1_1:
        explicitly disables legacy protocols where option bits exist.
    disable_legacy_server_connect:
        tries to avoid legacy "unsafe renegotiation" compatibility mode.
    extra_options:
        additional ssl.OP_* flags to apply (deduped).
    verify_flags:
        optional x509 verification flags.
    enable_crl_check:
        enable leaf crl checking (requires crls in your trust store).

    notes
    -----
    if you want to change trust roots or verification semantics, use httpx's
    `verify=` and `cert=`. if you try to do that here, you're asking for ambiguity.
    """

    tls_min_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_2
    tls_max_version: ssl.TLSVersion = ssl.TLSVersion.MAXIMUM_SUPPORTED

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


# reconoscope/sdk/ssl/builder.py
from __future__ import annotations

import logging
import ssl
from typing import TYPE_CHECKING

from reconoscope.sdk.warnings import (
    ReconoscopeWarning,
    SecurityWarning,
    emit_warning,
    on_error_emit_warning,
)

if TYPE_CHECKING:
    from reconoscope.http.options import SSLContextOptions

logger = logging.getLogger(__name__)


class TLSSecurityDegradation(SecurityWarning):
    """
    security posture was degraded compared to what the caller asked for.

    this is the one you treat as an error in strict deployments, because it means
    you did not actually get the tls hardening you thought you did. delightful.
    """


class TLSConfigurationWarning(ReconoscopeWarning):
    """
    non-fatal tls configuration issue.

    this is for "nice to have" settings that failed, where the resulting context
    is still usable, just less fancy than your dreams.
    """


def create_initial_context() -> ssl.SSLContext:
    """
    create a minimal client ssl context without owning trust roots or client certs.

    returns
    -------
    ssl.SSLContext
        a client protocol context ready to be tuned.

    notes
    -----
    this does not load cafiles or set verify modes. httpx owns those via `verify=`
    and `cert=`. we are just creating a context object to tune, like adults.
    """
    return ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)


def set_alpn_protocols(ssl_context: ssl.SSLContext, options: SSLContextOptions) -> None:
    """
    configure alpn protocols (http/2 + fallback).

    notes
    -----
    if this fails, you will probably still connect. you just won't negotiate h2.
    you can enjoy your artisanal http/1.1 latency.
    """
    if not options.alpn_protocols:
        return

    with on_error_emit_warning(
        'alpn could not be set; http/2 negotiation may not occur',
        catch=(NotImplementedError,),
        category=TLSConfigurationWarning,
        stacklevel=4,
    ):
        ssl_context.set_alpn_protocols(list(options.alpn_protocols))


def _safe_register_ssl_option(
    seen: set[ssl.Options],
    option: ssl.Options,
    ssl_context: ssl.SSLContext,
) -> None:
    if option in seen:
        emit_warning(
            f'ignoring duplicate ssl option `{option.name}`',
            category=TLSConfigurationWarning,
        )
        return

    seen.add(option)
    if option == ssl.OP_LEGACY_SERVER_CONNECT:
        ssl_context.options &= ~ssl.OP_LEGACY_SERVER_CONNECT
    else:
        ssl_context.options |= option


def register_ssl_option_flags(
    ssl_context: ssl.SSLContext, options: SSLContextOptions
) -> None:
    """
    apply ssl hardening flags based on options.

    Note
    -----
    failures here should be treated as security degradation, because the whole
    point is to harden the context
    """
    seen_options: set[ssl.Options] = set()

    if options.disable_compression:
        _safe_register_ssl_option(seen_options, ssl.OP_NO_COMPRESSION, ssl_context)

    if options.disable_renegotiation:
        _safe_register_ssl_option(seen_options, ssl.OP_NO_RENEGOTIATION, ssl_context)

    if options.disable_tlsv1:
        _safe_register_ssl_option(seen_options, ssl.OP_NO_TLSv1, ssl_context)

    if options.disable_tlsv1_1:
        _safe_register_ssl_option(seen_options, ssl.OP_NO_TLSv1_1, ssl_context)

    if options.disable_legacy_server_connect:
        _safe_register_ssl_option(seen_options, ssl.OP_LEGACY_SERVER_CONNECT, ssl_context)

    if options.extra_options:
        for extra_option in options.extra_options:
            _safe_register_ssl_option(seen_options, extra_option, ssl_context)


def register_tls_versions(
    ssl_context: ssl.SSLContext, options: SSLContextOptions
) -> None:
    """
    apply tls min/max version bounds.
    """
    ssl_context.minimum_version = options.tls_min_version
    ssl_context.maximum_version = options.tls_max_version


def register_tls_ciphers(ssl_context: ssl.SSLContext, options: SSLContextOptions) -> None:
    """
    apply tls cipher configuration for tls 1.3 and tls 1.2.
    """
    set_tls13_ciphersuites = getattr(ssl_context, 'set_ciphersuites', None)

    if callable(set_tls13_ciphersuites) and options.tls_ciphers.v1_3_ciphers:
        set_tls13_ciphersuites(':'.join(options.tls_ciphers.v1_3_ciphers))
    elif options.tls_ciphers.v1_3_ciphers:
        emit_warning(
            'tls 1.3 ciphersuites requested but set_ciphersuites is unavailable; runtime defaults will be used',
            category=TLSSecurityDegradation,
        )

    if options.tls_ciphers.v1_2_ciphers:
        ssl_context.set_ciphers(':'.join(options.tls_ciphers.v1_2_ciphers))


def register_ecdh_curve(ssl_context: ssl.SSLContext, options: SSLContextOptions) -> None:
    """
    apply preferred ecdh curve selection with fallback.
    """
    try:
        ssl_context.set_ecdh_curve(options.ecdh_curve)
    except (ssl.SSLError, NotImplementedError) as exc:
        logger.warning(
            'failed to set preferred ecdh curve=%s (reason=%r)', options.ecdh_curve, exc
        )
        with on_error_emit_warning(
            f'failed to set fallback ecdh curve={options.fallback_ecdh_curve!s}; no curve was set for the ssl context',
            catch=(ssl.SSLError, NotImplementedError),
            category=TLSSecurityDegradation,
            stacklevel=4,
        ):
            ssl_context.set_ecdh_curve(options.fallback_ecdh_curve)


def register_verify_flags(
    ssl_context: ssl.SSLContext, options: SSLContextOptions
) -> None:
    """
    apply x509 verification flags and optional crl checking.

    notes
    -----
    this does not disable verification. it tunes how verification is performed.
    trust roots and verify semantics still come from httpx's `verify=`.
    """
    if options.verify_flags is not None:
        ssl_context.verify_flags = options.verify_flags

    if options.enable_crl_check and hasattr(ssl, 'VERIFY_CRL_CHECK_LEAF'):
        ssl_context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF


def apply_ssl_options(
    ssl_context: ssl.SSLContext, options: SSLContextOptions
) -> ssl.SSLContext:
    """
    apply `SSLContextOptions` to an existing `ssl.SSLContext`.

    this is the integration point for httpx:
    - httpx creates/owns trust roots, verify semantics, and client certs
    - reconoscope tunes the resulting context for security/perf posture

    parameters
    ----------
    ssl_context:
        an existing ssl context to tune.
    options:
        tuning policy.

    returns
    -------
    ssl.SSLContext
        the same context instance, tuned.

    warns
    -----
    TLSSecurityDegradation
            emitted when requested security-relevant configuration cannot be applied.
    TLSConfigurationWarning
            emitted when optional configuration cannot be applied.
    """
    register_tls_versions(ssl_context, options)
    set_alpn_protocols(ssl_context, options)

    with on_error_emit_warning(
        'one or more requested ssl security options were not set',
        catch=(ssl.SSLError, Exception),
        category=TLSSecurityDegradation,
    ):
        register_ssl_option_flags(ssl_context, options)

    with on_error_emit_warning(
        'failed to set one or more tls ciphers/ciphersuites; runtime defaults will be used',
        catch=(ssl.SSLError, NotImplementedError),
        category=TLSSecurityDegradation,
        stacklevel=4,
    ):
        register_tls_ciphers(ssl_context, options)

    register_ecdh_curve(ssl_context, options)

    with on_error_emit_warning(
        'failed to set one or more verification flags',
        catch=(AttributeError, ssl.SSLError),
        category=TLSConfigurationWarning,
        stacklevel=4,
    ):
        register_verify_flags(ssl_context, options)

    return ssl_context


def build_ssl_context(options: SSLContextOptions) -> ssl.SSLContext:
    """
    create and tune an ssl context using `SSLContextOptions`.

    this is a convenience for cases where you *do* want a context object, but it
    still does not load trust roots or client certs. those belong to httpx.

    returns
    -------
    ssl.SSLContext
        a tuned context suitable for passing to httpx as `verify=ssl_context`.
    """
    ssl_context = create_initial_context()
    return apply_ssl_options(ssl_context, options)
