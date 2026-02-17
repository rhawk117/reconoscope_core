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
    from reconoscope.sdk.ssl.options import SSLContextOptions

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


def create_initial_context(options: SSLContextOptions) -> ssl.SSLContext:
    """
    create a base client context using the system (or provided) trust store.

    parameters
    ----------
    options:
            ssl context policy settings including optional trust store overrides and
            tls min/max version bounds.

    returns
    -------
    ssl.SSLContext
            a context initialized with trust roots and tls version bounds.

    notes
    -----
    this step should be boring. if it isn't, something is wrong with the
    environment, not your cipher list.
    """
    ssl_context = ssl.create_default_context(
        purpose=ssl.Purpose.SERVER_AUTH,
        cafile=options.cafile,
        capath=options.capath,
        cadata=options.cadata,
    )
    ssl_context.minimum_version = options.tls_min_version
    ssl_context.maximum_version = options.tls_max_version
    return ssl_context


def set_alpn_protocols(ssl_context: ssl.SSLContext, options: SSLContextOptions) -> None:
    """
    configure alpn protocols (http/2 + fallback).

    parameters
    ----------
    ssl_context:
            the context being configured.
    options:
            policy containing `alpn_protocols`.

    notes
    -----
    if this fails, you will probably still connect. you just won't negotiate h2.
    you can enjoy your artisanal http/1.1 latency.
    """
    if not options.alpn_protocols:
        return

    with on_error_emit_warning(
        'alpn is not supported by this python/openssl build; http/2 may not negotiate',
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
    """
    apply an ssl option once and only once.

    parameters
    ----------
    seen:
            set of already-applied ssl option flags.
    option:
            option flag to apply.
    ssl_context:
            context to mutate.

    notes
    -----
    duplicate flags are harmless because bitmasks, but humans love to paste the
    same thing twice and then ask why their output is noisy.
    """
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

    parameters
    ----------
    ssl_context:
            the context being configured.
    options:
            policy toggles controlling which hardening flags are applied.

    notes
    -----
    failures here should be treated as security degradation, because the whole
    point is to harden the context. otherwise you're just setting booleans for fun.
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


def register_tls_ciphers(ssl_context: ssl.SSLContext, options: SSLContextOptions) -> None:
    """
    apply tls cipher configuration for tls 1.3 and tls 1.2.

    parameters
    ----------
    ssl_context:
            the context being configured.
    options:
            policy containing `tls_ciphers`.

    notes
    -----
    - tls 1.3 uses `set_ciphersuites` (when available).
    - tls 1.2 uses `set_ciphers`.

    if a caller provided a cipher list and it can't be applied, that is a real
    security downgrade, not a quirky platform difference.
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

    parameters
    ----------
    ssl_context:
            the context being configured.
    options:
            policy containing `ecdh_curve` and `fallback_ecdh_curve`.

    notes
    -----
    this is best-effort because tls stacks have opinions. if both attempts fail,
    you should know about it, because you did not get what you asked for.
    """
    try:
        ssl_context.set_ecdh_curve(options.ecdh_curve)
    except (ssl.SSLError, NotImplementedError) as exc:
        # logging is appropriate here because the failure is actionable and has a real exception.
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

    parameters
    ----------
    ssl_context:
            the context being configured.
    options:
            policy containing `verify_flags` and `enable_crl_check`.

    notes
    -----
    crl checking only helps if you actually have crls available. turning it on
    does not summon revocation data out of the ether.
    """
    if options.verify_flags is not None:
        ssl_context.verify_flags = options.verify_flags

    if options.enable_crl_check and hasattr(ssl, 'VERIFY_CRL_CHECK_LEAF'):
        ssl_context.verify_flags |= ssl.VERIFY_CRL_CHECK_LEAF


def register_mtls_client_cert(
    ssl_context: ssl.SSLContext, options: SSLContextOptions
) -> None:
    """
    load the client certificate chain for mutual tls.

    parameters
    ----------
    ssl_context:
            the context being configured.
    options:
            policy containing client certificate configuration.

    notes
    -----
    if you asked for mtls and loading fails, that should be a hard failure.
    otherwise you'll think you're doing client auth while you're actually not.
    """
    if not options.client_certfile:
        return

    ssl_context.load_cert_chain(
        certfile=options.client_certfile,
        keyfile=options.client_keyfile,
        password=options.client_key_password,
    )


def register_keylog(ssl_context: ssl.SSLContext, options: SSLContextOptions) -> None:
    """
    enable tls key logging for debugging (wireshark).

    parameters
    ----------
    ssl_context:
            the context being configured.
    options:
            policy containing `keylog_filename`.

    notes
    -----
    if you enable this in production, at least have the courage to write it in
    your threat model: "we log session keys because it was convenient."
    """
    if not options.keylog_filename:
        return

    ssl_context.keylog_filename = options.keylog_filename


def build_ssl_context(options: SSLContextOptions) -> ssl.SSLContext:
    """
    build an `ssl.SSLContext` from `SSLContextOptions`.

    this is the centralized tls policy builder. it's supposed to be boring,
    predictable, and hard to misuse. humans will still try, but we can at least
    make it inconvenient.

    parameters
    ----------
    options:
            configuration policy for the ssl context.

    returns
    -------
    ssl.SSLContext
            a configured client ssl context ready for https connections.

    warns
    -----
    TLSSecurityDegradation
            emitted when requested security-relevant configuration cannot be applied.
    TLSConfigurationWarning
            emitted when optional configuration cannot be applied.

    notes
    -----
    if you want strict mode, configure your warnings filters so that
    `TLSSecurityDegradation` becomes an exception. python lets you do that.
    """
    ssl_context = create_initial_context(options)

    ssl_context.check_hostname = options.check_hostname
    ssl_context.verify_mode = options.verify_mode

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

    # if mtls is requested and fails, it should raise. no pretending.
    register_mtls_client_cert(ssl_context, options)

    # keylog is explicit opt-in. if it fails, that's a configuration issue.
    with on_error_emit_warning(
        'failed to enable tls key logging',
        catch=(Exception,),
        category=TLSConfigurationWarning,
        stacklevel=4,
    ):
        register_keylog(ssl_context, options)

    return ssl_context
