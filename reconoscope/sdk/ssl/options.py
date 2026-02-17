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

    attributes
    ----------
    v1_3_ciphers:
            tls 1.3 cipher suite names (openssl format).
    v1_2_ciphers:
            tls 1.2 cipher suite names (openssl cipher string entries).

    notes
    -----
    - tls 1.3 cipher selection requires `SSLContext.set_ciphersuites` on the
      runtime. if it's missing, the default openssl list wins.
    - tls 1.2 cipher selection uses `SSLContext.set_ciphers` and is generally supported.
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

        returns
        -------
        TLSCipherSuite
                a (tls 1.3, tls 1.2) policy pair.
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
    policy object for building a secure client-side `ssl.SSLContext`.

    this keeps tls configuration centralized so you do not end up with:
    - one code path doing "secure defaults"
    - another doing "whatever works in prod"
    - and a third doing "please don't look at this, it's complicated"

    parameters
    ----------
    tls_min_version:
            minimum tls version to allow. default is tls 1.2.
    tls_max_version:
            maximum tls version to allow. default is `MAXIMUM_SUPPORTED`.
    check_hostname:
            whether hostname validation is enabled. this should almost always be true.
    verify_mode:
            certificate verification mode. default is `CERT_REQUIRED`.
    cafile, capath, cadata:
            optional trust store overrides. if all are none, system trust is used.
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
    client_certfile, client_keyfile, client_key_password:
            optional mutual tls (client auth).
    keylog_filename:
            enables tls key logging (wireshark). do not do this in production unless
            your threat model is "i trust everyone forever".

    raises
    ------
    ValueError
            if `verify_mode` disables verification while `check_hostname` is enabled.

    notes
    -----
    "secure by default" still means you can override it, because humans insist on
    learning lessons the hard way. this at least makes the sharp edges obvious.
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

    def __post_init__(self) -> None:
        if self.verify_mode == ssl.CERT_NONE and self.check_hostname:
            raise ValueError(
                'invalid tls policy: verify_mode=CERT_NONE cannot be used '
                'with check_hostname=True.'
            )
