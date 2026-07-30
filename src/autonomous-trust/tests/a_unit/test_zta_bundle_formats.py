# ******************
#  Copyright 2026 TekFive, Inc., Sean M. Brennan, and contributors
#
#   Licensed under the Apache License, Version 2.0 (the "License");
#   you may not use this file except in compliance with the License.
#   You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS,
#   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#   See the License for the specific language governing permissions and
#   limitations under the License.
# ******************
"""CA-bundle loading: which encodings `X509Verifier` accepts, and what it says
when handed the wrong kind of file.

PKCS#7 (`.p7b`) is the format agency PKI (incl. DoD) normally ships chains in, so
it loads natively rather than requiring an out-of-band
``openssl pkcs7 -print_certs`` conversion. And a CRL / private key / CSR dropped
into the ``--ca-bundle`` slot used to leave an empty trust store, making every
credential REJECTED for 'unable to get local issuer certificate' -- blaming the
peer for a local file mix-up. Each is now named."""
import os
import sys
import warnings

import pytest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = _HERE
while _ROOT != os.path.dirname(_ROOT):
    if os.path.isfile(os.path.join(_ROOT, 'tools', 'provision_zta_certs.py')):
        break
    _ROOT = os.path.dirname(_ROOT)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)  # importable minting helpers in tools/

pytest.importorskip('cryptography')

from tools.provision_zta_certs import (  # noqa: E402
    make_ca, make_leaf_keypair, ca_bundle_pem, cert_der, make_crl)

from autonomous_trust.core.identity.zta import ZtaStatus, X509Verifier  # noqa: E402


@pytest.fixture(scope='module')
def pki():
    """A CA, a leaf it issued, and that leaf's DER credential."""
    ca_key, ca_cert = make_ca('Bundle Test CA')
    leaf_key, leaf = make_leaf_keypair('peer-1', ca_key, ca_cert)
    return {'ca_key': ca_key, 'ca_cert': ca_cert, 'leaf_key': leaf_key,
            'leaf': leaf, 'cred': cert_der(leaf)}


def _write(tmp_path, name, data: bytes) -> str:
    path = tmp_path / name
    path.write_bytes(data)
    return str(path)


def _p7b(certs, encoding_name: str) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, pkcs7
    return pkcs7.serialize_certificates(list(certs),
                                        getattr(Encoding, encoding_name))


class TestAcceptedEncodings:
    """Every encoding a CA bundle legitimately arrives in must verify a leaf."""

    def test_concatenated_pem(self, pki, tmp_path):
        bundle = _write(tmp_path, 'ca.pem', ca_bundle_pem(pki['ca_cert']))
        r = X509Verifier(bundle).verify_credential(pki['cred'])
        assert r.status is ZtaStatus.VERIFIED, r.reason

    def test_single_der_cert(self, pki, tmp_path):
        bundle = _write(tmp_path, 'ca.der', cert_der(pki['ca_cert']))
        r = X509Verifier(bundle).verify_credential(pki['cred'])
        assert r.status is ZtaStatus.VERIFIED, r.reason

    def test_der_pkcs7(self, pki, tmp_path):
        # the DoD-style .p7b: previously store=0 and a bogus issuer complaint
        bundle = _write(tmp_path, 'ca.p7b', _p7b([pki['ca_cert']], 'DER'))
        v = X509Verifier(bundle)
        assert v.is_available() is True
        assert v.bundle_error == ''
        r = v.verify_credential(pki['cred'])
        assert r.status is ZtaStatus.VERIFIED, r.reason

    def test_pem_wrapped_pkcs7(self, pki, tmp_path):
        bundle = _write(tmp_path, 'ca_pem.p7b', _p7b([pki['ca_cert']], 'PEM'))
        assert b'BEGIN PKCS7' in (tmp_path / 'ca_pem.p7b').read_bytes()
        r = X509Verifier(bundle).verify_credential(pki['cred'])
        assert r.status is ZtaStatus.VERIFIED, r.reason

    def test_multi_cert_pkcs7_loads_every_anchor(self, pki, tmp_path):
        # a real chain bundle holds root + intermediates; all become anchors
        other_key, other_ca = make_ca('Second CA')
        _leaf2_key, leaf2 = make_leaf_keypair('peer-2', other_key, other_ca)
        bundle = _write(tmp_path, 'multi.p7b',
                        _p7b([pki['ca_cert'], other_ca], 'DER'))
        v = X509Verifier(bundle)
        assert len(v._store) == 2
        assert v.verify_credential(pki['cred']).status is ZtaStatus.VERIFIED
        assert v.verify_credential(cert_der(leaf2)).status is ZtaStatus.VERIFIED

    def test_pkcs7_parse_emits_no_warning_to_callers(self, pki, tmp_path):
        # agency p7b files are often BER-encoded; pyca's UserWarning about that
        # is not actionable and must not leak into a TUI's stderr
        bundle = _write(tmp_path, 'ca.p7b', _p7b([pki['ca_cert']], 'DER'))
        with warnings.catch_warnings():
            warnings.simplefilter('error')  # any warning becomes a failure
            v = X509Verifier(bundle)
        assert v.is_available() is True

    def test_pkcs7_rejects_a_leaf_it_does_not_anchor(self, pki, tmp_path):
        # sanity: p7b support must not make everything verify
        stranger_key, stranger_ca = make_ca('Not Our CA')
        _s_key, stranger = make_leaf_keypair('stranger', stranger_key, stranger_ca)
        bundle = _write(tmp_path, 'ca.p7b', _p7b([pki['ca_cert']], 'DER'))
        r = X509Verifier(bundle).verify_credential(cert_der(stranger))
        assert r.status is ZtaStatus.REJECTED
        assert 'issuer' in r.reason


class TestWrongKindOfFile:
    """The bundle slot names what it was actually given."""

    def _reject_reason(self, bundle, pki):
        v = X509Verifier(bundle)
        assert v.is_available() is False
        assert v.bundle_error, 'a bad bundle must record why'
        r = v.verify_credential(pki['cred'])
        assert r.status is ZtaStatus.REJECTED
        assert len(r.credential_hash) == 32  # hash still computed for binding
        return r.reason

    def test_pem_crl(self, pki, tmp_path):
        crl = make_crl(pki['ca_key'], pki['ca_cert'], [])
        reason = self._reject_reason(_write(tmp_path, 'x.crl', crl), pki)
        assert 'CRL' in reason
        assert 'crl_path' in reason        # points at where it does belong
        assert 'issuer certificate' not in reason  # not the old misleading text

    def test_der_crl(self, pki, tmp_path):
        # agency CRLs are usually DER, which carries no PEM marker to match
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        crl = x509.load_pem_x509_crl(make_crl(pki['ca_key'], pki['ca_cert'], []))
        reason = self._reject_reason(
            _write(tmp_path, 'x.crl', crl.public_bytes(Encoding.DER)), pki)
        assert 'CRL' in reason and 'crl_path' in reason

    def test_private_key(self, pki, tmp_path):
        from cryptography.hazmat.primitives import serialization as ser
        key_pem = pki['leaf_key'].private_bytes(
            ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.NoEncryption())
        reason = self._reject_reason(_write(tmp_path, 'k.pem', key_pem), pki)
        assert 'private key' in reason

    def test_csr(self, pki, tmp_path):
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization as ser
        from cryptography.x509.oid import NameOID
        csr = (x509.CertificateSigningRequestBuilder()
               .subject_name(x509.Name([
                   x509.NameAttribute(NameOID.COMMON_NAME, 'peer-1')]))
               .sign(pki['leaf_key'], hashes.SHA256()))
        reason = self._reject_reason(
            _write(tmp_path, 'r.csr', csr.public_bytes(ser.Encoding.PEM)), pki)
        assert 'request' in reason and 'CSR' in reason

    def test_empty_file(self, pki, tmp_path):
        assert 'empty' in self._reject_reason(_write(tmp_path, 'e.pem', b''), pki)

    def test_unrecognized_junk(self, pki, tmp_path):
        reason = self._reject_reason(_write(tmp_path, 'j.pem', b'hello world'), pki)
        assert 'unrecognized' in reason
        assert 'PKCS#7' in reason  # lists what would have been accepted

    def test_missing_file_names_the_path(self, pki, tmp_path):
        missing = str(tmp_path / 'absent.pem')
        reason = self._reject_reason(missing, pki)
        assert 'absent.pem' in reason
        assert 'could not be read' in reason

    def test_no_bundle_configured(self, pki):
        reason = self._reject_reason('', pki)
        assert 'no CA bundle configured' in reason

    def test_reason_names_the_offending_path(self, pki, tmp_path):
        crl = make_crl(pki['ca_key'], pki['ca_cert'], [])
        reason = self._reject_reason(_write(tmp_path, 'oops.crl', crl), pki)
        assert 'oops.crl' in reason  # which file, not just what kind


class TestCrlEncodings:
    """`check_revocation` accepts a CRL in either encoding, and says so when it
    cannot use the file at all.

    A DER CRL -- the usual agency encoding -- previously parsed as nothing and
    fell through to UNAVAILABLE 'no revocation source configured', which is
    indistinguishable from having configured no CRL: the check silently did
    nothing while appearing wired up."""

    def _verified(self, bundle, crl_path, pki):
        v = X509Verifier(bundle, '', crl_path)
        r = v.verify_credential(pki['cred'])
        assert r.status is ZtaStatus.VERIFIED, r.reason
        return v, r.credential_hash

    def test_pem_crl_not_revoked(self, pki, tmp_path):
        bundle = _write(tmp_path, 'ca.pem', ca_bundle_pem(pki['ca_cert']))
        crl = _write(tmp_path, 'x.crl', make_crl(pki['ca_key'], pki['ca_cert'], []))
        v, h = self._verified(bundle, crl, pki)
        assert v.check_revocation(h).status is ZtaStatus.VERIFIED

    def test_der_crl_not_revoked(self, pki, tmp_path):
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        pem = make_crl(pki['ca_key'], pki['ca_cert'], [])
        der = x509.load_pem_x509_crl(pem).public_bytes(Encoding.DER)
        bundle = _write(tmp_path, 'ca.pem', ca_bundle_pem(pki['ca_cert']))
        v, h = self._verified(bundle, _write(tmp_path, 'x.crl', der), pki)
        r = v.check_revocation(h)
        assert r.status is ZtaStatus.VERIFIED, r.reason
        assert 'CRL loaded' in r.reason  # actually consulted, not skipped

    def test_der_crl_detects_revocation(self, pki, tmp_path):
        # the case that silently passed before: a revoked cert in a DER CRL
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        pem = make_crl(pki['ca_key'], pki['ca_cert'], [pki['leaf'].serial_number])
        der = x509.load_pem_x509_crl(pem).public_bytes(Encoding.DER)
        bundle = _write(tmp_path, 'ca.pem', ca_bundle_pem(pki['ca_cert']))
        v, h = self._verified(bundle, _write(tmp_path, 'x.crl', der), pki)
        assert v.check_revocation(h).status is ZtaStatus.REVOKED

    def test_pem_and_der_agree(self, pki, tmp_path):
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        pem = make_crl(pki['ca_key'], pki['ca_cert'], [pki['leaf'].serial_number])
        der = x509.load_pem_x509_crl(pem).public_bytes(Encoding.DER)
        bundle = _write(tmp_path, 'ca.pem', ca_bundle_pem(pki['ca_cert']))
        out = []
        for name, data in (('p.crl', pem), ('d.crl', der)):
            v, h = self._verified(bundle, _write(tmp_path, name, data), pki)
            out.append(v.check_revocation(h).status)
        assert out[0] is out[1] is ZtaStatus.REVOKED

    def test_p7b_bundle_with_der_crl(self, pki, tmp_path):
        # the operator's actual file pair: .p7b chain + DER .crl
        from cryptography import x509
        from cryptography.hazmat.primitives.serialization import Encoding
        der = x509.load_pem_x509_crl(
            make_crl(pki['ca_key'], pki['ca_cert'],
                     [pki['leaf'].serial_number])).public_bytes(Encoding.DER)
        bundle = _write(tmp_path, 'ca.p7b', _p7b([pki['ca_cert']], 'DER'))
        v, h = self._verified(bundle, _write(tmp_path, 'x.crl', der), pki)
        assert v.check_revocation(h).status is ZtaStatus.REVOKED

    def test_unusable_crl_is_not_reported_as_no_source(self, pki, tmp_path):
        bundle = _write(tmp_path, 'ca.pem', ca_bundle_pem(pki['ca_cert']))
        v, h = self._verified(bundle, _write(tmp_path, 'j.crl', b'junk'), pki)
        r = v.check_revocation(h)
        assert r.status is ZtaStatus.UNAVAILABLE
        assert 'no revocation source configured' not in r.reason
        assert 'j.crl' in r.reason and 'could not be parsed' in r.reason

    def test_unusable_crl_never_reads_as_not_revoked(self, pki, tmp_path):
        # fail-closed: a check that cannot run must not look like a clean result
        bundle = _write(tmp_path, 'ca.pem', ca_bundle_pem(pki['ca_cert']))
        for name, data in (('j.crl', b'junk'), ('e.crl', b'')):
            v, h = self._verified(bundle, _write(tmp_path, name, data), pki)
            assert v.check_revocation(h).status is not ZtaStatus.VERIFIED

    def test_certificate_in_the_crl_slot(self, pki, tmp_path):
        # the reverse swap of the bundle case
        bundle = _write(tmp_path, 'ca.pem', ca_bundle_pem(pki['ca_cert']))
        wrong = _write(tmp_path, 'oops.crl', ca_bundle_pem(pki['ca_cert']))
        v, h = self._verified(bundle, wrong, pki)
        r = v.check_revocation(h)
        assert r.status is ZtaStatus.UNAVAILABLE
        assert 'certificate, not a CRL' in r.reason
        assert 'CA bundle' in r.reason  # says where it belongs

    def test_der_certificate_in_the_crl_slot(self, pki, tmp_path):
        bundle = _write(tmp_path, 'ca.pem', ca_bundle_pem(pki['ca_cert']))
        wrong = _write(tmp_path, 'oops.crl', cert_der(pki['ca_cert']))
        v, h = self._verified(bundle, wrong, pki)
        assert 'not a CRL' in v.check_revocation(h).reason

    def test_missing_crl_names_the_path(self, pki, tmp_path):
        bundle = _write(tmp_path, 'ca.pem', ca_bundle_pem(pki['ca_cert']))
        v, h = self._verified(bundle, str(tmp_path / 'gone.crl'), pki)
        r = v.check_revocation(h)
        assert r.status is ZtaStatus.UNAVAILABLE
        assert 'gone.crl' in r.reason and 'could not be read' in r.reason

    def test_no_crl_configured_is_unchanged(self, pki, tmp_path):
        bundle = _write(tmp_path, 'ca.pem', ca_bundle_pem(pki['ca_cert']))
        v, h = self._verified(bundle, '', pki)
        r = v.check_revocation(h)
        assert r.status is ZtaStatus.UNAVAILABLE
        assert r.reason == 'no revocation source configured'

    def test_ocsp_only_is_unchanged(self, pki, tmp_path):
        bundle = _write(tmp_path, 'ca.pem', ca_bundle_pem(pki['ca_cert']))
        v = X509Verifier(bundle, 'http://ocsp.example', '')
        h = v.verify_credential(pki['cred']).credential_hash
        r = v.check_revocation(h)
        assert r.status is ZtaStatus.UNAVAILABLE
        assert 'OCSP' in r.reason


class TestUnchangedBehavior:
    """The diagnostics must not alter any verdict."""

    def test_good_bundle_has_no_error(self, pki, tmp_path):
        bundle = _write(tmp_path, 'ca.pem', ca_bundle_pem(pki['ca_cert']))
        assert X509Verifier(bundle).bundle_error == ''

    def test_bad_bundle_still_rejects_not_unavailable(self, pki, tmp_path):
        # C parity: no anchor means REJECTED, not a new status
        reason_status = X509Verifier(
            _write(tmp_path, 'j.pem', b'junk')).verify_credential(pki['cred'])
        assert reason_status.status is ZtaStatus.REJECTED

    def test_expired_still_wins_over_bundle_error(self, pki, tmp_path):
        # ordering is unchanged: expiry is checked before the chain walk
        import datetime
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes
        from cryptography.x509.oid import NameOID
        past = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=10)
        expired = (x509.CertificateBuilder()
                   .subject_name(x509.Name([
                       x509.NameAttribute(NameOID.COMMON_NAME, 'old')]))
                   .issuer_name(pki['ca_cert'].subject)
                   .public_key(pki['leaf_key'].public_key())
                   .serial_number(x509.random_serial_number())
                   .not_valid_before(past - datetime.timedelta(days=1))
                   .not_valid_after(past)
                   .sign(pki['ca_key'], hashes.SHA256()))
        v = X509Verifier(_write(tmp_path, 'j.pem', b'junk'))
        assert v.verify_credential(cert_der(expired)).status is ZtaStatus.EXPIRED

    def test_crl_still_works_in_its_own_slot(self, pki, tmp_path):
        # the file the operator has is usable -- just not as the bundle
        bundle = _write(tmp_path, 'ca.pem', ca_bundle_pem(pki['ca_cert']))
        crl = _write(tmp_path, 'x.crl', make_crl(pki['ca_key'], pki['ca_cert'], []))
        v = X509Verifier(bundle, '', crl)
        r = v.verify_credential(pki['cred'])
        assert r.status is ZtaStatus.VERIFIED
        rev = v.check_revocation(r.credential_hash)
        assert rev.status is ZtaStatus.VERIFIED
        assert 'CRL loaded' in rev.reason

    def test_revoked_via_crl_with_p7b_bundle(self, pki, tmp_path):
        # p7b bundle + CRL together, the operator's actual file pair
        bundle = _write(tmp_path, 'ca.p7b', _p7b([pki['ca_cert']], 'DER'))
        crl = _write(tmp_path, 'x.crl',
                     make_crl(pki['ca_key'], pki['ca_cert'],
                              [pki['leaf'].serial_number]))
        v = X509Verifier(bundle, '', crl)
        r = v.verify_credential(pki['cred'])
        assert r.status is ZtaStatus.VERIFIED  # chain is fine
        assert v.check_revocation(r.credential_hash).status is ZtaStatus.REVOKED
