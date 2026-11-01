"""Master key, HKDF subkeys, and AES-256-GCM envelopes (SPEC §7)."""

import base64
import hashlib
import hmac
import pickle
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st

from agent_gateway.modules.crypto.envelope import AesGcmEnvelopeCipher, envelope_key_version
from agent_gateway.modules.crypto.keyring import MasterKeyRing, derive_subkey, generate_master_key
from agent_gateway.modules.crypto.ports import (
    ENVELOPE_HEADER_BYTES,
    ENVELOPE_MAGIC,
    NONCE_BYTES,
    TAG_BYTES,
    CryptoError,
    KeyRing,
    MasterKeyError,
    SubkeyPurpose,
    credential_aad,
)

MASTER_KEY = bytes(range(32))
AAD = credential_aad("cred_01JB8ABCDEFGHJKMNPQRSTVWXY", 1)


def rfc5869_hkdf_sha256(ikm: bytes, info: bytes, length: int = 32) -> bytes:
    """Independent HKDF reference (RFC 5869) with an empty salt."""
    prk = hmac.new(b"\x00" * 32, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes([counter]), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


@pytest.fixture
def keyring() -> MasterKeyRing:
    return MasterKeyRing(MASTER_KEY)


@pytest.fixture
def cipher(keyring: MasterKeyRing) -> AesGcmEnvelopeCipher:
    return AesGcmEnvelopeCipher.for_credentials(keyring)


class TestMasterKeyFile:
    def test_loads_base64_key(self, tmp_path: Path) -> None:
        path = tmp_path / "master.key"
        path.write_text(base64.b64encode(MASTER_KEY).decode() + "\n", encoding="ascii")
        ring = MasterKeyRing.from_file(path, key_version=3)
        assert ring.key_version == 3
        assert ring.subkey(SubkeyPurpose.CREDENTIALS) == derive_subkey(
            MASTER_KEY, SubkeyPurpose.CREDENTIALS
        )

    def test_generated_key_loads(self, tmp_path: Path) -> None:
        path = tmp_path / "master.key"
        path.write_text(generate_master_key(), encoding="ascii")
        assert MasterKeyRing.from_file(path).key_version == 1
        assert generate_master_key() != generate_master_key()

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(MasterKeyError, match="cannot read"):
            MasterKeyRing.from_file(tmp_path / "nope.key")

    @pytest.mark.parametrize(
        ("content", "message"),
        [
            (b"", "exactly 32 bytes"),
            (base64.b64encode(bytes(31)), "exactly 32 bytes"),
            (base64.b64encode(bytes(33)), "exactly 32 bytes"),
            (b"not base64 !!", "not valid base64"),
            (b"\xff\xfe", "not valid base64"),
            (bytes(range(32)), "not valid base64"),
            (b"A" * 2000, "too large"),
        ],
    )
    def test_rejects_bad_key_files(self, tmp_path: Path, content: bytes, message: str) -> None:
        path = tmp_path / "master.key"
        path.write_bytes(content)
        with pytest.raises(MasterKeyError, match=message) as info:
            MasterKeyRing.from_file(path)
        assert info.value.__cause__ is None

    def test_error_never_contains_key_material(self, tmp_path: Path) -> None:
        path = tmp_path / "master.key"
        encoded = base64.b64encode(bytes(31)).decode()
        path.write_text(encoded, encoding="ascii")
        with pytest.raises(MasterKeyError) as info:
            MasterKeyRing.from_file(path)
        assert encoded not in str(info.value)

    @pytest.mark.parametrize("length", [0, 16, 31, 33, 64])
    def test_rejects_wrong_length(self, length: int) -> None:
        with pytest.raises(MasterKeyError):
            MasterKeyRing(bytes(length))

    @pytest.mark.parametrize("version", [0, -1, 256])
    def test_rejects_bad_key_version(self, version: int) -> None:
        with pytest.raises(MasterKeyError, match="key version"):
            MasterKeyRing(MASTER_KEY, key_version=version)


class TestSubkeys:
    def test_satisfies_protocol(self, keyring: MasterKeyRing) -> None:
        ring: KeyRing = keyring
        assert ring.key_version == 1

    @pytest.mark.parametrize("purpose", list(SubkeyPurpose))
    def test_matches_rfc5869_reference(
        self, keyring: MasterKeyRing, purpose: SubkeyPurpose
    ) -> None:
        expected = rfc5869_hkdf_sha256(MASTER_KEY, purpose.value.encode())
        assert keyring.subkey(purpose) == expected
        assert len(expected) == 32

    def test_info_strings_match_spec(self) -> None:
        assert SubkeyPurpose.CREDENTIALS.value == "agw/credentials/v1"
        assert SubkeyPurpose.TOKEN_HMAC.value == "agw/token-hmac/v1"
        assert SubkeyPurpose.AUDIT_ANCHOR.value == "agw/audit-anchor/v1"

    def test_subkeys_are_independent(self, keyring: MasterKeyRing) -> None:
        subkeys = {keyring.subkey(purpose) for purpose in SubkeyPurpose}
        assert len(subkeys) == len(SubkeyPurpose)
        assert MASTER_KEY not in subkeys

    def test_subkeys_are_stable_and_key_dependent(self, keyring: MasterKeyRing) -> None:
        purpose = SubkeyPurpose.TOKEN_HMAC
        assert keyring.subkey(purpose) == keyring.subkey(purpose)
        assert MasterKeyRing(bytes(32)).subkey(purpose) != keyring.subkey(purpose)

    def test_repr_hides_key_material(self, keyring: MasterKeyRing) -> None:
        keyring.subkey(SubkeyPurpose.CREDENTIALS)
        for text in (repr(keyring), str(keyring)):
            assert "***" in text
            assert MASTER_KEY.hex() not in text
            assert str(MASTER_KEY) not in text

    def test_cannot_be_pickled(self, keyring: MasterKeyRing) -> None:
        with pytest.raises(TypeError):
            pickle.dumps(keyring)

    def test_master_key_is_not_an_attribute(self, keyring: MasterKeyRing) -> None:
        assert not hasattr(keyring, "__dict__")
        assert not hasattr(keyring, "master_key")


class TestEnvelope:
    def test_round_trip(self, cipher: AesGcmEnvelopeCipher) -> None:
        plaintext = b'{"type": "api_token", "value": "secret"}'
        envelope = cipher.seal(plaintext, AAD)
        assert cipher.open(envelope, AAD) == plaintext
        assert plaintext not in envelope

    def test_layout_matches_spec(self, keyring: MasterKeyRing) -> None:
        cipher = AesGcmEnvelopeCipher(keyring.subkey(SubkeyPurpose.CREDENTIALS), key_version=7)
        envelope = cipher.seal(b"hello", AAD)
        assert envelope[0:4] == b"AGWC" == ENVELOPE_MAGIC
        assert envelope[4] == 0x01
        assert envelope[5] == 7
        assert ENVELOPE_HEADER_BYTES == 18
        assert len(envelope) == 18 + len(b"hello") + TAG_BYTES
        assert envelope_key_version(envelope) == 7

    def test_decryptable_with_plain_aesgcm(self, keyring: MasterKeyRing) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        key = keyring.subkey(SubkeyPurpose.CREDENTIALS)
        envelope = AesGcmEnvelopeCipher(key, key_version=1).seal(b"interop", AAD)
        nonce = envelope[6 : 6 + NONCE_BYTES]
        assert AESGCM(key).decrypt(nonce, envelope[18:], AAD) == b"interop"

    def test_empty_plaintext(self, cipher: AesGcmEnvelopeCipher) -> None:
        assert cipher.open(cipher.seal(b"", AAD), AAD) == b""

    @pytest.mark.parametrize(
        "wrong_aad",
        [
            credential_aad("cred_01JB8ABCDEFGHJKMNPQRSTVWXY", 2),
            credential_aad("cred_01JB8ABCDEFGHJKMNPQRSTVWXZ", 1),
            b"",
            AAD + b"x",
        ],
    )
    def test_wrong_aad_fails(self, cipher: AesGcmEnvelopeCipher, wrong_aad: bytes) -> None:
        envelope = cipher.seal(b"secret", AAD)
        with pytest.raises(CryptoError, match="authentication failed"):
            cipher.open(envelope, wrong_aad)

    def test_wrong_key_fails(self, cipher: AesGcmEnvelopeCipher) -> None:
        other = AesGcmEnvelopeCipher.for_credentials(MasterKeyRing(bytes(32)))
        with pytest.raises(CryptoError):
            other.open(cipher.seal(b"secret", AAD), AAD)

    def test_other_subkey_fails(self, keyring: MasterKeyRing, cipher: AesGcmEnvelopeCipher) -> None:
        other = AesGcmEnvelopeCipher(keyring.subkey(SubkeyPurpose.TOKEN_HMAC), key_version=1)
        with pytest.raises(CryptoError):
            other.open(cipher.seal(b"secret", AAD), AAD)

    def test_every_single_byte_tamper_fails(self, cipher: AesGcmEnvelopeCipher) -> None:
        envelope = cipher.seal(b"a credential value", AAD)
        for index in range(len(envelope)):
            tampered = bytearray(envelope)
            tampered[index] ^= 0x01
            with pytest.raises(CryptoError):
                cipher.open(bytes(tampered), AAD)

    def test_truncated_and_extended_envelopes_fail(self, cipher: AesGcmEnvelopeCipher) -> None:
        envelope = cipher.seal(b"secret", AAD)
        for length in range(len(envelope)):
            with pytest.raises(CryptoError):
                cipher.open(envelope[:length], AAD)
        with pytest.raises(CryptoError):
            cipher.open(envelope + b"\x00", AAD)

    def test_wrong_magic_rejected(self, cipher: AesGcmEnvelopeCipher) -> None:
        envelope = cipher.seal(b"secret", AAD)
        with pytest.raises(CryptoError, match="magic"):
            cipher.open(b"XGWC" + envelope[4:], AAD)
        with pytest.raises(CryptoError, match="magic"):
            envelope_key_version(b"XGWC" + envelope[4:])

    def test_wrong_format_version_rejected(self, cipher: AesGcmEnvelopeCipher) -> None:
        envelope = cipher.seal(b"secret", AAD)
        for version in (0x00, 0x02, 0xFF):
            with pytest.raises(CryptoError, match="format version"):
                cipher.open(envelope[:4] + bytes([version]) + envelope[5:], AAD)

    def test_wrong_key_version_rejected(self, keyring: MasterKeyRing) -> None:
        key = keyring.subkey(SubkeyPurpose.CREDENTIALS)
        envelope = AesGcmEnvelopeCipher(key, key_version=1).seal(b"secret", AAD)
        with pytest.raises(CryptoError, match="different key version"):
            AesGcmEnvelopeCipher(key, key_version=2).open(envelope, AAD)

    def test_nonces_are_unique(self, cipher: AesGcmEnvelopeCipher) -> None:
        envelopes = [cipher.seal(b"same plaintext", AAD) for _ in range(2000)]
        nonces = {envelope[6:18] for envelope in envelopes}
        assert len(nonces) == len(envelopes)
        assert len({envelope[18:] for envelope in envelopes}) == len(envelopes)

    @pytest.mark.parametrize("length", [0, 16, 31, 33])
    def test_rejects_bad_key_length(self, length: int) -> None:
        with pytest.raises(CryptoError, match="32 bytes"):
            AesGcmEnvelopeCipher(bytes(length), key_version=1)

    @pytest.mark.parametrize("version", [0, 256])
    def test_rejects_bad_key_version(self, version: int) -> None:
        with pytest.raises(CryptoError, match="key version"):
            AesGcmEnvelopeCipher(bytes(32), key_version=version)

    def test_repr_hides_key(self, cipher: AesGcmEnvelopeCipher, keyring: MasterKeyRing) -> None:
        key = keyring.subkey(SubkeyPurpose.CREDENTIALS)
        assert key.hex() not in repr(cipher)
        assert str(cipher) == "AesGcmEnvelopeCipher(key_version=1, key=***)"
        assert cipher.key_version == 1
        with pytest.raises(TypeError):
            pickle.dumps(cipher)

    @given(plaintext=st.binary(max_size=4096), aad=st.binary(max_size=128))
    def test_round_trip_property(self, plaintext: bytes, aad: bytes) -> None:
        cipher = AesGcmEnvelopeCipher(bytes(range(32)), key_version=1)
        assert cipher.open(cipher.seal(plaintext, aad), aad) == plaintext


def test_credential_aad_format() -> None:
    assert credential_aad("cred_x", 3) == b"agw-cred|cred_x|3"
