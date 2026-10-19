# pyright: reportMissingTypeStubs=false, reportUnknownArgumentType=false, reportUnknownMemberType=false, reportUnknownVariableType=false

from __future__ import annotations

import io
from typing import BinaryIO

import tink
from tink import aead, cleartext_keyset_handle, streaming_aead

aead.register()
streaming_aead.register()


class AeadPrimitive:
    def __init__(self, primitive: aead.Aead) -> None:
        self._primitive = primitive

    def encrypt(self, plaintext: bytes, associated_data: bytes) -> bytes:
        return self._primitive.encrypt(plaintext, associated_data)

    def decrypt(self, ciphertext: bytes, associated_data: bytes) -> bytes:
        return self._primitive.decrypt(ciphertext, associated_data)

    def unwrap(self) -> aead.Aead:
        return self._primitive


class StreamingAeadPrimitive:
    def __init__(self, primitive: streaming_aead.StreamingAead) -> None:
        self._primitive = primitive

    def new_encrypting_stream(
        self, ciphertext_destination: BinaryIO, associated_data: bytes
    ) -> BinaryIO:
        return self._primitive.new_encrypting_stream(ciphertext_destination, associated_data)

    def new_decrypting_stream(
        self, ciphertext_source: BinaryIO, associated_data: bytes
    ) -> BinaryIO:
        return self._primitive.new_decrypting_stream(ciphertext_source, associated_data)


class Keyset:
    def __init__(self, handle: tink.KeysetHandle) -> None:
        self._handle = handle

    @classmethod
    def generate_aead(cls) -> Keyset:
        return cls(tink.new_keyset_handle(aead.aead_key_templates.AES256_GCM))

    @classmethod
    def generate_streaming_aead(cls) -> Keyset:
        return cls(
            tink.new_keyset_handle(streaming_aead.streaming_aead_key_templates.AES256_GCM_HKDF_1MB)
        )

    @classmethod
    def read_cleartext(cls, serialized: bytes) -> Keyset:
        return cls(cleartext_keyset_handle.read(tink.BinaryKeysetReader(serialized)))

    @classmethod
    def read_encrypted(
        cls, serialized: bytes, wrapping_aead: AeadPrimitive, associated_data: bytes
    ) -> Keyset:
        return cls(
            tink.KeysetHandle.read_with_associated_data(
                tink.BinaryKeysetReader(serialized),
                wrapping_aead.unwrap(),
                associated_data,
            )
        )

    def serialize_cleartext(self) -> bytes:
        output = io.BytesIO()
        cleartext_keyset_handle.write(tink.BinaryKeysetWriter(output), self._handle)
        return output.getvalue()

    def write_encrypted(self, wrapping_aead: AeadPrimitive, associated_data: bytes) -> bytes:
        output = io.BytesIO()
        self._handle.write_with_associated_data(
            tink.BinaryKeysetWriter(output), wrapping_aead.unwrap(), associated_data
        )
        return output.getvalue()

    def aead(self) -> AeadPrimitive:
        return AeadPrimitive(self._handle.primitive(aead.Aead))

    def streaming_aead(self) -> StreamingAeadPrimitive:
        return StreamingAeadPrimitive(self._handle.primitive(streaming_aead.StreamingAead))
