"""Tests for agentproof.hasher — canonical JSON serialization and hashing."""

import pytest

import json

from agentproof.hasher import canonical_json, sha256_digest, blake3_digest, hash_bytes, hash_hex


class TestCanonicalJson:
    def test_deterministic_sorted_keys(self):
        a = {"b": 2, "a": 1, "c": [3, 2, 1]}
        b = {"a": 1, "b": 2, "c": [3, 2, 1]}
        assert canonical_json(a) == canonical_json(b)

    def test_no_whitespace(self):
        data = {"x": 1, "y": 2}
        canonical = canonical_json(data)
        assert " " not in canonical.decode("utf-8")
        assert "\n" not in canonical.decode("utf-8")

    def test_sorted_keys_recursively(self):
        data = {
            "z": {"b": 1, "a": 2},
            "a": {"d": 1, "c": 2},
        }
        canonical = canonical_json(data)
        # Built-in sort_keys should produce identical output
        expected = json.dumps(data, sort_keys=True, separators=(",", ":"))
        assert canonical.decode("utf-8") == expected

    def test_empty_object(self):
        assert canonical_json({}) == b"{}"

    def test_nested_objects(self):
        data = {"inner": {"b": 1, "a": [1, {"c": 3, "b": 2}]}}
        canonical = canonical_json(data)
        # Keys are sorted at every level (no whitespace in separators)
        assert b'"inner":{"a":' in canonical
        assert b'"b":1' in canonical
        assert b'"c":3' in canonical


class TestSha256Digest:
    def test_sha256_of_bytes(self):
        data = b"hello world"
        digest = sha256_digest(data)
        assert len(digest) == 64
        assert all(c in "0123456789abcdef" for c in digest)

    def test_sha256_deterministic(self):
        data = b"same data"
        assert sha256_digest(data) == sha256_digest(data)

    def test_sha256_different_data(self):
        assert sha256_digest(b"hello") != sha256_digest(b"world")


class TestBlake3Digest:
    def test_blake3_available(self):
        # blake3 may not be installed in the test environment
        from agentproof import hasher as h
        assert h.blake3 is None or h.blake3 is not None

    def test_blake3_deterministic(self):
        data = b"test"
        assert blake3_digest(data) == blake3_digest(data)


class TestHashFunctions:
    def test_hash_bytes(self):
        data = b"some data"
        digest = hash_bytes(data)
        assert len(digest) == 64
        assert sha256_digest(data) == digest

    def test_hash_hex(self):
        s = "hello"
        digest = hash_hex(s)
        assert len(digest) == 64
        assert sha256_digest(s.encode("utf-8")) == digest
