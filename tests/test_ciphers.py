"""Tests for the Super Cipher layers.

Run from the project root:
    python -m pytest tests/ -v
"""
import os
import random
import string
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from super_cipher import (  # noqa: E402
    affine_decrypt,
    affine_encrypt,
    is_ascii_alpha,
    mod_inverse,
    rail_fence_decrypt,
    rail_fence_encrypt,
    vigenere_decrypt,
    vigenere_encrypt,
)


# --------------------------- Known-answer tests ---------------------------
def test_affine_known_vector():
    """Classic textbook vector: a=5, b=8."""
    assert affine_encrypt("AFFINECIPHER", 5, 8) == "IHHWVCSWFRCP"
    assert affine_decrypt("IHHWVCSWFRCP", 5, 8) == "AFFINECIPHER"


def test_vigenere_known_vector():
    """Classic textbook vector: key LEMON."""
    assert vigenere_encrypt("ATTACKATDAWN", "LEMON") == "LXFOPVEFRNHR"
    assert vigenere_decrypt("LXFOPVEFRNHR", "LEMON") == "ATTACKATDAWN"


def test_rail_fence_known_vector():
    """Classic textbook vector: 3 rails."""
    assert rail_fence_encrypt("WEAREDISCOVEREDFLEEATONCE", 3) == "WECRLTEERDSOEEFEAOCAIVDEN"
    assert rail_fence_decrypt("WECRLTEERDSOEEFEAOCAIVDEN", 3) == "WEAREDISCOVEREDFLEEATONCE"


def test_mod_inverse():
    assert mod_inverse(5, 26) == 21
    assert (5 * 21) % 26 == 1
    # 13 shares a factor with 26, so no inverse exists.
    assert mod_inverse(13, 26) is None


# --------------------------- Regression: ASCII-only ---------------------------
def test_is_ascii_alpha_rejects_non_ascii_letters():
    """str.isalpha() would return True for all of these; the cipher must not."""
    for char in "éü日مα":
        assert char.isalpha(), "precondition: Python considers it a letter"
        assert not is_ascii_alpha(char)


@pytest.mark.parametrize(
    "text",
    ["café", "naïve résumé", "日本語", "مرحبا hello", "emoji \U0001f512 test"],
)
def test_non_ascii_survives_round_trip(text):
    """Regression for the bug where 'café' decrypted to 'cafg'."""
    assert full_round_trip(text) == text


def test_non_ascii_passes_through_unchanged():
    """Non-ASCII characters must be left byte-identical by every layer."""
    assert affine_encrypt("日本語", 5, 8) == "日本語"
    assert vigenere_encrypt("日本語", "KEY") == "日本語"


# --------------------------- Regression: degenerate keys ---------------------------
@pytest.mark.parametrize("key", [-5, -1, 0, 1])
def test_rail_fence_degenerate_keys_are_identity_not_crash(key):
    """Regression: key <= 0 used to raise IndexError."""
    assert rail_fence_encrypt("HELLO", key) == "HELLO"
    assert rail_fence_decrypt("HELLO", key) == "HELLO"


def test_affine_invalid_multiplier_is_reported():
    assert affine_decrypt("ANYTHING", 13, 4) == "INVALID MULTIPLICATIVE KEY"


# --------------------------- Round-trip properties ---------------------------
def full_round_trip(text, rail_key=3, vig_key="MPM", a=5, b=8):
    """Encrypt through all three layers, then decrypt in the inverse order."""
    encrypted = affine_encrypt(vigenere_encrypt(rail_fence_encrypt(text, rail_key), vig_key), a, b)
    return rail_fence_decrypt(vigenere_decrypt(affine_decrypt(encrypted, a, b), vig_key), rail_key)


@pytest.mark.parametrize(
    "text",
    [
        "HELLOWORLD",
        "Hello, World!",
        "Attack at dawn 123!",
        "MixedCASE with  spaces",
        "trailing whitespace   ",
        "   leading whitespace",
        "line1\nline2\ttabbed",
        "!@#$%^&*()",
        "a",
        "",
    ],
)
def test_full_pipeline_round_trip(text):
    assert full_round_trip(text) == text


@pytest.mark.parametrize("rail_key", [2, 3, 4, 5, 7, 11])
def test_round_trip_across_rail_keys(rail_key):
    text = "The quick brown fox jumps over the lazy dog, 42 times!"
    assert full_round_trip(text, rail_key=rail_key) == text


@pytest.mark.parametrize("a", [1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25])
def test_round_trip_across_valid_affine_multipliers(a):
    text = "The quick brown fox jumps over the lazy dog"
    assert full_round_trip(text, a=a, b=8) == text


def test_round_trip_randomised():
    """Fuzz the pipeline over random ASCII input."""
    pool = string.ascii_letters + string.digits + " .,!?\n\t"
    rng = random.Random(1234)  # seeded: failures are reproducible
    for _ in range(300):
        text = "".join(rng.choice(pool) for _ in range(rng.randint(0, 80)))
        rail_key = rng.choice([2, 3, 4, 5, 9])
        assert full_round_trip(text, rail_key=rail_key) == text


def test_case_is_preserved():
    assert full_round_trip("AbCdEfG") == "AbCdEfG"


# --------------------------- Documented design weaknesses ---------------------------
def test_affine_layer_collapses_into_vigenere():
    """The 'third layer' is not independent: affine(vigenere(x)) == vigenere'(affine(x)).

    This is asserted deliberately, to pin the documented weakness in place. If a
    future change makes this fail, the layering has genuinely changed and the
    security notes in the README must be revisited.
    """
    plaintext = "ATTACKATDAWNATTACKATDAWN"
    a, b, key = 5, 8, "MPM"

    layered = affine_encrypt(vigenere_encrypt(plaintext, key), a, b)
    derived_key = "".join(chr((a * (ord(c) - 65) + b) % 26 + 65) for c in key)
    collapsed = vigenere_encrypt(affine_encrypt(plaintext, a, 0), derived_key)

    assert layered == collapsed


def test_cipher_is_deterministic_no_iv():
    """No IV/nonce: identical plaintext always yields identical ciphertext."""
    first = affine_encrypt(vigenere_encrypt(rail_fence_encrypt("SECRET", 3), "MPM"), 5, 8)
    second = affine_encrypt(vigenere_encrypt(rail_fence_encrypt("SECRET", 3), "MPM"), 5, 8)
    assert first == second
