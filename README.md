# Multi-Layer Cryptography Application

A Tkinter desktop app that chains three **classical** ciphers — Rail Fence, Vigenère, and Affine — and shows the output of every stage of both encryption and decryption.

## What it does

Encryption applies three layers in order:

```
plaintext ──▶ Rail Fence ──▶ Vigenère ──▶ Affine ──▶ ciphertext
```

Decryption applies the exact inverse:

```
ciphertext ──▶ Affine⁻¹ ──▶ Vigenère⁻¹ ──▶ Rail Fence⁻¹ ──▶ plaintext
```

The GUI displays all six intermediate values, so you can watch the text transform at each stage.

**Features**

- Four configurable keys: rail count, Vigenère keyword, and the Affine multiplier `a` and additive `b`
- **Encrypt & Decrypt** — runs the full round trip and *verifies* that the recovered plaintext matches the original
- **Decrypt Only** — decrypts ciphertext you paste in, using the supplied keys
- Load plaintext from a `.txt` file and save decrypted output back to disk
- Case is preserved; digits, punctuation, whitespace, and all non-ASCII characters pass through untouched

## Stack

- Python 3.9+ (uses `str.removesuffix`)
- Tkinter (standard library)
- pytest for the test suite
- No third-party runtime dependencies

## Install

```bash
git clone <your-repo-url>
cd multi-layer-cryptography-app
python -m venv .venv
```

Activate the environment:

```bash
# Windows
.venv\Scripts\activate
# macOS / Linux
source .venv/bin/activate
```

There are no runtime dependencies to install. On Debian/Ubuntu you may need Tkinter itself:

```bash
sudo apt install python3-tk
```

## Run

```bash
python src/super_cipher.py
```

## Test

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -v
```

The suite covers published known-answer vectors for all three ciphers, round-trip properties across key ranges, and regression tests for each fixed bug.

## Key constraints

| Key | Valid values | Notes |
|---|---|---|
| Rail Fence | integer ≥ 2 | 1 or less is the identity transform and is rejected by the UI |
| Vigenère | ASCII letters A–Z / a–z, non-empty | Non-ASCII letters are rejected; their shift would fall outside 0–25 |
| Affine `a` | must be coprime with 26 | 1, 3, 5, 7, 9, 11, 15, 17, 19, 21, 23, 25 |
| Affine `b` | any integer | Applied mod 26 |

The key fields are pre-filled with demo values (`3` / `MPM` / `5` / `8`). Change them before encrypting anything you care about — though see the warning above about what "care about" can reasonably mean here.

## Security notes

These are measured properties of the design, not implementation bugs. The cipher implementations themselves are correct and match published test vectors.

**1. The Affine layer adds essentially no security.**
Affine encryption is a linear map, so applying it after Vigenère collapses into a single Vigenère pass with a transformed key:

```
affine(vigenere(x, K), a, b)  ==  vigenere(affine(x, a, 0), K')   where K' = a·K + b
```

This identity is asserted in `tests/test_ciphers.py::test_affine_layer_collapses_into_vigenere`. The "three-layer" pipeline provides roughly two layers of actual diffusion.

**2. The total keyspace is about 2²⁶.**
For rail keys 2–20, the 12 valid Affine multipliers, 26 additive values, and a 3-letter Vigenère key: 19 × 12 × 26 × 26³ ≈ 1.04 × 10⁸ combinations. That is exhaustible in seconds on any modern machine.

**3. The layers are separable, so attack cost is additive, not multiplicative.**
Rail Fence is a pure transposition and preserves letter frequencies, so it can be stripped independently. The remaining Vigenère falls to standard Kasiski or index-of-coincidence analysis. An attacker never has to search the combined keyspace.

**4. There is no IV or nonce, so encryption is deterministic.**
The same plaintext under the same keys always produces byte-identical ciphertext, which leaks repeated messages and enables dictionary attacks.

**5. There is no integrity protection.**
Ciphertext is malleable and carries no MAC, so tampering cannot be detected.

**6. Keys are entered and held in plaintext** in the GUI, with no key derivation function.

## Project layout

```
multi-layer-cryptography-app/
├── src/super_cipher.py      # ciphers + Tkinter GUI
├── tests/test_ciphers.py    # known vectors, round-trips, regressions
├── requirements.txt
├── requirements-dev.txt
├── .gitignore
└── README.md
```

`src/super_cipher.py` is importable without side effects — the GUI is built inside `main()` behind an `if __name__ == "__main__"` guard, so the cipher functions can be reused and tested on their own.
