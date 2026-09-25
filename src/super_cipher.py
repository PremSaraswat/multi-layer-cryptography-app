import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext


def is_ascii_alpha(char):
    """True only for A-Z / a-z.

    str.isalpha() is True for 'e' and 'a' too, but the cipher maths below
    assume a 26-letter ASCII alphabet. Feeding non-ASCII letters through
    ord(char) - 97 maps them into unrelated code points and destroys them
    irreversibly, so they must be passed through untouched instead.
    """
    return ("A" <= char <= "Z") or ("a" <= char <= "z")


# ----------------------------- Rail Fence Cipher -----------------------------
def rail_fence_encrypt(text, key):
    if key < 2:
        # key <= 0 would index an empty rail list (IndexError); key == 1 is identity.
        return text
    rails = [''] * key
    rail = 0
    direction = 1
    for char in text:
        rails[rail] += char
        rail += direction
        if rail == 0 or rail == key - 1:
            direction *= -1
    return ''.join(rails)

def rail_fence_decrypt(cipher, key):
    if key < 2:
        return cipher
    n = len(cipher)
    pattern = [0] * n
    rail = 0
    direction = 1
    for i in range(n):
        pattern[i] = rail
        rail += direction
        if rail == 0 or rail == key - 1:
            direction *= -1
    rails = [''] * key
    pos = 0
    for r in range(key):
        for i in range(n):
            if pattern[i] == r:
                rails[r] += cipher[pos]
                pos += 1
    result = ''
    indices = [0] * key
    for i in range(n):
        r = pattern[i]
        result += rails[r][indices[r]]
        indices[r] += 1
    return result

# ----------------------------- Vigenere Cipher (Case Sensitive) -----------------------------
def vigenere_encrypt(text, key):
    cipher = ''
    key_index = 0
    for char in text:
        if is_ascii_alpha(char):
            shift = ord(key[key_index % len(key)].upper()) - 65
            if char.isupper():
                cipher += chr((ord(char) - 65 + shift) % 26 + 65)
            else:
                cipher += chr((ord(char) - 97 + shift) % 26 + 97)
            key_index += 1
        else:
            cipher += char
    return cipher

def vigenere_decrypt(cipher, key):
    text = ''
    key_index = 0
    for char in cipher:
        if is_ascii_alpha(char):
            shift = ord(key[key_index % len(key)].upper()) - 65
            if char.isupper():
                text += chr((ord(char) - 65 - shift) % 26 + 65)
            else:
                text += chr((ord(char) - 97 - shift) % 26 + 97)
            key_index += 1
        else:
            text += char
    return text

# ----------------------------- Affine Cipher (Case Sensitive) -----------------------------
def mod_inverse(a, m):
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def affine_encrypt(text, a, b):
    cipher = ''
    for char in text:
        if is_ascii_alpha(char):
            if char.isupper():
                cipher += chr(((a * (ord(char) - 65) + b) % 26) + 65)
            else:
                cipher += chr(((a * (ord(char) - 97) + b) % 26) + 97)
        else:
            cipher += char
    return cipher

def affine_decrypt(cipher, a, b):
    text = ''
    a_inv = mod_inverse(a, 26)
    if a_inv is None:
        return "INVALID MULTIPLICATIVE KEY"
    for char in cipher:
        if is_ascii_alpha(char):
            if char.isupper():
                text += chr(((a_inv * ((ord(char) - 65 - b)) % 26) + 65))
            else:
                text += chr(((a_inv * ((ord(char) - 97 - b)) % 26) + 97))
        else:
            text += char
    return text

# ----------------------------- Core Cipher Process -----------------------------
def process_cipher():
    try:
        rail_key = int(entry_rail.get())
        vig_key = entry_vigenere.get().strip()
        a = int(entry_affine_a.get())
        b = int(entry_affine_b.get())

        if rail_key < 2:
            messagebox.showerror("Error", "Rail Fence key must be 2 or greater.")
            return
        if not vig_key or not all(is_ascii_alpha(c) for c in vig_key):
            # str.isalpha() also accepts non-ASCII letters, whose shift value
            # would fall outside 0-25 and produce an unrecoverable ciphertext.
            messagebox.showerror("Error", "Vigenere key must contain only letters A-Z (ASCII only).")
            return
        if mod_inverse(a, 26) is None:
            messagebox.showerror("Error", f"Invalid multiplicative key 'a' = {a}. It must be coprime with 26.")
            return

        # Tk always appends one trailing newline to a Text widget's contents;
        # remove exactly that, and nothing the user actually typed.
        plaintext = text_input.get("1.0", tk.END).removesuffix("\n")
        if not plaintext:
            messagebox.showerror("Error", "Please enter text or load a file first.")
            return

        # -------------------- Encryption Stages --------------------
        rf_enc = rail_fence_encrypt(plaintext, rail_key)
        vig_enc = vigenere_encrypt(rf_enc, vig_key)
        aff_enc = affine_encrypt(vig_enc, a, b)

        # -------------------- Decryption Stages --------------------
        aff_dec = affine_decrypt(aff_enc, a, b)
        vig_dec = vigenere_decrypt(aff_dec, vig_key)
        rf_dec = rail_fence_decrypt(vig_dec, rail_key)

        # Display results
        output_rail_enc.delete("1.0", tk.END)
        output_rail_enc.insert(tk.END, rf_enc)

        output_vig_enc.delete("1.0", tk.END)
        output_vig_enc.insert(tk.END, vig_enc)

        output_aff_enc.delete("1.0", tk.END)
        output_aff_enc.insert(tk.END, aff_enc)

        output_aff_dec.delete("1.0", tk.END)
        output_aff_dec.insert(tk.END, aff_dec)

        output_vig_dec.delete("1.0", tk.END)
        output_vig_dec.insert(tk.END, vig_dec)

        output_rail_dec.delete("1.0", tk.END)
        output_rail_dec.insert(tk.END, rf_dec)

        if rf_dec == plaintext:
            messagebox.showinfo(
                "Success",
                "Encryption & Decryption complete.\n"
                "Verified: the final plaintext matches the original exactly.",
            )
        else:
            messagebox.showerror(
                "Round-trip FAILED",
                "The decrypted text does NOT match the original input.\n"
                "Do not trust this output; please report the input and keys used.",
            )

    except ValueError:
        messagebox.showerror("Error", "Invalid key format. Please check all keys.")

# ----------------------------- File Handling -----------------------------
def load_file():
    file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
    if not file_path:
        return
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            text_input.delete("1.0", tk.END)
            text_input.insert(tk.END, content)
        messagebox.showinfo("Success", f"Loaded file:\n{file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Could not read file:\n{e}")

def save_decrypted():
    decrypted_text = output_rail_dec.get("1.0", tk.END).removesuffix("\n")
    if not decrypted_text.strip():
        messagebox.showerror("Error", "No decrypted text to save!")
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text Files", "*.txt")])
    if not file_path:
        return
    try:
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(decrypted_text)
        messagebox.showinfo("Success", f"Decrypted text saved to:\n{file_path}")
    except Exception as e:
        messagebox.showerror("Error", f"Could not save file:\n{e}")

# ----------------------------- Decrypt-Only Mode -----------------------------
def decrypt_only():
    """Decrypt ciphertext supplied by the user (not just what we encrypted)."""
    try:
        rail_key = int(entry_rail.get())
        vig_key = entry_vigenere.get().strip()
        a = int(entry_affine_a.get())
        b = int(entry_affine_b.get())

        if rail_key < 2:
            messagebox.showerror("Error", "Rail Fence key must be 2 or greater.")
            return
        if not vig_key or not all(is_ascii_alpha(c) for c in vig_key):
            messagebox.showerror("Error", "Vigenere key must contain only letters A-Z (ASCII only).")
            return
        if mod_inverse(a, 26) is None:
            messagebox.showerror("Error", f"Invalid multiplicative key 'a' = {a}. It must be coprime with 26.")
            return

        ciphertext = text_input.get("1.0", tk.END).removesuffix("\n")
        if not ciphertext:
            messagebox.showerror("Error", "Paste the ciphertext into the input box first.")
            return

        # Inverse of the encryption order: Affine -> Vigenere -> Rail Fence.
        aff_dec = affine_decrypt(ciphertext, a, b)
        vig_dec = vigenere_decrypt(aff_dec, vig_key)
        rf_dec = rail_fence_decrypt(vig_dec, rail_key)

        for box in (output_rail_enc, output_vig_enc, output_aff_enc):
            box.delete("1.0", tk.END)
        output_aff_enc.insert(tk.END, ciphertext)

        for box, val in ((output_aff_dec, aff_dec), (output_vig_dec, vig_dec), (output_rail_dec, rf_dec)):
            box.delete("1.0", tk.END)
            box.insert(tk.END, val)

        messagebox.showinfo("Decrypted", "Decryption complete. See the final plaintext box.")

    except ValueError:
        messagebox.showerror("Error", "Invalid key format. Please check all keys.")



def main():
    global root, entry_rail, entry_vigenere, entry_affine_a, entry_affine_b, text_input, output_rail_enc, output_vig_enc, output_aff_enc, output_aff_dec, output_vig_dec, output_rail_dec
    # ----------------------------- GUI Layout -----------------------------
    root = tk.Tk()
    root.title("Super Cipher: Rail Fence + Vigenere + Affine")
    root.geometry("1050x1000")
    root.configure(bg="#1e1e2f")

    tk.Label(root, text="🔐 Super Cipher Encryption & Decryption", font=("Segoe UI", 18, "bold"), bg="#1e1e2f", fg="cyan").pack(pady=10)

    # Key Frame
    frame_keys = tk.Frame(root, bg="#1e1e2f")
    frame_keys.pack(pady=5)

    tk.Label(frame_keys, text="Rail Fence Key:", bg="#1e1e2f", fg="white").grid(row=0, column=0, padx=5)
    entry_rail = tk.Entry(frame_keys, width=5)
    entry_rail.grid(row=0, column=1, padx=5)
    entry_rail.insert(0, "3")

    tk.Label(frame_keys, text="Vigenere Key:", bg="#1e1e2f", fg="white").grid(row=0, column=2, padx=5)
    entry_vigenere = tk.Entry(frame_keys, width=10)
    entry_vigenere.grid(row=0, column=3, padx=5)
    entry_vigenere.insert(0, "MPM")

    tk.Label(frame_keys, text="Multiplicative Key (a):", bg="#1e1e2f", fg="white").grid(row=0, column=4, padx=5)
    entry_affine_a = tk.Entry(frame_keys, width=5)
    entry_affine_a.grid(row=0, column=5, padx=5)
    entry_affine_a.insert(0, "5")

    tk.Label(frame_keys, text="Additive Key (b):", bg="#1e1e2f", fg="white").grid(row=0, column=6, padx=5)
    entry_affine_b = tk.Entry(frame_keys, width=5)
    entry_affine_b.grid(row=0, column=7, padx=5)
    entry_affine_b.insert(0, "8")

    # Input area
    tk.Label(root, text="📄 Input Text (or load file):", bg="#1e1e2f", fg="white").pack()
    text_input = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=120, height=6, bg="#2e2e3e", fg="white", font=("Consolas", 10))
    text_input.pack(pady=5)

    tk.Button(root, text="Load Text File", command=load_file, bg="#444", fg="white", font=("Segoe UI", 10, "bold")).pack(pady=5)
    tk.Button(root, text="Encrypt & Decrypt", command=process_cipher, bg="cyan", fg="black", font=("Segoe UI", 11, "bold")).pack(pady=10)
    tk.Button(root, text="Decrypt Only (paste ciphertext above)", command=decrypt_only, bg="#f4a261", fg="black", font=("Segoe UI", 10, "bold")).pack(pady=(0, 10))

    # ----------------------------- Encryption Outputs -----------------------------
    labels = [
        ("Rail Fence Encrypted:", "lightblue"),
        ("Vigenere Encrypted:", "lightgreen"),
        ("Affine Encrypted (Final Cipher):", "cyan"),
        ("Affine Decrypted:", "#f4a261"),
        ("Vigenere Decrypted:", "#f1fa8c"),
        ("Rail Fence Decrypted (Final Plaintext):", "yellow")
    ]
    outputs = []

    for label, color in labels:
        tk.Label(root, text=label, bg="#1e1e2f", fg="white").pack()
        box = scrolledtext.ScrolledText(root, wrap=tk.WORD, width=120, height=3, bg="#2e2e3e", fg=color, font=("Consolas", 10))
        box.pack(pady=3)
        outputs.append(box)

    output_rail_enc, output_vig_enc, output_aff_enc, output_aff_dec, output_vig_dec, output_rail_dec = outputs

    # Save Button
    tk.Button(root, text="💾 Save Decrypted File", command=save_decrypted, bg="#4caf50", fg="white", font=("Segoe UI", 10, "bold")).pack(pady=15)

    root.mainloop()
    root.mainloop()


if __name__ == "__main__":
    main()
