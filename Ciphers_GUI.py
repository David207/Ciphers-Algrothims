import tkinter as tk
from Crypto.Cipher import DES, AES
from Crypto.Util.Padding import pad, unpad
import base64

# Caesar Cipher
def caesar_encrypt(text, shift):
    result = ""
    for char in text:
        if char.isupper():
            result += chr((ord(char) + shift - 65) % 26 + 65)
        elif char.islower():
            result += chr((ord(char) + shift - 97) % 26 + 97)
        else:
            result += char
    return result

def caesar_decrypt(text, shift):
    return caesar_encrypt(text, -shift)

# Monoalphabetic Cipher
def monoalphabetic_encrypt(text, key):
    result = ""
    for char in text:
        if char.isalpha():
            result += key[ord(char.lower()) - 97]
        else:
            result += char
    return result

def monoalphabetic_decrypt(text, key):
    result = ""
    inverse_key = {v: k for k, v in enumerate(key)}
    for char in text:
        if char.isalpha():
            result += chr(inverse_key[char.lower()] + 97)
        else:
            result += char
    return result

# Playfair Cipher
def generate_playfair_key_matrix(key):
    key = key.upper().replace("J", "I")
    matrix = []
    used = set()

    for char in key:
        if char not in used and char.isalpha():
            matrix.append(char)
            used.add(char)

    alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    for char in alphabet:
        if char not in used:
            matrix.append(char)
            used.add(char)

    return [matrix[i*5:(i+1)*5] for i in range(5)]

def find_position(char, matrix):
    for row in range(5):
        for col in range(5):
            if matrix[row][col] == char:
                return row, col
    return None

def playfair_encrypt(text, key):
    matrix = generate_playfair_key_matrix(key)
    text = text.upper().replace("J", "I")
    text = ''.join([c for c in text if c.isalpha()])

    # Insert 'X' between identical letters
    i = 0
    while i < len(text) - 1:
        if text[i] == text[i+1]:
            text = text[:i+1] + 'X' + text[i+1:]
        i += 2

    if len(text) % 2 != 0:
        text += 'X'

    result = []
    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        row1, col1 = find_position(a, matrix)
        row2, col2 = find_position(b, matrix)

        if row1 == row2:
            result.append(matrix[row1][(col1 + 1) % 5])
            result.append(matrix[row2][(col2 + 1) % 5])
        elif col1 == col2:
            result.append(matrix[(row1 + 1) % 5][col1])
            result.append(matrix[(row2 + 1) % 5][col2])
        else:
            result.append(matrix[row1][col2])
            result.append(matrix[row2][col1])

    return "".join(result)

def playfair_decrypt(text, key):
    matrix = generate_playfair_key_matrix(key)
    text = text.upper().replace("J", "I")
    text = ''.join([c for c in text if c.isalpha()])

    result = []
    for i in range(0, len(text), 2):
        a, b = text[i], text[i+1]
        row1, col1 = find_position(a, matrix)
        row2, col2 = find_position(b, matrix)

        if row1 == row2:
            result.append(matrix[row1][(col1 - 1) % 5])
            result.append(matrix[row2][(col2 - 1) % 5])
        elif col1 == col2:
            result.append(matrix[(row1 - 1) % 5][col1])
            result.append(matrix[(row2 - 1) % 5][col2])
        else:
            result.append(matrix[row1][col2])
            result.append(matrix[row2][col1])

    return "".join(result)

# Polyalphabetic Cipher
def polyalphabetic_encrypt(text, key):
    result = ""
    key_length = len(key)
    for i in range(len(text)):
        if text[i].isalpha():
            result += chr(((ord(text[i]) + ord(key[i % key_length].upper()) - 2 * ord('A')) % 26) + ord('A'))
        else:
            result += text[i]
    return result

def polyalphabetic_decrypt(text, key):
    result = ""
    key_length = len(key)
    for i in range(len(text)):
        if text[i].isalpha():
            result += chr(((ord(text[i]) - ord(key[i % key_length].upper()) + 26) % 26) + ord('A'))
        else:
            result += text[i]
    return result

# Vigenère Cipher
def vigenere_encrypt(text, key):
    result = ""
    key_length = len(key)
    for i in range(len(text)):
        if text[i].isalpha():
            result += chr(((ord(text[i].upper()) + ord(key[i % key_length].upper()) - 2 * ord('A')) % 26) + ord('A'))
        else:
            result += text[i]
    return result

def vigenere_decrypt(text, key):
    result = ""
    key_length = len(key)
    for i in range(len(text)):
        if text[i].isalpha():
            result += chr(((ord(text[i].upper()) - ord(key[i % key_length].upper()) + 26) % 26) + ord('A'))
        else:
            result += text[i]
    return result

# Rail Fence Cipher
def rail_fence_encrypt(text, key):
    rail = [['\n' for _ in range(len(text))] for _ in range(key)]
    dir_down = False
    row, col = 0, 0
    for i in range(len(text)):
        if row == 0 or row == key - 1:
            dir_down = not dir_down
        rail[row][col] = text[i]
        col += 1
        row = row + 1 if dir_down else row - 1
    result = []
    for i in range(key):
        for j in range(len(text)):
            if rail[i][j] != '\n':
                result.append(rail[i][j])
    return "".join(result)

def rail_fence_decrypt(cipher, key):
    rail = [['\n' for _ in range(len(cipher))] for _ in range(key)]
    dir_down = None
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        rail[row][col] = '*'
        col += 1
        row = row + 1 if dir_down else row - 1
    index = 0
    for i in range(key):
        for j in range(len(cipher)):
            if rail[i][j] == '*' and index < len(cipher):
                rail[i][j] = cipher[index]
                index += 1
    result = []
    row, col = 0, 0
    for i in range(len(cipher)):
        if row == 0:
            dir_down = True
        if row == key - 1:
            dir_down = False
        if rail[row][col] != '*':
            result.append(rail[row][col])
            col += 1
        row = row + 1 if dir_down else row - 1
    return "".join(result)

# Row Transposition Cipher
def row_transposition_encrypt(text, key):
    key_indices = sorted(range(len(key)), key=lambda k: key[k])
    result = ''
    for i in key_indices:
        for j in range(i, len(text), len(key)):
            result += text[j]
    return result

def row_transposition_decrypt(cipher, key):
    key_indices = sorted(range(len(key)), key=lambda k: key[k])
    num_cols = len(key)
    num_rows = len(cipher) // num_cols
    result = [''] * len(cipher)
    idx = 0
    for i in key_indices:
        for j in range(i, len(cipher), num_cols):
            result[j] = cipher[idx]
            idx += 1
    return ''.join(result)

# DES Cipher
def des_encrypt(text, key):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    padded_text = pad(text.encode('utf-8'), DES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_text).decode('utf-8')

def des_decrypt(cipher_text, key):
    cipher = DES.new(key.encode('utf-8'), DES.MODE_ECB)
    decoded_encrypted_text = base64.b64decode(cipher_text)
    decrypted_text = unpad(cipher.decrypt(decoded_encrypted_text), DES.block_size)
    return decrypted_text.decode('utf-8')

# AES Cipher
def aes_encrypt(text, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    padded_text = pad(text.encode('utf-8'), AES.block_size)
    encrypted_text = cipher.encrypt(padded_text)
    return base64.b64encode(encrypted_text).decode('utf-8')

def aes_decrypt(cipher_text, key):
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    # Ensure the base64 string is correctly padded
    cipher_text += '=' * (-len(cipher_text) % 4)
    decoded_encrypted_text = base64.b64decode(cipher_text)
    decrypted_text = unpad(cipher.decrypt(decoded_encrypted_text), AES.block_size)
    return decrypted_text.decode('utf-8')

# GUI
class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cipher GUI")

        self.cipher_var = tk.StringVar(value="Caesar")
        self.mode_var = tk.StringVar(value="Encrypt")
        
        self.create_widgets()

    def create_widgets(self):
        tk.Label(self.root, text="Select Cipher:").grid(row=0, column=0, sticky="w")
        tk.OptionMenu(self.root, self.cipher_var, "Caesar", "Monoalphabetic", "Playfair",
                      "Polyalphabetic", "Vigenère", "Rail Fence", "Row Transposition", "DES", "AES").grid(row=0, column=1, sticky="w")

        tk.Label(self.root, text="Mode:").grid(row=1, column=0, sticky="w")
        tk.OptionMenu(self.root, self.mode_var, "Encrypt", "Decrypt").grid(row=1, column=1, sticky="w")

        tk.Label(self.root, text="Input Text:").grid(row=2, column=0, sticky="w")
        self.input_text = tk.Entry(self.root, width=50)
        self.input_text.grid(row=10, column=20, columnspan=2, sticky="w")

        tk.Label(self.root, text="Key:").grid(row=3, column=0, sticky="w")
        self.key_text = tk.Entry(self.root, width=50)
        self.key_text.grid(row=3, column=1, columnspan=2, sticky="w")

        self.result_label = tk.Label(self.root, text="Result:")
        self.result_label.grid(row=4, column=0, sticky="w")

        self.result_text = tk.Entry(self.root, width=50)
        self.result_text.grid(row=4, column=1, columnspan=2, sticky="w")

        tk.Button(self.root, text="Submit", command=self.encrypt_decrypt).grid(row=5, column=1, sticky="w")
        tk.Button(self.root, text="Clear", command=self.clear).grid(row=5, column=2, sticky="w")

    def clear(self):
        self.input_text.delete(0, tk.END)
        self.key_text.delete(0, tk.END)
        self.result_text.delete(0, tk.END)

    def encrypt_decrypt(self):
        text = self.input_text.get()
        key = self.key_text.get()
        cipher = self.cipher_var.get()
        mode = self.mode_var.get()

        if cipher == "Caesar":
            shift = key if key.isdigit() else 0
            result = caesar_encrypt(text, shift) if mode == "Encrypt" else caesar_decrypt(text, shift)
        elif cipher == "Monoalphabetic":
            result = monoalphabetic_encrypt(text, key) if mode == "Encrypt" else monoalphabetic_decrypt(text, key)
        elif cipher == "Playfair":
            result = playfair_encrypt(text, key) if mode == "Encrypt" else playfair_decrypt(text, key)
        elif cipher == "Polyalphabetic":
            result = polyalphabetic_encrypt(text, key) if mode == "Encrypt" else polyalphabetic_decrypt(text, key)
        elif cipher == "Vigenère":
            result = vigenere_encrypt(text, key) if mode == "Encrypt" else vigenere_decrypt(text, key)
        elif cipher == "Rail Fence":
            result = rail_fence_encrypt(text, int(key)) if mode == "Encrypt" else rail_fence_decrypt(text, int(key))
        elif cipher == "Row Transposition":
            result = row_transposition_encrypt(text, key) if mode == "Encrypt" else row_transposition_decrypt(text, key)
        elif cipher == "DES":
            if mode == "Encrypt":
                result = des_encrypt(text, key)
            else:
                try:
                    result = des_decrypt(text, key)
                except Exception as e:
                    result = str(e)
        elif cipher == "AES":
            if mode == "Encrypt":
                result = aes_encrypt(text, key)
            else:
                try:
                    result = aes_decrypt(text, key)
                except Exception as e:
                    result = str(e)

        self.result_text.delete(0, tk.END)
        self.result_text.insert(0, result)

if __name__ == "__main__":
    root = tk.Tk()
    app = CipherApp(root)
    root.mainloop()
