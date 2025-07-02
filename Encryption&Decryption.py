from tkinter import *
from tkinter import ttk
from tkinter import messagebox
from PIL import Image, ImageTk
import base64
from Crypto.Cipher import AES
import os

# Create root object
root = Tk()

# Define size of window
root.geometry("1200x600")
root.title("Message Encryption and Decryption")

# Style configuration
style = ttk.Style()

# Define colors
background_color = "#f0f8ff"  # Alice blue
frame_color = "#e6e6fa"       # Lavender
label_color = "#4b0082"        # Indigo
button_color = "#4682b4"       # Steel blue
button_hover_color = "#4169e1" # Royal blue
entry_color = "#ffffff"        # White
button_text_color = "#000000"  # Black

# Apply colors to styles
style.configure('TFrame', background=frame_color)
style.configure('TLabel', background=frame_color, font=('Arial', 14, 'bold'), foreground=label_color)
style.configure('TButton', font=('Arial', 12, 'bold'), padding=10, background=button_color, foreground=button_text_color)
style.map('TButton', background=[('active', button_hover_color)])

# Configure Entry widget style
style.configure('TEntry', padding=5, relief='flat', background=entry_color)

# Frames for layout
Tops = ttk.Frame(root, padding="10 10 10 10")
Tops.pack(side=TOP, fill=X)

f1 = ttk.Frame(root, padding="20 20 20 20")
f1.pack(padx=20, pady=20, fill=BOTH, expand=True)

# Title Label
lblInfo = ttk.Label(Tops, text="Encryption & Decryption", font=('Arial', 36, 'bold'))
lblInfo.pack()

# Initialize variables
Msg = StringVar()
key = StringVar()
mode = StringVar()
Result = StringVar()
algorithm = StringVar()

# Message History
message_history = []

# Message label and entry
lblMsg = ttk.Label(f1, text="MESSAGE")
lblMsg.grid(row=0, column=0, padx=10, pady=10, sticky='w')
txtMsg = ttk.Entry(f1, textvariable=Msg, style='TEntry')
txtMsg.grid(row=0, column=1, padx=10, pady=10, sticky='ew')

# Key label and entry
lblkey = ttk.Label(f1, text="KEY (String)")
lblkey.grid(row=1, column=0, padx=10, pady=10, sticky='w')
txtkey = ttk.Entry(f1, textvariable=key, style='TEntry')
txtkey.grid(row=1, column=1, padx=10, pady=10, sticky='ew')

# Mode label and entry
lblmode = ttk.Label(f1, text="MODE (e for encrypt, d for decrypt)")
lblmode.grid(row=2, column=0, padx=10, pady=10, sticky='w')
txtmode = ttk.Entry(f1, textvariable=mode, style='TEntry')
txtmode.grid(row=2, column=1, padx=10, pady=10, sticky='ew')

# Algorithm dropdown
lblAlgorithm = ttk.Label(f1, text="Select Algorithm")
lblAlgorithm.grid(row=3, column=0, padx=10, pady=10, sticky='w')

algorithms = ["Base64", "AES", "XOR"]
algorithm_dropdown = ttk.Combobox(f1, textvariable=algorithm, values=algorithms, state='readonly')
algorithm_dropdown.grid(row=3, column=1, padx=10, pady=10, sticky='ew')
algorithm_dropdown.current(0)  # Set default to Base64

# Result label and entry
lblResult = ttk.Label(f1, text="RESULT")
lblResult.grid(row=4, column=0, padx=10, pady=10, sticky='w')
txtResult = ttk.Entry(f1, textvariable=Result, style='TEntry')
txtResult.grid(row=4, column=1, padx=10, pady=10, sticky='ew')

# Functions for encoding and decoding
def encode_base64(key, msg):
    enc = [chr((ord(c) + ord(key[i % len(key)])) % 256) for i, c in enumerate(msg)]
    return base64.urlsafe_b64encode("".join(enc).encode()).decode()

def decode_base64(key, enc):
    enc = base64.urlsafe_b64decode(enc).decode()
    dec = [chr((256 + ord(c) - ord(key[i % len(key)])) % 256) for i, c in enumerate(enc)]
    return "".join(dec)

def encode_aes(key, msg):
    cipher = AES.new(key.ljust(16).encode(), AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode())
    return base64.b64encode(cipher.nonce + ciphertext).decode()

def decode_aes(key, enc):
    enc = base64.b64decode(enc)
    nonce = enc[:16]
    ciphertext = enc[16:]
    cipher = AES.new(key.ljust(16).encode(), AES.MODE_EAX, nonce=nonce)
    return cipher.decrypt(ciphertext).decode()

def encode_xor(key, msg):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(msg))

def decode_xor(key, msg):
    return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(msg))

def Results():
    msg = Msg.get()
    k = key.get()
    m = mode.get()
    alg = algorithm.get()

    if m == 'e':
        if alg == "Base64":
            result = encode_base64(k, msg)
        elif alg == "AES":
            result = encode_aes(k, msg)
        elif alg == "XOR":
            result = encode_xor(k, msg)
    elif m == 'd':
        if alg == "Base64":
            result = decode_base64(k, msg)
        elif alg == "AES":
            result = decode_aes(k, msg)
        elif alg == "XOR":
            result = decode_xor(k, msg)
    else:
        result = "Invalid mode. Use 'e' or 'd'."
        Result.set(result)
        return

    # Store in history
    message_history.append((msg, k, m, alg, result))
    Result.set(result)
    show_encryption_visual(msg, result)

def Reset():
    Msg.set("")
    key.set("")
    mode.set("")
    Result.set("")
    algorithm.set(algorithms[0])

# Show message history
def show_history():
    history_window = Toplevel(root)
    history_window.title("Message History")
    history_window.geometry("800x400")
    text_area = Text(history_window, wrap='word')
    text_area.pack(expand=True, fill='both')
    text_area.insert(END, "Message | Key | Mode | Algorithm | Result\n")
    text_area.insert(END, "-" * 100 + "\n")
    
    for entry in message_history:
        msg, k, m, alg, res = entry
        text_area.insert(END, f"{msg} | {k} | {m} | {alg} | {res}\n")

# Visual representation of encryption
def show_encryption_visual(msg, result):
    visual_window = Toplevel(root)
    visual_window.title("Encryption Visual Representation")
    visual_window.geometry("400x200")
    visual_label = Label(visual_window, text=f"'{msg}' => '{result}'", font=('Arial', 14))
    visual_label.pack(pady=20)

# Buttons
button_width = 15  # Width of buttons
small_button_width = 10  # Width of smaller buttons

btnTotal = ttk.Button(f1, text="Show Result", command=Results, width=button_width)
btnTotal.grid(row=5, column=0, padx=10, pady=10, columnspan=1, sticky='ew')

btnReset = ttk.Button(f1, text="Reset", command=Reset, width=button_width)
btnReset.grid(row=5, column=1, padx=10, pady=10, columnspan=1, sticky='ew')

btnHistory = ttk.Button(f1, text="Show History", command=show_history, width=button_width)
btnHistory.grid(row=6, column=1, padx=10, pady=10, columnspan=1, sticky='ew')

# Adjust column weight
f1.columnconfigure(1, weight=1)

# Keep window alive
root.mainloop()
