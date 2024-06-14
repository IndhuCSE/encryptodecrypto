from tkinter import Tk, Label, Button, filedialog, Entry, messagebox
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
from PIL import Image, ImageTk
import os

class ImageEncryptionApp:
    def __init__(self, master):
        self.master = master
        master.title("Image Encryption Tool")

        self.label = Label(master, text="Select an image to encrypt:")
        self.label.pack()

        self.select_button = Button(master, text="Select Image", command=self.select_image)
        self.select_button.pack()

        self.password_label = Label(master, text="Enter password:")
        self.password_label.pack()

        self.password_entry = Entry(master, show="*")
        self.password_entry.pack()

        self.encrypt_button = Button(master, text="Encrypt Image", command=self.encrypt_image)
        self.encrypt_button.pack()

        self.decrypt_button = Button(master, text="Decrypt Image", command=self.decrypt_image)
        self.decrypt_button.pack()

        self.output_label = Label(master, text="")
        self.output_label.pack()

        self.selected_image_path = None

    def select_image(self):
        self.selected_image_path = filedialog.askopenfilename(title="Select Image File")
        if self.selected_image_path:
            self.output_label.config(text=f"Selected image: {self.selected_image_path}")
            self.show_image_preview()

    def show_image_preview(self):
        if self.selected_image_path:
            image = Image.open(self.selected_image_path)
            image.thumbnail((200, 200))
            photo = ImageTk.PhotoImage(image)
            self.preview_label = Label(self.master, image=photo)
            self.preview_label.image = photo
            self.preview_label.pack()

    def encrypt_image(self):
        if not self.selected_image_path:
            messagebox.showerror("Error", "Please select an image to encrypt.")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        output_image_path = os.path.splitext(self.selected_image_path)[0] + "_encrypted.jpg"  # Change the extension here
        try:
            encrypt_image(self.selected_image_path, output_image_path, password)
            messagebox.showinfo("Success", f"Image encrypted successfully! Encrypted image saved as: {output_image_path}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

    def decrypt_image(self):
        if not self.selected_image_path:
            messagebox.showerror("Error", "Please select an image to decrypt.")
            return

        password = self.password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password.")
            return

        output_image_path = os.path.splitext(self.selected_image_path)[0] + "_decrypted.jpg"
        try:
            decrypt_image(self.selected_image_path, output_image_path, password)
            messagebox.showinfo("Success", f"Image decrypted successfully! Decrypted image saved as: {output_image_path}")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {str(e)}")

def encrypt_image(input_image_path, output_image_path, password):
    # Generate a key from the password using PBKDF2
    salt = get_random_bytes(16)
    key = PBKDF2(password.encode(), salt, dkLen=32, count=1000000, hmac_hash_module=SHA256)

    # Initialize AES cipher in CBC mode with a random IV
    iv = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Read and encrypt the image
    with open(input_image_path, 'rb') as f:
        image_data = f.read()
    
    image_data = pad(image_data, AES.block_size)
    encrypted_image_data = cipher.encrypt(image_data)

    # Add a custom header and footer to indicate encryption
    header = b"ENCRYPTED_IMAGE_HEADER"
    footer = b"ENCRYPTED_IMAGE_FOOTER"
    encrypted_image_data = header + encrypted_image_data + footer

    # Write encrypted image data to a new file
    with open(output_image_path, 'wb') as f:
        f.write(salt)
        f.write(iv)
        f.write(encrypted_image_data)

def decrypt_image(input_image_path, output_image_path, password):
    # Read salt, IV, and encrypted image data from the file
    with open(input_image_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        encrypted_image_data = f.read()

    # Generate key from password and salt using PBKDF2
    key = PBKDF2(password.encode(), salt, dkLen=32, count=1000000, hmac_hash_module=SHA256)

    # Remove the custom header and footer
    header = b"ENCRYPTED_IMAGE_HEADER"
    footer = b"ENCRYPTED_IMAGE_FOOTER"
    encrypted_image_data = encrypted_image_data[len(header):-len(footer)]

    # Initialize AES cipher in CBC mode with the provided IV
    cipher = AES.new(key, AES.MODE_CBC, iv)

    # Decrypt the image data
    decrypted_image_data = cipher.decrypt(encrypted_image_data)

    # Remove padding
    decrypted_image_data = unpad(decrypted_image_data, AES.block_size)

    # Write decrypted image data to a new file
    with open(output_image_path, 'wb') as f:
        f.write(decrypted_image_data)

root = Tk()
my_gui = ImageEncryptionApp(root)
root.mainloop()
