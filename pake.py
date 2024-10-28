# -- coding: utf-8 -- 

from PyQt6.QtCore import *  # type: ignore
from PyQt6.QtGui import *  # type: ignore
from PyQt6.QtWidgets import *  # type: ignore
from pydub import AudioSegment
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

class Ui_Dialog(object):
    def setupUi(self, Dialog):
        if not Dialog.objectName():
            Dialog.setObjectName(u"Dialog")
        Dialog.resize(633, 519)

        # QTextEdit
        self.textEdit = QTextEdit(Dialog)
        self.textEdit.setObjectName(u"textEdit")
        self.textEdit.setGeometry(QRect(10, 170, 611, 41))
        font = QFont()
        font.setPointSize(10)
        self.textEdit.setFont(font)

        # Labels
        self.label = QLabel(Dialog)
        self.label.setObjectName(u"label")
        self.label.setGeometry(QRect(10, 120, 591, 51))
        self.label.setFont(font)

        # Buttons
        self.pushButton = QPushButton(Dialog)
        self.pushButton.setObjectName(u"pushButton")
        self.pushButton.setGeometry(QRect(10, 220, 611, 61))
        self.pushButton.clicked.connect(self.select_file)  # Connect button signal

        self.label_2 = QLabel(Dialog)
        self.label_2.setObjectName(u"label_2")
        self.label_2.setGeometry(QRect(10, 290, 591, 51))
        self.label_2.setFont(font)

        self.keyInput = QLineEdit(Dialog)  # Add input field for secret key
        self.keyInput.setObjectName(u"keyInput")
        self.keyInput.setGeometry(QRect(10, 340, 611, 41))
        self.keyInput.setEchoMode(QLineEdit.EchoMode.Password)  # Hide input

        self.pushButton_2 = QPushButton(Dialog)
        self.pushButton_2.setObjectName(u"pushButton_2")
        self.pushButton_2.setGeometry(QRect(10, 390, 301, 61))
        self.pushButton_2.setText("ENCRYPT")
        self.pushButton_2.clicked.connect(self.encrypt_audio)  # Connect button signal

        self.pushButton_3 = QPushButton(Dialog)
        self.pushButton_3.setObjectName(u"pushButton_3")
        self.pushButton_3.setGeometry(QRect(320, 390, 301, 61))
        self.pushButton_3.setText("DECRYPT")
        self.pushButton_3.clicked.connect(self.decrypt_audio)  # Connect button signal

        self.pushButton_4 = QPushButton(Dialog)
        self.pushButton_4.setObjectName(u"pushButton_4")
        self.pushButton_4.setGeometry(QRect(10, 470, 611, 41))
        self.pushButton_4.setText("RESET")
        self.pushButton_4.clicked.connect(self.reset)  # Connect button signal

        self.label_3 = QLabel(Dialog)
        self.label_3.setObjectName(u"label_3")
        self.label_3.setEnabled(True)
        self.label_3.setGeometry(QRect(220, 40, 198, 44))

        font1 = QFont()
        font1.setFamily(u"Segoe UI Variable Small Semibol")
        font1.setPointSize(20)
        font1.setBold(True)
        font1.setWeight(75)
        font1.setStrikeOut(False)
        self.label_3.setFont(font1)
        self.label_3.setLayoutDirection(Qt.LayoutDirection.RightToLeft)

        self.retranslateUi(Dialog)

        QMetaObject.connectSlotsByName(Dialog)

    def select_file(self):
        # Open file selection dialog
        file_name, _ = QFileDialog.getOpenFileName(
            None,
            "Select a File",
            "",
            "Audio Files (*.wav);;All Files (*)"
        )

        if file_name:
            self.textEdit.setPlainText(file_name)  # Display selected file path

    def encrypt_audio(self):
        file_path = self.textEdit.toPlainText()
        secret_key = self.keyInput.text().encode('utf-8')

        if not file_path or not secret_key:
            QMessageBox.warning(None, "Error", "Please select a file and enter a secret key.")
            return

        try:
            audio_bytes, sample_width, frame_rate, channels = self.convert_audio_to_bytes(file_path)
            key = pad(secret_key, Blowfish.block_size)  # Pad the key to be compatible with Blowfish
            iv, encrypted_audio = self.encrypt_audio_blowfish(audio_bytes, key)

            # Save the encrypted audio
            encrypted_file_path = "encrypted_audio_blowfish.wav"
            encrypted_audio_segment = self.convert_bytes_to_audio(encrypted_audio, sample_width, frame_rate, channels)
            self.save_audio_to_wav(encrypted_file_path, encrypted_audio_segment)

            QMessageBox.information(None, "Success", f"Audio encrypted and saved as '{encrypted_file_path}'!")
        except Exception as e:
            QMessageBox.critical(None, "Error", f"Failed to encrypt audio: {str(e)}")

    def decrypt_audio(self):
        file_path = self.textEdit.toPlainText()
        secret_key = self.keyInput.text().encode('utf-8')

        if not file_path or not secret_key:
            QMessageBox.warning(None, "Error", "Please select a file and enter a secret key.")
            return

        try:
            # Load the encrypted audio file
            encrypted_audio_segment = AudioSegment.from_file(file_path)
            encrypted_audio_bytes = encrypted_audio_segment.raw_data

            key = pad(secret_key, Blowfish.block_size)  # Pad the key to be compatible with Blowfish

            # Assuming the IV is stored as the first bytes of the encrypted file, extract it.
            iv = encrypted_audio_bytes[:Blowfish.block_size]  # The first block is the IV
            ciphertext = encrypted_audio_bytes[Blowfish.block_size:]

            decrypted_audio_bytes = self.decrypt_audio_blowfish(iv, ciphertext, key)

            # Save the decrypted audio
            decrypted_file_path = "decrypted_audio_blowfish.wav"
            decrypted_audio_segment = self.convert_bytes_to_audio(decrypted_audio_bytes, encrypted_audio_segment.sample_width, encrypted_audio_segment.frame_rate, encrypted_audio_segment.channels)
            decrypted_audio_segment.export(decrypted_file_path, format="wav")

            QMessageBox.information(None, "Success", f"Audio decrypted and saved as '{decrypted_file_path}'!")
        except Exception as e:
            QMessageBox.critical(None, "Error", f"Failed to decrypt audio: {str(e)}")

    def reset(self):
        self.textEdit.clear()
        self.keyInput.clear()

    def retranslateUi(self, Dialog):
        Dialog.setWindowTitle(QCoreApplication.translate("Dialog", u"Audio Encryptor/Decryptor", None))
        self.label.setText(QCoreApplication.translate("Dialog", u"Select the enter file button to select the audio you want to Encrypt or Decrypt", None))
        self.pushButton.setText(QCoreApplication.translate("Dialog", u"SELECT FILE", None))
        self.label_2.setText(QCoreApplication.translate("Dialog", u"Enter Secret Key (Remember this for Decryption)", None))
        self.label_3.setText(QCoreApplication.translate("Dialog", u"ENCDEC APP", None))

    # Helper functions for audio processing
    def convert_audio_to_bytes(self, file_path):
        audio = AudioSegment.from_file(file_path)
        audio_bytes = audio.raw_data
        return audio_bytes, audio.sample_width, audio.frame_rate, audio.channels

    def convert_bytes_to_audio(self, audio_bytes, sample_width, frame_rate, channels):
        return AudioSegment(data=audio_bytes, sample_width=sample_width, frame_rate=frame_rate, channels=channels)

    def encrypt_audio_blowfish(self, audio_bytes, key):
        cipher = Blowfish.new(key, Blowfish.MODE_CBC)
        iv = cipher.iv
        ciphertext = cipher.encrypt(pad(audio_bytes, Blowfish.block_size))
        return iv, iv + ciphertext  # Prepend IV to ciphertext for decryption

    def decrypt_audio_blowfish(self, iv, ciphertext, key):
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        decrypted_bytes = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)
        return decrypted_bytes

    def save_audio_to_wav(self, file_path, audio_segment):
        audio_segment.export(file_path, format="wav")


if __name__ == "__main__":
    import sys
    app = QApplication(sys.argv)
    Dialog = QDialog()
    ui = Ui_Dialog()
    ui.setupUi(Dialog)
    Dialog.show()  # Show dialog
    sys.exit(app.exec())
