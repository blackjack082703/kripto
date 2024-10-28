from pydub import AudioSegment
from Crypto.Cipher import Blowfish
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Fungsi untuk memuat file audio dan mengonversi ke byte
def convert_audio_to_bytes(file_path):
    audio = AudioSegment.from_file(file_path)
    audio_bytes = audio.raw_data
    return audio_bytes, audio.sample_width, audio.frame_rate, audio.channels

# Fungsi untuk mengubah byte array kembali menjadi audio
def convert_bytes_to_audio(audio_bytes, sample_width, frame_rate, channels):
    return AudioSegment(data=audio_bytes, sample_width=sample_width, frame_rate=frame_rate, channels=channels)

# Fungsi untuk mengenkripsi audio menggunakan Blowfish
def encrypt_audio_blowfish(audio_bytes, key):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC)
    iv = cipher.iv
    ciphertext = cipher.encrypt(pad(audio_bytes, Blowfish.block_size))
    return iv, ciphertext

# Fungsi untuk mendekripsi audio yang sudah terenkripsi dengan Blowfish
def decrypt_audio_blowfish(iv, ciphertext, key):
    cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    decrypted_bytes = unpad(cipher.decrypt(ciphertext), Blowfish.block_size)
    return decrypted_bytes

# Fungsi untuk menyimpan byte audio ke file WAV
def save_audio_to_wav(file_path, audio_segment):
    audio_segment.export(file_path, format="wav")

# Contoh penggunaan
if __name__ == "__main__":
    # Path ke file audio
    file_path = "whatthehell.wav"  # Path ke file audio yang ingin dienkripsi
    encrypted_file_path = "encrypted_audio_blowfish.wav"  # Path untuk menyimpan audio terenkripsi

    # 1. Mengonversi file audio menjadi byte array
    audio_bytes, sample_width, frame_rate, channels = convert_audio_to_bytes(file_path)

    # 2. Membuat kunci enkripsi (panjang 32-448 bit)
    key = get_random_bytes(16)  # 16 byte = 128 bit

    # 3. Enkripsi audio
    iv, encrypted_audio = encrypt_audio_blowfish(audio_bytes, key)
    print("Audio terenkripsi dengan Blowfish!")

    # 4. Simpan audio terenkripsi ke file WAV
    # Mengonversi hasil enkripsi menjadi AudioSegment untuk menyimpannya
    encrypted_audio_segment = convert_bytes_to_audio(encrypted_audio, sample_width, frame_rate, channels)
    save_audio_to_wav(encrypted_file_path, encrypted_audio_segment)
    print(f"Audio terenkripsi disimpan sebagai '{encrypted_file_path}'")

    # 5. Dekripsi audio
    decrypted_audio_bytes = decrypt_audio_blowfish(iv, encrypted_audio, key)
    print("Audio berhasil didekripsi dengan Blowfish!")

    # 6. Mengonversi byte array hasil dekripsi kembali menjadi audio
    decrypted_audio = convert_bytes_to_audio(decrypted_audio_bytes, sample_width, frame_rate, channels)

    # 7. Simpan hasil dekripsi sebagai file audio baru
    decrypted_audio.export("decrypted_audio_blowfish.wav", format="wav")
    print("File audio hasil dekripsi disimpan sebagai 'decrypted_audio_blowfish.wav'")