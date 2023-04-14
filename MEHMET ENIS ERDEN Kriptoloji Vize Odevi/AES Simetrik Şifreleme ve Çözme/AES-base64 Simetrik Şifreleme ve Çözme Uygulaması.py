
print("\n\n"
      
"M       M   EEEEEE   EEEEEE                                                                                \n"
"M M   M M   E        E                                                                                     \n"
"M  M M  M   EEEE     EEEE                                                                                  \n"
"M   M   M   E        E                                                                                     \n"
"M       M o EEEEEE o EEEEEE o                                                                              \n\n\n"

"HH      HH    HHHHHHHHHHHH   HH        HH   HHHH      HH   HHHHHHHHHHH                                     \n"
"HH      HH    HH        HH   HH        HH   HH HH     HH   HH        HH                                    \n"
"HH      HH    HH        HH   HH        HH   HH  HH    HH   HH         HH                                   \n"
"HHHHHHHHHH    HH        HH   HH        HH   HH   HH   HH   HH          HH                                  \n"    
"HHHHHHHHHH    HH        HH   HH        HH   HH    HH  HH   HH          HH                                  \n"
"HH      HH    HH        HH   HH        HH   HH     HH HH   HH         HH                                   \n"
"HH      HH    HH        HH   HH        HH   HH      HHHH   HH        HH                                    \n"
"HH      HH    HHHHHHHHHHHH   HHHHHHHHHHHH   HH       HHH   HHHHHHHHHH/                                     \n\n")

from Crypto.Cipher import AES
import base64
import secrets

def generate_key():
    # 8 byte uzunluğunda rastgele bir anahtar oluşturur
    return secrets.token_hex(8)

def pad(data):
    # Veriyi blok boyutuna uygun hale getirir
    block_size = AES.block_size
    padding = block_size - len(data) % block_size
    padding_text = chr(padding) * padding
    return data + padding_text.encode()

def unpad(padded_data):
    # Dolgu baytlarını veriden çıkarır
    padding = ord(padded_data[-1:])
    return padded_data[:-padding]

def encrypt(message, key, rounds):
    # Veriyi şifreler
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    padded_message = pad(message)
    for i in range(rounds):
        padded_message = cipher.encrypt(padded_message)
    return base64.b64encode(padded_message).decode()

def decrypt(ciphertext, key, rounds):
    # Şifreli veriyi çözer
    cipher = AES.new(key.encode(), AES.MODE_ECB)
    message = base64.b64decode(ciphertext.encode())
    for i in range(rounds):
        message = cipher.decrypt(message)
    return unpad(message).decode()

def encrypt_message(message, key):
    encrypted = ''
    for char in message:
        encrypted += chr(ord(char) + key)
    return encrypted

def repeat_encrypt(message, key, repeat):
    for i in range(repeat):
        message = encrypt_message(message, key)
    return message

# Şifreleme işlemi için
print("Merhaba 𝐻𝒪𝒰𝒩𝒟'a Hoş Geldin.\n"
"𝐻𝒪𝒰𝒩𝒟, AES Algoritması ile Simetrik Şifreleme Yapan Bir Programdır.\n"
"Böylelikle Şifrelerin Artık Daha Güvenli Olacak.\n")

while True:
    print("Lütfen yapmak istediğiniz işlemi seçin.\n")
    print("1.Metin Şifreleme: \n")
    print("2.Şifreli Metni Çözme: \n")
    print("3.Programdan Çıkış:\n")
    choice = input("Seçimizin(1/2/3):\n   ")
    if choice == "1":
        plaintext = input("Lütfen şifrelenecek metni girin:\n ")
        while True:
            key = input("Otomatik anahtar oluşturulsun mu? (E/H):\n ")
            if key.upper() == "E":
                key = generate_key()
                print("Güvenliğiniz için otomatik anahtar oluşturuldu: \n", key)
            elif key.upper() == "H":
                key = input("Lütfen 16 karakter uzunluğunda bir anahtar girin.Anahtarınızda ingilizce karakterler, semboller ve rakamlar kullanabilirsiniz:\n ")
            
            else:
                print("Lütfen tekrar tuşlama yapınız.")
                continue
            while len(key) != 16:
                key = input("Lütfen 16 karakter uzunluğunda bir anahtar girin:\n ")
            repeat = int(input("Metnin kaç defa şifrelenmesini istiyorsunuz?:\n "))
        
            ciphertext = encrypt(plaintext.encode(), key, repeat)
            print("Şifrelenmiş metin:\n ", ciphertext)
            break
    elif choice == "2":
        # Şifre çözme işlemi için
        ciphertext = input("Lütfen çözümlenecek metni girin:\n ")
        key = input("Lütfen 16 karakter uzunluğunda bir anahtar girin:\n ")
        while len(key) != 16:
            key = input("Lütfen 16 karakter uzunluğunda bir anahtar girin:\n ")
        repeat = int(input("Metnin kaç defa çözümlenmesini istiyorsunuz?:\n "))

        plaintext = decrypt(ciphertext, key, repeat)
        print("Çözülmüş metin: ", plaintext)
       

    elif choice == "3":
        print("Program Sonlandırılıyor...")
        break

    else:
        print("Yanlış tuşlama yaprtınız.Lütfen tekrar tuşlama yapınız.\n")
        continue
    while True:
            choice = input("Tekrar işlem yapmak istiyormusunuz?(E/H):\n ")
            if choice.upper() =="E":
                break
            elif choice == "H":
                print("Program Sonlandırılıyor...")
                break
            else:
                print("Yanlış tuşlama yaprtınız.Lütfen tekrar tuşlama yapınız.")
                continue
        
        