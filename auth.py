import serial
from rsa import RSA, genrsa
ser = serial.Serial('/dev/tty.usbserial-0001', 115200)
import os


bits = 2048
print("RSA bits", bits)
r = RSA(*genrsa(bits, e=65537, n=22844016404727758843775687051940287598974678231304687972699194239497463990007179937199334388674733076944798800417915297736323160920339245917823374587096481228706928683545848316554674861382114893910313065191755904236299595831982163069257511373594115870648555228347173289907423296935495128072064469174832685372028346425215202614218323710527374004913862101378010725507656630340535332206311162078546431734388605404097593288885881603595431454713921350330115956194661843980184691910786879317708782318754490546035983514802956614439851605576594747664162734612066597511124338565089903304673969613150493453401618488227032688359, d=0)) #No private key
if r:
    print("RSA OK")
    chal = os.urandom(64).hex() # create random bytes 
    print(chal)
    encrypted = r.pkcs_encrypt(chal.encode("UTF-8")) # encrypt random bytes with public key
    while True:
        data = ser.readline()
        print(f'Received data: {data}')
        if data == b'>\r\n': # Check if it is asking for encrypted data
            data_to_send = encrypted.hex() + "\r\n"
            ser.write(data_to_send.encode("UTF-8")) # Give encrypted data for it to decrypt
            print("Decrypting...")
            ser.readline() #Skip useless data
            data = ser.readline() #Wait for decrypted string
            if data.decode("UTF-8").replace('\n', '').strip() == chal: # Compare 
                print("Authenticated user!")
            else:
                print("Something went wrong!")
                print(chal) # print to see difference
                print(data.decode("UTF-8").replace('\n', ''))
            



