from rsa import RSA, genrsa


byts = b'\xa8\x90?\x0f\xe2\xec\x90?{\x99D\xc8eF\xa0\xce\xd1\xb0\xb7\x84\x92!n\xf5\x08G]w\x81\xe7\xeex9A49\xdc\x89K\x05\x99qQ\xe8E\xefx\xf4\x19\xa8\xab\x80\xd7\x9f\x98l\xb4\x8c\xbf/\xb9\x8a}U\x1c{*\xd4\t\xc2\x02\t\xd0\x1e\xd5\x9arrH\xe2v@;\x80\xf9\xb7\xca\x08\x03\x12\x0b]\x19\x95<f\xb7\x98\xc6\x8ag\x0f\x8f\xd4\xf7A\xd9\xb05\xb8-KR\xc6\x05GE/|\xef\x8b\xba\xd5\x9c\xe0P\x15\xf3\xc5\xaf\xa1\x9d\x9dv\xd7[\x10\x04pa6\xcbTV\xf1\\g\xa8k\r6e1\xc0\xea\xb8\x1b\rz1\x9bw\xdf\x85\x16c\x1e.\xdd-\x04r\xb7\xa99\xd0\xf1.>L\xe33\x04\xc5;\r\xb9\xe4\xe2\xa6\x8b\x0cIF\x87\xf8L\xf2\xe9\xe5_\xb8\xbfrF\xaf8\x0b\x84\xa9\xd4K\n\xe7\xa2\xedm\xc6U\xd6\xad\xad1V~\x93\xb4\xa6T\x19\xb1\x18+;wMY93P$4R\x10\xd4\x07\xb2\x8c\xb83\xabp\x03\x1ba\xb3'
bits = 2048
print(byts.hex())
print("RSA bits", bits)
r = RSA(*genrsa(bits, e=65537, n=22844016404727758843775687051940287598974678231304687972699194239497463990007179937199334388674733076944798800417915297736323160920339245917823374587096481228706928683545848316554674861382114893910313065191755904236299595831982163069257511373594115870648555228347173289907423296935495128072064469174832685372028346425215202614218323710527374004913862101378010725507656630340535332206311162078546431734388605404097593288885881603595431454713921350330115956194661843980184691910786879317708782318754490546035983514802956614439851605576594747664162734612066597511124338565089903304673969613150493453401618488227032688359, d=0)) #No private key
if r:
    print("RSA OK")
    data = b"a message to sign and encrypt via RSA"
    print("random data len:", len(data), data)
    assert r.pkcs_verify(r.pkcs_sign(data)) == data
    print(r.pkcs_encrypt(data))
    assert r.pkcs_decrypt(r.pkcs_encrypt(data)) == data
    print("pkcs_decrypt OK")
    print(r.n)
    print(r.d)
    print(r.pkcs_decrypt(byts))


