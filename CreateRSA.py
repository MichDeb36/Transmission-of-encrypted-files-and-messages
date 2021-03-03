from Crypto.PublicKey import RSA
key = RSA.generate(2048)

private, public = key, key.publickey()
sPrivate = open('Keys\Private\private.pem', 'wb')
sPublic = open('Keys\Public\public.pem', 'wb')
sPrivate.write(private.export_key('PEM'))
sPublic.write(public.export_key('PEM'))
sPrivate.close()
sPublic.close()
