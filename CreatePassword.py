from hashlib import sha256

userPassword = 'admin'


hashedWord = sha256(userPassword.encode())
password = open('Keys\Password\password.pem','wb')
password.write(hashedWord.hexdigest().encode())
password.close()

print(hashedWord)
