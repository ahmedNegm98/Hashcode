import hashlib
import secrets
class HashTruncator:
    SALT_BYTES = 16
    HASH_ITERATIONS = 100000
    PASSWORD_HASH = "f51b0beade4f415e7d87b6815f6668d498f66066a582b2692dff4c2d622c9693"  

    @classmethod
    def hash_password(self, password, salt):
        hash_func = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, self.HASH_ITERATIONS)
        return hash_func.hex()

    @classmethod
    def generate_salt(self):
        return secrets.token_bytes(self.SALT_BYTES)

    def __init__(self, input_data):
        self.input_data = input_data
        self.hash_value = hashlib.sha256(input_data).hexdigest()
        self.encoded_value = [ord(c) for c in self.hash_value]
        self.n = len(self.encoded_value) // 3

    def truncate_hash(self):
        user_input = input("Enter the password to access the class file: ")
        salt = b'\xd1V\xfd1\xe2\x16\x04w\nM\x1f\xe9\xd7\xf9\xc2\xe5'
        hashed_input = self.hash_password(user_input, salt)
        # print (self.PASSWORD_HASH,hashed_input)
        if hashed_input == self.PASSWORD_HASH:
            truncated_value0 = self.encoded_value[0]
            truncated_value1 = self.encoded_value[self.n]
            truncated_value2 = self.encoded_value[2*self.n]

            for i in range(len(self.encoded_value)-1):
                if i <= self.n:
                    truncated_value0 ^= self.encoded_value[i+1]
                elif i < 2*self.n:
                    truncated_value1 ^= self.encoded_value[i+1]
                else:
                    truncated_value2 ^= self.encoded_value[i+1]

            truncated_value = str(truncated_value0) + str(truncated_value1) + str(truncated_value2)
            return truncated_value[:6]
        else : 
            return 0    


##from HashClass import HashTruncator
txt = input("Enter the text: ")
while (txt != '0'):
    txt_bytes = txt.encode('utf-8')  # Convert string to bytes
    hash_truncator = HashTruncator(txt_bytes)

    ##hash_truncator.hashed_password =  input("Enter the password to access the class file: ")
    truncated_hash = hash_truncator.truncate_hash()
    print("Truncated Hash:", truncated_hash)
    txt = input("Enter the text: \"Zero to exit\" ")
