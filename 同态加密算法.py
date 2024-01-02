import rsa
import rsa.core
import sympy


class Paillier:
    def __init__(self, p=7, q=11):
        self.p = p
        self.q = q
        self.public_key_g = 5652

        if sympy.gcd(self.p * self.q, (self.p - 1) * (self.q - 1)) == 1:
            # 密钥生成
            self.public_key_n = self.p * self.q  # 公钥（n, g)
            self.private_key_m  = sympy.lcm(self.p - 1, self.q - 1)  # 私钥m

            for i in range(self.public_key_n**2):    # 私钥u
                add = i*((((self.public_key_g**self.private_key_m) % (self.public_key_n**2)) - 1) / self.public_key_n)
                if add % self.public_key_n == 1:
                    self.private_key_u = i
                    break
        else:
            print('p，q不满足互为素数！')

    def encrypt(self, M):
        # 加密算法
        r = 23
        C = ((self.public_key_g ** M) * (r ** self.public_key_n)) % self.public_key_n ** 2
        return C

    def decrypt(self, C):
        # 解密算法
        L1 = (((C**self.private_key_m) % self.public_key_n**2)-1) / self.public_key_n
        M = (L1 * self.private_key_u) % self.public_key_n
        return M


# 乘法同态
def Multiplicative_homomorphism(a, b):
    [public_key, private_key] = rsa.newkeys(512)  # 密钥生成
    encrypto1 = rsa.core.encrypt_int(a, public_key.e, public_key.n)  # e(a)
    encrypto2 = rsa.core.encrypt_int(b, public_key.e, public_key.n)  # e(b)
    decrypto = rsa.core.decrypt_int(encrypto1 * encrypto2, private_key.d, public_key.n)  # d(e(c))=d(e(a)*e(b))
    print('乘法同态：')
    print('encrypto1 = ' + str(encrypto1))
    print('encrypto2 = ' + str(encrypto2))
    print('encrypto1 * encrypto2 = ' + str(encrypto1 * encrypto2))
    print('decrypto = ' + str(decrypto) + '\n')


# 加法同态
def Additive_homomorphism(a, b):
    add = Paillier()
    encrypto1 = add.encrypt(a)
    encrypto2 = add.encrypt(b)
    decrypto = add.decrypt(encrypto1 * encrypto2)
    print('加法同态：')
    print('encrypto1 = ' + str(encrypto1))
    print('encrypto2 = ' + str(encrypto2))
    print('encrypto1 * encrypto2 = ' + str(encrypto1 * encrypto2))
    print('decrypto = ' + str(decrypto))


if __name__ == '__main__':
    a = 19
    b = 26
    Multiplicative_homomorphism(a, b)
    Additive_homomorphism(a, b)
