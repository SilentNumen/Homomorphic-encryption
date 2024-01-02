import rsa
import rsa.core
import random


class compare:
    def __init__(self):
        [public_key, private_key] = rsa.newkeys(512)
        self.public = public_key
        self.private = private_key

    def get_publickey(self):
        return self.public

    def get_privatekey(self):
        return self.private

    def set_num(self, z: list, n):
        for i in range(len(z)):
            z[i] = z[i] + 1
            if i == n-1:
                break
        return z

    def varify(self, z, n, x, p):
        for i in range(len(z)):
            if i == n-1:
                if z[i] == x % p:
                    print('Alice < Bob')
                else:
                    print('Alice >= Bob')


if __name__ == '__main__':
    M = compare()
    moneyA = random.randint(1, 10)    # 富翁Alice财富
    moneyB = random.randint(1, 10)    # 富翁Bob财富
    print('富翁Alice财富：' + str(moneyA))
    print('富翁Bob财富：' + str(moneyB))
    # Bob方操作 step1
    x = random.randint(100, 999)
    public_key = M.get_publickey()
    k = rsa.core.encrypt_int(x, public_key.e, public_key.n)
    # Alice方操作 step2
    z = []
    p = 17
    private_key = M.get_privatekey()
    for i in range(10):
        dec = rsa.core.decrypt_int(k-moneyB+1+i, private_key.d, public_key.n)
        z.append(dec % p)
    print(z)
    z = M.set_num(z, moneyA)
    print(z)
    # Bob方操作 step3
    M.varify(z, moneyB, x, p)
