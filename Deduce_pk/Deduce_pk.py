#deduce_pk

import ecdsa
import random
import hashlib


if __name__ == "__main__":
    G = ecdsa.NIST256p.generator
    n = G.order()
    d_A = random.randrange(1, n - 1)      # 生成私钥d_A
    # 生成公私钥对象
    public_key = ecdsa.ecdsa.Public_key(G, G * d_A)
    private_key = ecdsa.ecdsa.Private_key(public_key, d_A)
    message = "santubbgithub"
    e = int(hashlib.sha1(message.encode("utf8")).hexdigest(), 16)   # Hash(m)
    k = random.randrange(1, n - 1)    # 生成临时密钥
    sign = private_key.sign(e, k)      # 生成签名(r,s)
    r = sign.r
    s = sign.s
    curve = G.curve()
    p = curve.p()       # 素域阶
    de_p_key = []       # 被恢复出的公钥
    x_lst = [r]         # P = kG,x为P横坐标,x = r mod n
    if r < p-n:
        x_lst.append(r + n)     
    for i in range(len(x_lst)):
        x = x_lst[i]
        y_square = (pow(x, 3, curve.p()) + (curve.a() * x) + curve.b()) % curve.p()     
        y_hat = ecdsa.numbertheory.square_root_mod_prime(y_square, curve.p())
        y = y_hat if y_hat % 2 == 0 else curve.p() - y_hat

        R1 = ecdsa.ellipticcurve.PointJacobi(curve, x, y, 1, n)
        Q1 = ecdsa.numbertheory.inverse_mod(r, n) * (s * R1 + (-e % n) * G)     
        Pk1 = ecdsa.ecdsa.Public_key(G, Q1)

        R2 = ecdsa.ellipticcurve.PointJacobi(curve, r, -y, 1, n)
        Q2 = ecdsa.numbertheory.inverse_mod(r, n) * (s * R2 + (-e % n) * G)     
        Pk2 = ecdsa.ecdsa.Public_key(G, Q2)
        de_p_key.append([Pk1.point.x(), Pk1.point.y()])
        de_p_key.append([Pk2.point.x(), Pk2.point.y()])
    p_key = [public_key.point.x(), public_key.point.y()]
    if p_key in de_p_key:
        print("Deduce public key from signature successfully!")
        print("The deduced public keys are:")
        for i in range(len(de_p_key)):
            print(de_p_key[i])
        print("The true public key is:\n", p_key)
    else:
        print("Didn't deduce public key from signature")
