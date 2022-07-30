
iv = [0x7380166F, 0x4914B2B9, 0x172442D7, 0xDA8A0600, 0xA96F30BC, 0x163138AA, 0xE38DEE4D, 0xB0FB0E4E]
T = [0x79cc4519, 0x7a879d8a]


def Shiftleft(X, i):
    i = i % 32
    return ((X << i) & 0xFFFFFFFF) | ((X & 0xFFFFFFFF) >> (32 - i))


def f_f(X, Y, Z, j):
    if j >= 0 and j <= 15:
        return X ^ Y ^ Z
    else:
        return ((X & Y) | (X & Z) | (Y & Z))


def g_g(X, Y, Z, j):
    if j >= 0 and j <= 15:
        return X ^ Y ^ Z
    else:
        return ((X & Y) | (~X & Z))

def t_t(j):
    if j >= 0 and j <= 15:
        return T[0]
    else:
        return T[1]


def p_0(X):
    return X ^ Shiftleft(X, 9) ^ Shiftleft(X, 17)


def p_1(X):
    return X ^ Shiftleft(X, 15) ^ Shiftleft(X, 23)

def CF(V, M, i):
    A, B, C, D, E, F, G, H = V[i]
    W, W_ = Expand(M, i)
    for j in range(64):
        SS1 = Shiftleft((Shiftleft(A, 12) + E + Shiftleft(t_t(j), j % 32)) % (2 ** 32), 7)
        SS2 = SS1 ^ Shiftleft(A, 12)
        TT1 = (f_f(A, B, C, j) + D + SS2 + W_[j]) % (2 ** 32)
        TT2 = (g_g(E, F, G, j) + H + SS1 + W[j]) % (2 ** 32)
        D = C
        C = Shiftleft(B, 9)
        B = A
        A = TT1
        H = G
        G = Shiftleft(F, 19)
        F = E
        E = p_0(TT2)
    a, b, c, d, e, f, g, h = V[i]
    V_ = [a ^ A, b ^ B, c ^ C, d ^ D, e ^ E, f ^ F, g ^ G, h ^ H]
    return V_


def Insert(message):
    m = bin(int(message, 16))[2:]
    if len(m) != len(message) * 4:
        m = '0' * (len(message) * 4 - len(m)) + m
    l = len(m)
    l_bin = '0' * (64 - len(bin(l)[2:])) + bin(l)[2:]
    m = m + '1'
    if len(m) % 512 > 448:
        m = m + '0' * (512 - len(m) % 512 + 448) + l_bin
    else:
        m = m + '0' * (448 - len(m) % 512) + l_bin
    m = hex(int(m, 2))[2:]
    return m


def Group(m):
    n = len(m) / 128
    M = []
    for i in range(int(n)):
        M.append(m[0 + 128 * i:128 + 128 * i])
    return M

def Iterate(M):
    n = len(M)
    V = []
    V.append(iv)
    for i in range(n):
        V.append(CF(V, M, i))
    return V[n]

def Expand(M, n):
    W = []
    W_ = []
    for j in range(16):
        W.append(int(M[n][0 + 8 * j:8 + 8 * j], 16))
    for j in range(16, 68):
        W.append(p_1(W[j - 16] ^ W[j - 9] ^ Shiftleft(W[j - 3], 15)) ^ Shiftleft(W[j - 13], 7) ^ W[j - 6])
    for j in range(64):
        W_.append(W[j] ^ W[j + 4])
    Wstr = ''
    W_str = ''
    for x in W:
        Wstr += (hex(x)[2:] + ' ')
    for x in W_:
        W_str += (hex(x)[2:] + ' ')
    return W, W_



def SM3(message):
    m = Insert(message)  # 填充后消息
    M = Group(m)  # 数据分组
    Vn = Iterate(M)  # 迭代
    res = ''
    for x in Vn:
            res += hex(x)[2:]
    return res


if __name__ == '__main__':
    print(SM3('655231'))
