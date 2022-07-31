#utils
A = 0
B = 7

# 有限域的阶
P = 115792089237316195423570985008687907853269984665640564039457584007908834671663
# 椭圆曲线的阶
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337


'''计算二次剩余 满足x^2=y mod p的x'''
def Legendre(y,p): # 判断二次（非）剩余
    return pow(y,(p - 1) // 2,p)
def T_S(y,p):
    assert Legendre(y,p) == 1
    if p % 4 == 3:
        return pow(y,(p + 1) // 4,p)
    q = p - 1
    s = 0
    while q % 2 == 0:
        q = q // 2
        s += 1
    for z in range(2,p):
        if Legendre(z,p) == p - 1:
            c = pow(z,q,p)
            break
    r = pow(y,(q + 1) // 2,p)
    t = pow(y,q,p)
    m = s
    if t % p == 1:
        return r
    else:
        i = 0
        while t % p != 1: 
            temp = pow(t,2**(i+1),p)
            i += 1
            if temp % p == 1:
                b = pow(c,2**(m - i - 1),p)
                r = r * b % p
                c = b * b % p
                t = t * c % p
                m = i
                i = 0 
        return r


'''欧几里得求逆元'''
def Euclidean(j, k):
    if j == k:
        return (j, 1, 0)
    else:
        i = 0
        j_array = [j]
        k_array = [k]
        q_array = []
        r_array = []

        prev_r_is_zero = False

        while not (prev_r_is_zero):
            q_array.append(k_array[i]//j_array[i])
            r_array.append(k_array[i]%j_array[i])
            k_array.append(j_array[i])
            j_array.append(r_array[i])
            i += 1
            if r_array[i-1] == 0:
                prev_r_is_zero = True
        i -= 1
        gcd = j_array[i]
        x_array = [1]
        y_array = [0]

        i -= 1
        total_steps = i

        while i >= 0:
            y_array.append(x_array[total_steps-i])
            x_array.append(y_array[total_steps-i] - q_array[i]*x_array[total_steps-i])
            i -= 1

        return (gcd, x_array[-1], y_array[-1])

def mod_inverse(j, n):
    (gcd, x, y) = Euclidean(j, n)

    if gcd == 1:
        return x%n
    else:
        return -1


'''椭圆曲线加、乘'''
def Elliptic_Add(p, q):
    if p == 0 and q == 0: return 0
    elif p == 0: return q
    elif q == 0: return p
    else:
        # Swap p and q if px > qx.
        if p[0] > q[0]:
            temp = p
            p = q
            q = temp
        r = []
        Slp = (q[1] - p[1])*mod_inverse(q[0] - p[0], P) % P

        r.append((Slp**2 - p[0] - q[0]) % P)
        r.append((Slp*(p[0] - r[0]) - p[1]) % P)

        return (r[0], r[1])


def Elliptic_Double(p):
    r = []
    num=1

    Slp = (3*p[0]**2 + A)*mod_inverse(2*p[1], P) % P
    if num==1:
        r.append((Slp**2 - 2*p[0])%P)
        r.append((Slp*(p[0] - r[0]) - p[1])%P)

    return (r[0], r[1])


# 计算比特位数
def Get_Bitnums(x):
    if isinstance(x, int):
        nums = 0
        tmp = x >> 64
        while tmp:
            nums += 64
            tmp >>= 64
        tmp = x >> nums >> 8
        while tmp:
            nums += 8
            tmp >>= 8
        x >>= nums
        while x:
            nums += 1
            x >>= 1
        return nums
    elif isinstance(x, str):
        return len(x.encode()) << 3
    elif isinstance(x, bytes):
        return len(x) << 3
    return 0


def Elliptic_Multiply(s, p):
    n1 = p
    r1 = 0 

    s_binary = bin(s)[2:] 
    s_length = len(s_binary)

    for i in reversed(range(s_length)):
        if s_binary[i] == '1':
            r1 = Elliptic_Add(r1, n1)
        n1 = Elliptic_Double(n1)

    return r1




#sm2

import secrets
from hashlib import sha256
from gmssl import sm3, func
A = 0
B = 7

G_X = 55066263022277343669578718895168534326250603453777594175500187360389116729240
G_Y = 32670510020758816978083085130507043184471273380659243275938904335757337482424

G = (G_X, G_Y)
# 有限域的阶
P = 115792089237316195423570985008687907853269984665640564039457584007908834671663
# 椭圆曲线的阶
N = 115792089237316195423570985008687907852837564279074904382605163141518161494337


def Precompute(ID,a,b,G_X,G_Y,x_A,y_A):# ID，椭圆曲线参数a、b,G点x、y,公钥x、y
    a=str(a)
    b=str(b)
    G_X=str(G_X)
    G_Y=str(G_Y)
    x_A=str(x_A)
    y_A=str(y_A)
    ENTL=str(Get_Bitnums(ID))

    joint=ENTL+ID+a+b+G_X+G_Y+x_A+y_A
    joint_b=bytes(joint,encoding='utf-8')
    digest= sm3.sm3_hash(func.bytes_to_list(joint_b))
    return int(digest, 16)



def Generate_Key():
    private_key = int(secrets.token_hex(32), 16)
    public_key = Elliptic_Multiply(private_key, G)
    return private_key, public_key





def Sign(private_key, message,Z_A):#私钥签名
    _M=Z_A+message
    _M_b=bytes(_M,encoding='utf-8')
    e = sm3.sm3_hash(func.bytes_to_list(_M_b))
    e=int(e, 16)

    k = secrets.randbelow(P)#0~P的随机数
    random_point = Elliptic_Multiply(k, G)

    print(random_point,'randpoint')
    r =( e+random_point[0] )% N
    s = (mod_inverse(1+private_key, N) * (k - r*private_key))%N  
    return (r, s)




def Verify(public_key,ID, message, Signature):#验证

    r=Signature[0]
    s=Signature[1]

    Z=Precompute(ID,A,B,G_X,G_Y,public_key[0],public_key[1])

    _M=str(Z)+message
    _M_b=bytes(_M,encoding='utf-8')
    e=sm3.sm3_hash(func.bytes_to_list(_M_b))#str
    e=int(e, 16)



    t=(r+s) % N

    point=Elliptic_Multiply(s ,G)
    point1=Elliptic_Multiply(t ,  public_key)
    point=Elliptic_Add(point,point1)

    x1=point[0]
    x2=point[1]
    R=(e+x1)%N
    print('r',r)
    print(R)

    return R==r



if __name__=='__main__':
    prikey, pubkey = Generate_Key()
    print('公钥：',pubkey)
    message = "sdu"
    ID='qxy'
    Z_A=Precompute(ID,A,B,G_X,G_Y,pubkey[0],pubkey[1])
    Signature = Sign(prikey, message,str(Z_A))
    print("签名: ",Signature)

    '''验证'''
    if Verify(pubkey,ID,message,Signature)==1:
        print('验证通过')


