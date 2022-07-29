#Rho_method
import random
def rho_method(example):
    x = hex(random.randint(0, 2**(example+1)-1))[2:]
    num = int(example/4)                # 16进制位数
    x_1 = SM3(x)                
    x_2 = SM3(x_1)             
    i = 1
    while x_1[:num] != x_2[:num]:
        i += 1
        x_1 = SM3(x_1)              
        x_2 = SM3(SM3(x_2))    
    x_2 = x_1           
    x_1 = x             
    for j in range(i):
        if SM3(x_1)[:num] == SM3(x_2)[:num]:
            return SM3(x_1)[:num], x_1, x_2
        else:
            x_1 = SM3(x_1)
            x_2 = SM3(x_2)


if __name__ == '__main__':
    example = 8    # 此处进行前8bit的碰撞以作演示
    Hex, m1, m2 = rho_method(example)
    print("成功找到碰撞！")
    print("消息1:", m1)
    print("消息2:", m2)
    print("两者哈希值的前{}bit相同，16进制表示为:{}".format(example, Hex))
