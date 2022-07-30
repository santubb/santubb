#birthday attack
def birthday_attack(example):
    num = int(2 ** (example / 2))  # 所要搜寻原像空间的大小
    sst = [-1] * 2**example        # 这里即用空间换时间，也可以使用字典查询，但是当碰撞bit数较大时运行较慢
    for i in range(num):
        temp = int(SM3(str(i))[0:int(example / 4)], 16)
        if sst[temp] == -1:
            sst[temp] = i
        else:
            return hex(temp), i, sst[temp]


if __name__ == '__main__':
    example = 8    # 此处进行前8bit的碰撞以作演示，实际可找到更多位数
    Hex, m1, m2 = birthday_attack(example)
    print("成功找到碰撞，消息{}与{}哈希值的前{}bit相同，16进制表示为:{}。".format(m1, m2, example, Hex))
