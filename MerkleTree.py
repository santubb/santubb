# MerkleTree

from hashlib import sha256
import random
import string
import math


# 随机生成data
def generate_data(length):
    res = []
    for i in range(length):
        blocksize = [random.choice(string.digits + string.ascii_letters) for i in range(5)]  # 一个消息块长为5
        res.append(''.join(blocksize))
    return res


# 生成MerkleTree
def generate_merkletree(data):
    deep = math.ceil(math.log2(len(data)) + 1)  # merkle tree深度
    merkletree = [[sha256(i.encode()).hexdigest() for i in data]]  # merkle tree的第0层(倒置)
    for i in range(deep - 1):
        len_lay = len(merkletree[i])  # 第i层消息块个数
        mkt_lay = [sha256(merkletree[i][j * 2].encode() + merkletree[i][j * 2 + 1].encode()).hexdigest() for j in
                   range(int(len_lay / 2))]  # merkle tree的第i+1层
        if len_lay % 2 != 0:
            mkt_lay.append(merkletree[i][-1])  # 若块数为奇数，则最后一个块直接放入下一层
        merkletree.append(mkt_lay)
    return merkletree


def proof(spec_elm, merkletree, root):
    hash_le = (sha256(spec_elm.encode())).hexdigest()
    if hash_le in merkletree[0]:
        index_le = merkletree[0].index(hash_le)  # 指定元素在数第一层的索引值
    else:
        return "This message isn't in the data."
    deep = len(merkletree)  # merkle tree深度
    audit_path = []  # 审计路线
    for i in range(deep - 1):
        if index_le % 2 == 0:  # 左子结点
            if len(merkletree[i]) - 1 != index_le:  # 该结点不是该层最后的一个单独结点
                audit_path.append(['l', merkletree[i][index_le + 1]])
        else:  # 右子结点
            audit_path.append(['r', merkletree[i][index_le - 1]])
        index_le = int(index_le / 2)    # 更新索引值
    for ele in audit_path:
        if ele[0] == 'l':
            hash_le = sha256(hash_le.encode() + ele[1].encode()).hexdigest()
        else:
            hash_le = sha256(ele[1].encode() + hash_le.encode()).hexdigest()
    if hash_le == root:
        return "This message is in the merkle tree."
    else:
        return "This message is in the data but it isn't in the merkle tree."


if __name__ == "__main__":
    data = generate_data(100000)
    data2 = generate_data(100000)
    index = random.randint(0, 99999)
    spec_element = data[index]       # inclusion proof
    data2[index] = spec_element      # exclusion proof 指定消息在data中
    spec_element2 = '12345'          # exclusion proof 指定消息不在data中(大概率)
    merkletree = generate_merkletree(data)
    merkletree2 = generate_merkletree(data2)
    root = merkletree[-1][0]
    print("For message:", spec_element, proof(spec_element, merkletree, root))
    print("For message:", spec_element, proof(spec_element, merkletree2, root))
    print("For message:", spec_element2, proof(spec_element2, merkletree, root))
