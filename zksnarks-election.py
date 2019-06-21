#!/usr/bin/env python
# encoding: utf-8
'''
@author: xuqiang
@license: (C) Copyright 2013-2022.
@contact: xq-310@163.com
@software: wallet
@file: zksnarks-election.py.py
@time: 2019/6/21 下午10:16
@desc:
'''

from hashlib import sha256
from random import getrandbits
import random
import string

def Hash(msg):
    msg = msg.encode('utf-8')
    return sha256(msg).hexdigest()

def random_id(number):
    return [(''.join(random.sample(string.digits,4))) for i in range(2**number)]

def hash_id(id, number):
    return [Hash(id[i]) for i in range(2**number)]

def GetTreeRoot(id, path):
    d=id
    for p in path:
        d=Hash(d+p)
    return d

class zksnarks():

    def __init__(self):
        pass
    #这里是约束函数
    def Circuit(self, pub, witness):
        return (Hash(witness["private"]) in id_hash
                and pub["root"]==GetTreeRoot(Hash(witness["private"]),witness["path"])
                and pub["vote_hash"]==Hash(witness["private"]+pub["vote"]))
    #通过约束函数，生成证明密钥和验证密钥
    def Setup(self, key):
        proof_key = key + id(self.Circuit)
        verify_key = key - id(self.Circuit)
        return proof_key,verify_key
    #生成proof
    def Proof(self, proof_key, pub, witness):
        proof = proof_key+self.Circuit(pub, witness)+int(Hash(str(pub))[:6],16)
        return proof
    #验证函数
    def Verify(self, verify_key, pub, proof):
        result = verify_key+2*id(self.Circuit)+1+int(Hash(str(pub))[:6],16)
        return result==proof

class Merkletree():
    #初始化，number要创建能够容纳用户，但是其表示2的number次幂，例如number=3，则表示
    #有8个人投票；hash_id是一个列表，是所有用户id的集合；
    #初始化函数，使用字典构建一个tree结构，包含了从叶子节点一直到根节点所有hash值；
    def __init__(self, number, hash_id):
        self.tree={}
        self.number=number
        for i in range(number, -1, -1):
            tree_tmp={}
            for j in range(1, 2**i+1, 1):
                if i==number:
                    tree_tmp[j]=hash_id[j-1]
                else:
                    tree_tmp[j]=Hash(self.tree[i+1][j*2-1]+self.tree[i+1][j*2])
            self.tree[i]=tree_tmp
    #获取根节点hash
    @property
    def root(self):
        return self.tree[0][1]
    #用户输入number（这里的nubmer表示的是叶子节点的顺序，从1开始依次+1）
    #根据number，生成用户验证路径，返回一个列表
    def path(self, number):
        path=[]
        num=number
        for i in range(self.number, 0, -1):
            if num%2==0:
                path.append(self.tree[i][num-1])
                num=int(num/2)
            else:
                path.append(self.tree[i][num+1])
                num=int((num+1)/2)
        return path

#生成随机用户私钥以及私钥hash的函数（id），初始化自己生成一套即可；其实3表示2的3次幂=8
#private_key=random_id(3)
#id_hash=hash_id(private, 3)

private_key=['8735', '0364', '8927', '3941', '8931', '7150', '1824', '4083']
id_hash=['cc4996f23b1298387d649919eaa4f4f1f1c26ef836af118ca1334a366efbf979', 'b9ff439e33f8f6f58616593936746d86adc8163a38bc44580d2bbc2ffc965a62', '1211b78610929c31e748981c4df7adba9b068e63fd887ec1a3b1af46c2dba1c1', '6621ead3c9ec19dfbd65ca799cc387320c1f22ac0c6b3beaae9de7ef190668c4', '699415a6e63027a2c3cb8fcb891dab4c62a28b6a15dbe6ccf5dab0126c02505b', '02cf62656564decc54131e85c0415cbad4eb573a24278854fe8bc4aa3fe45268', '2ced184d8477465987593807f31360e94b539aa41f515e0a973179f881663698', 'd0ab3354a660b3abcb7829c7636981ddc8ce4a68c943947081ff8399f063f786']

#生成随机秘钥
random_key = getrandbits(256)

#这里的3也是指数，生成一个8人的tree，另外一个参数是用户id集合；
mtree=Merkletree(3,id_hash)

#正确的身份投票Jordan，验证通过
vote="Jordan" #投票内容
vote_hash=Hash(private_key[0]+vote)  #由于发送投票结果可能会被截获，所以和用户的私钥绑定
witness={"private":private_key[0],"path":mtree.path(1)}
pub={"root":mtree.root,"vote":vote, "vote_hash":vote_hash}#这一部分就是用户需要发送投票结果，里边没有包含任何个人身份信息

zk=zksnarks()
pk, vk=zk.Setup(random_key)#生成vk，pk
proof=zk.Proof(pk,pub,witness)
ret=zk.Verify(vk,pub,proof)
print("vote:",pub["vote"],"   result:",ret)


#错误的身份投票Jordan，验证失败
vote="Jordan"
vote_hash=Hash("6666"+vote)
witness={"private":"6666","path":mtree.path(1)}
pub={"root":mtree.root,"vote":vote, "vote_hash":vote_hash}

zk=zksnarks()
pk, vk=zk.Setup(random_key)
proof=zk.Proof(pk,pub,witness)
ret=zk.Verify(vk,pub,proof)
print("vote:",pub["vote"],"   result:",ret)