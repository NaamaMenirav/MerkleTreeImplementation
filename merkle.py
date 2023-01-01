# Task2
# Names:
# ID:

import hashlib
import math
import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def calculate_hash(leaf):
    return hashlib.sha256(leaf).hexdigest()


def concat(left: str, right: str) -> str:
    concatanted = left + right
    return calculate_hash(concatanted.encode('utf-8'))


def closest_power_of_2(list_len):
    i = 0
    power2 = 2 ** i
    while power2 < list_len:
        i += 1
        power2 = 2 ** i
    return power2


class Leaves(object):
    def __init__(self):
        self.leaves_list: list = []

    def add_leaf(self, new_leaf):
        self.leaves_list.append(calculate_hash(new_leaf.encode('utf-8')))

    def get_leaves(self) -> list:
        return self.leaves_list


class MerkleTree(object):

    def __init__(self):
        self.right = None
        self.left = None
        self.value = None

    def construct_tree(self, leaves: list):  # child is a MerkelTree
        if len(leaves) == 2:  # ab
            self.left = leaves[0]
            self.right = leaves[1]
            self.value = concat(self.left, self.right)
            return
        if len(leaves) == 1:  # ab  c , only child
            self.left = leaves[0]
            self.value = leaves[0]
            return
        power_of_2 = closest_power_of_2(len(leaves))
        self.left = MerkleTree()
        self.right = MerkleTree()
        self.left.construct_tree(leaves[:power_of_2 // 2])
        self.right.construct_tree(leaves[power_of_2 // 2:])
        self.value = concat(self.left.value, self.right.value)

    def display_root(self, leaves: list):
        self.construct_tree(leaves)
        return self.value

    def proof_of_inclusion(self, number: int, leaves: list):
        self.construct_tree(leaves)
        len_leaves = len(leaves)
        print(self.value)
        self.proof_of_inclusion_rec(number, len_leaves)

    def proof_of_inclusion_rec(self, number: int, len_leaves: int):
        if len_leaves == 2:
            if number == 1:
                print("0" + self.left)
            else:
                if self.right:
                    print("1" + self.right)
            return
        if len_leaves == 1:
            return
        if number >= closest_power_of_2(len_leaves) // 2:
            self.right.proof_of_inclusion_rec(number - closest_power_of_2(len_leaves) // 2,
                                              len_leaves - closest_power_of_2(len_leaves) // 2)
            print("0" + self.left.value)
        else:
            self.left.proof_of_inclusion_rec(number, closest_power_of_2(len_leaves) // 2)
            print("1" + self.right.value)

    # 4
    def check_proof_of_inclusion(self, str_to_find, inclusion_proof_3):
        inclusion_proof_3_list = inclusion_proof_3.split("\n")
        if self.value != inclusion_proof_3_list[0]:
            return False
        curr_node = self
        for i in range(len(inclusion_proof_3_list) - 1, 0, -1):
            curr_compare = (inclusion_proof_3_list[i])[1:]
            # The father of the wanted value
            if i == 1:
                if curr_node.left == curr_compare:
                    curr_node = curr_node.right
                elif curr_node.right == curr_compare:
                    curr_node = curr_node.left
                else:
                    return False
            # Pass over all the nodes until the father of the leaves
            else:
                if curr_node.left.value == curr_compare:
                    curr_node = curr_node.right
                elif curr_node.right.value == curr_compare:
                    curr_node = curr_node.left
                else:
                    return False

        # Check if the current node has the str_to_find as a value
        # The last node is a string and not a MerkleTree object
        hash_to_find = calculate_hash(str_to_find.encode('utf-8'))
        if curr_node != hash_to_find:
            return False
        else:
            return True

    @staticmethod
    def generate_keys():
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        public_key = private_key.public_key()

        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # print(private_pem.decode('utf-8'))
        # print(public_pem.decode('utf-8'))
        return private_pem.decode('utf-8'), public_pem.decode('utf-8')

    # 6
    def sign_root(self, private_key_string):
        root = self.value.encode('utf-8')
        private_key = serialization.load_pem_private_key(private_key_string.encode('utf-8'), password=None)
        signature = private_key.sign(root,
                                     padding.PSS(
                                         mgf=padding.MGF1(hashes.SHA256()),
                                         salt_length=padding.PSS.MAX_LENGTH
                                     ),
                                     hashes.SHA256())

        signature = base64.urlsafe_b64encode(signature).decode('utf-8')
        print(signature)
        return signature

    # 7
    @staticmethod
    def verify_signature(public_key_string, signature, text):
        print('here')
        public_key = serialization.load_pem_public_key(public_key_string.encode('utf-8'), backend=None)
        signature = signature.encode('utf-8')
        print(signature)
        signature = base64.b64decode(signature)
        print(signature)

        try:
            public_key.verify(signature,
                              text.encode('utf-8'),
                              padding.PSS(
                                  mgf=padding.MGF1(hashes.SHA256()),
                                  salt_length=padding.PSS.MAX_LENGTH
                              ),
                              hashes.SHA256()
                              )
            return True
        except InvalidSignature as e:
            return False


def handle_ex1(command_param_list: str, leaves: Leaves):
    leaves.add_leaf(command_param_list)


def handle_ex2(merkle_tree: MerkleTree, leaves: Leaves):
    """
    handles ex2 - displaying root hash value
    :param first_param:
    :param merkle_tree:
    :param leaves:
    """
    merkle_tree.display_root(leaves.get_leaves())


def handle_ex3(merkle_tree: MerkleTree, number: str, leaves: Leaves):
    if number.isnumeric() and int(number) < len(leaves.get_leaves()):
        merkle_tree.proof_of_inclusion(int(number), leaves.get_leaves())
    else:
        print("")


def handle_ex4(merkle_tree: MerkleTree, str_to_find: str, proof: str):
    merkle_tree.check_proof_of_inclusion(str_to_find, proof)


def handle_ex5(merkle_tree: MerkleTree):
    print(merkle_tree.generate_keys())


def handle_ex6(merkle_tree: MerkleTree, private_key : str):
    if "-----BEGIN RSA PRIVATE KEY-----" not in private_key or "-----END RSA PRIVATE KEY-----" not in private_key:
        print("")
        return
    else:
        merkle_tree.sign_root(private_key)


def handle_ex7():
    pass


def input_handler(merkle_tree, leaves):
    """
    infinite loop iterating over users input
    command type and params are separated by space
    params are separated by newline
    """
    # input takes user entered input until newline
    # command consists of command type + first param
    command = input()  # "command_type first_param"
    command_param_list = command.split(" ")
    # there are no params for the command
    command_type = command_param_list[0]
    root = None
    while True:
        try:
            if command_type == "1":
                if len(command_param_list) == 2:
                    handle_ex1(command_param_list[1], leaves)
                else:
                    print("")
            elif command_type == "2":
                if len(command_param_list) == 1:
                    handle_ex2(merkle_tree, leaves)
                else:
                    print("")
            elif command_type == "3":
                if len(command_param_list) == 2:
                    handle_ex3(merkle_tree, command_param_list[1], leaves)
                else:
                    print("")
            elif command_type == "4":
                if len(command_param_list) == 3:
                    handle_ex3(merkle_tree, command_param_list[1], command_param_list[2])
                else:
                    print("")
            elif command_type == "5":
                if len(command_param_list) == 1:
                    handle_ex5(merkle_tree)
                else:
                    print("")
            elif command_type == "6":
                handle_ex6(command[2:])
            elif command_type == "7":
                print(command.split("\\n\\n"))

        except Exception as ex:
            continue


def main():
    l = Leaves()
    root = MerkleTree()
    l.add_leaf("a")
    root.construct_tree(l.get_leaves())

    # print(root.display_root())
    # print(root.proof_of_inclusion(0, l.get_leaves()))
    # print(root.proof_of_inclusion(2, l.get_leaves()))
    print(root.check_proof_of_inclusion("a", """d71dc32fa2cd95be60b32dbb3e63009fa8064407ee19f457c92a09a5ff841a8a
13e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d
12e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6"""))
    #     print(root.check_proof_of_inclusion("b", """d71dc32fa2cd95be60b32dbb3e63009fa8064407ee19f457c92a09a5ff841a8a
    # 13e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d
    # 12e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6"""))
    #     print(root.generate_keys())
    private_key_input = """-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1MAmLr5TwN8OnQF9OjfWGyGuHfl5056u7XBjYcsidkQHVLk
K
8NhFzSvBnQbi18PcXVSLusLPVnGs6a9rfN9NkCM6uSom0+lpFgMWuD/7w0HPIW7
C
w0hVlFNWvZ8vv5uzA/mzpF8S1fRmCMkfQyP4TDJ2MImQxcdkWDpFDq1pmvRJw
eav
zUnc2eUmuz4bwLYwv3CBKDlCSdIAFCkVP6PJl8cbZkOPqbVPMW+MLf+pZrKfWcz
C
xCnzHmLbzngClQp+4meAtGOGgKKwsmS1eA0BAYfao0g+cu1ESU5ePea/jrX0nJON
vDOAeh00keQvxE1xoEnKppbKT2F6RTyBITbCmwIDAQABAoIBAH0iQ5MMyVBRIl
RA
svpSKzGsHrBsszZASF1J1HqJs0xiePlhGUlNu8iQqwGEMlp8ThnrB4Ci4rbSh8Sv
NAavhPx5bCnK3CmaSP/0cyGOKLPQ+laMwiuAWS2z0voXLkuB9copzXqpnPeRF46l
VSj1eC7BI3krAKcDv0aRh1q5rrq/T3sH76nENwjxRVig9wZ1jWNBqpWD7LOx2M8I
NcW4ZbcALbREzKEyydZ1BBx0FXMYyeJRvRdmLzNCb7RZ/wz4B/1bSoUUi8mTBF6
x
ft6fZ6JQNak9r2PEvc7eh+FWoDF3Gu3PBFb0poX7SdWWle9qG6efTSiavUo+cetS
Qb0qV4kCgYEA+weJpApGEqxKwCe8oN+pd42QOmnKEzqQlZ33pSP97VmOQj6GcX
fu
onnH/0hu4jozj5N96kOCDjDPdpCOvUgzupJBhiRr1M/4y8f+SoWrRCuHHscnfh5Q
pv+iwpSHTcV8ys2fGowpmd9tZfGerJkvAcD/3jG1Mo+0anemHAoCbXUCgYEA2PaT
rBVXKJovd9ZjPqWX7MWhTh1NFGCquQPe4cX5h8wIgjSBqozsosKzKYHmK/kw7y
U/
P9UvCiEbiowPiqDZoSbZ6twpf2bcXjaVKWdRqFD+OvGXEvpPVvdbRUXv0J9UDsd1
EDM5/lX6Sja54ibIKP+okcjH3YPd4xbRvZoyHc8CgYARJgGsGBuTWPu+RrinEMBl
72DD7MgmKiEIZ4MsX9oP5cdHFThf9f5yUPltoggZIjq1ezDl2PjAeWsiwVtO6OjH
vQgG3uQS5KYtXZssghciEAsp+hbjkbSWw+3ddwILOQt+Wy+cQ6jv3wh9J1VcmxZP
+1w/VIv5SUHc6BGL5s8lpQKBgQC4zfdlOdw+0m6iZfOtNgHdhU1rqxuvwtNIutpL
d4WfvRR2S+Ey88zQqoVPUr1LMXwUB6cDaUQjHaZG8hx+2ZnmYaB3I8cZJPWKLn
YJ
iV8Nvsd+T7B+UsXn7tRIglTOYBiKaiz1epzoXjXOpyTYVG5kNbhRTTOpJJyIxTQs
iz4rEwKBgBxxJ6t4F8APkYkXaY5EB/Z6EtJJDbKgoqBkfWuVZ0DzPBmVKUbP6EKM
T085EM/HlQer1QQjfkdepVuCL7mdDjKcxVMiuMKPWtVlsJjtJMa11smmdqZ5UT/w
6R54/knAIkDXNlGE2xBXCcfKdhF2+lICi5COWEQk5NASSVdgfKjN
-----END RSA PRIVATE KEY-----"""
    # print(root.sign_root(private_key_input))
    public_key_input = """-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1MAmLr5TwN8OnQF9Oj
fW
GyGuHfl5056u7XBjYcsidkQHVLkK8NhFzSvBnQbi18PcXVSLusLPVnGs6a9rfN9N
kCM6uSom0+lpFgMWuD/7w0HPIW7Cw0hVlFNWvZ8vv5uzA/mzpF8S1fRmCMkfQ
yP4
TDJ2MImQxcdkWDpFDq1pmvRJweavzUnc2eUmuz4bwLYwv3CBKDlCSdIAFCkVP6
PJ
l8cbZkOPqbVPMW+MLf+pZrKfWczCxCnzHmLbzngClQp+4meAtGOGgKKwsmS1eA
0B
AYfao0g+cu1ESU5ePea/jrX0nJONvDOAeh00keQvxE1xoEnKppbKT2F6RTyBITbC
mwIDAQAB
-----END PUBLIC KEY-----"""
    signature_base64 = """LhnptHJUc4M0GVZR+wbp5NC6owLwH2+N/UpOKV6jnyH8iA8YoVSQkMU63z8QZ
yr50L1f4hTWSxZbjzeQ1Rm/1OyAyX9QdQHIrMWRjOx0GPfqPi4wmcmF9ZxPr7Sh
wRZtbqz9mAekKYDell44Pj21xKsFFy4PgpnxrXFNppPOA3ZpQk245bYPIdzYpcmq0
FyYx5RQQCQYBV69QrQOAvvkVVkwZbiqI0/+tZWmfNdV/x6E3PWYljSccMLW/m4
nhcy+XQ39Q2oxIzYlobwndW3epxEReLzP7qeN9BR/BVew2yCn4quhm1fA7544mp
ZaW0VynQDRHBy7gqJDhuWRLjKOcQ=="""
    print(root.generate_keys().decode("utf-8"))
    hash_root = "ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bc"
    sign_root_output = root.sign_root(private_key_input)
    print("---------------------------------------")
    print(sign_root_output)
    print("---------------------------------------")


# print(root.verify_signature(public_key_input, signature_base64, hash_root))


if __name__ == '__main__':
    main()
