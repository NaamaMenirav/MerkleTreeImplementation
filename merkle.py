# Task2
# Names:
# ID:

import hashlib
import math
import base64


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


class leaves(object):
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

    def display_root(self):
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


def main():
    l = leaves()
    root = MerkleTree()
    l.add_leaf("a")
    l.add_leaf("b")
    l.add_leaf("c")
    root.construct_tree(l.get_leaves())

    # print(root.display_root())
    # print(root.proof_of_inclusion(0, l.get_leaves()))
    # print(root.proof_of_inclusion(2, l.get_leaves()))
    print(root.check_proof_of_inclusion("a", """d71dc32fa2cd95be60b32dbb3e63009fa8064407ee19f457c92a09a5ff841a8a
13e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d
12e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6"""))
    print(root.check_proof_of_inclusion("b", """d71dc32fa2cd95be60b32dbb3e63009fa8064407ee19f457c92a09a5ff841a8a
13e23e8160039594a33894f6564e1b1348bbd7a0088d42c4acb73eeaed59c009d
12e7d2c03a9507ae265ecf5b5356885a53393a2029d241394997265a1a25aefc6"""))


if __name__ == '__main__':
    main()
