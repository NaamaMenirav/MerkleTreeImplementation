# Credit
# Name: Gali
# Name: Naama Menirav


import hashlib
import base64

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def calculate_hash(leaf):
    """
    This function calculates the hash of a given string
    :param leaf: string
    :return: calculation of hash in hexa
    """
    return hashlib.sha256(leaf).hexdigest()


def concat(left: str, right: str) -> str:
    """
    This function concatenates between two strings
    :param left: string
    :param right: string
    :return: concatenated string
    """
    concatented = left + right
    return calculate_hash(concatented.encode('utf-8'))


def closest_power_of_2(list_len):
    """
    This function calculates the closest power of 2 to the amount of the leaves.
    Merkle Tree is a tree that is full to the left.
    The left side contains number of leaves that is at least as the number of leaves in the right.
    In order to find the place of the middle leaf, we divide the closest power of two into half.
    :param list_len: length of list of leaves
    :return: closest power of 2
    """
    i = 0
    power2 = 2 ** i
    while power2 < list_len:
        i += 1
        power2 = 2 ** i
    return power2


class Leaves(object):
    def __init__(self):
        """
        This function initiate the list of leaves
        """
        self.leaves_list: list = []

    def add_leaf(self, new_leaf):
        """
        This function adds leaf to an existing array
        :param new_leaf:
        :return: none
        """
        self.leaves_list.append(calculate_hash(new_leaf.encode('utf-8')))

    def get_leaves(self) -> list:
        """
        This function return the leaves list
        :return: list
        """
        return self.leaves_list


class MerkleTree(object):

    def __init__(self):
        """
        This function initiate a Merkle Tree
        """
        self.right = None
        self.left = None
        self.value = None

    def construct_tree(self, leaves: list):
        """
        This function constructs a Merkle Tree.
        Each child is a Merkle Tree also
        :param leaves: list
        :return: none
        """
        if len(leaves) == 0:
            return
        # Base situation when we have 2 leaves.
        # The index of the left leaf is 0, and the index of the right one is 1.
        if len(leaves) == 2:  # ab
            self.left = leaves[0]
            self.right = leaves[1]
            self.value = concat(self.left, self.right)
            return
        # Situation when we have only 1 leaf
        # The index of the left leaf is 0, and there isn't a right leaf
        if len(leaves) == 1:  # ab  c , only child
            self.left = leaves[0]
            self.value = leaves[0]
            return
        # Situation when we have more than 2 leaves
        power_of_2 = closest_power_of_2(len(leaves))
        # Each child is a Merkle Tree
        self.left = MerkleTree()
        self.right = MerkleTree()
        # Call the recursive function to each Merkle Tree
        # The Merkle Tree is full to the lest
        self.left.construct_tree(leaves[:power_of_2 // 2])
        self.right.construct_tree(leaves[power_of_2 // 2:])
        # Calculating the hash of the current node
        self.value = concat(self.left.value, self.right.value)

    def display_root(self, leaves: list):
        """
        This function displays the root value of the Merkle Tree
        :param leaves: list
        :return: none
        """
        self.construct_tree(leaves)
        if self.value is None:
            print("")
            return
        print(self.value)

    def proof_of_inclusion(self, number: int, leaves: list):
        """
        This function creates a proof that a specific leaf is in a Merkle Tree
        Calls a recursive function
        :param number: index of leaf
        :param leaves: list
        :return:
        """
        self.construct_tree(leaves)
        len_leaves = len(leaves)
        # Prints the value of the root before the proof itself
        print(self.value, end=" ")
        self.proof_of_inclusion_rec(number, len_leaves)

    def proof_of_inclusion_rec(self, number: int, len_leaves: int):
        """
        This function finds in each level on the tree the value that is needed for the proof
        :param number: index of leaf
        :param len_leaves: length of the leaves
        :return: none
        """
        # If we want the right value we return the left and vise verse, stopping point
        if len_leaves == 2:
            if number == 1:
                print("0" + self.left, end=" ")
            else:
                if self.right:
                    print("1" + self.right, end=" ")
            return
        # If we have only one child, we don't do anything, stopping point
        if len_leaves == 1:
            return
        # If the number is in the right side of the tree
        if number >= closest_power_of_2(len_leaves) // 2:
            self.right.proof_of_inclusion_rec(number - closest_power_of_2(len_leaves) // 2,
                                              len_leaves - closest_power_of_2(len_leaves) // 2)
            print("0" + self.left.value, end=" ")
        # If the number is in the left side of the tree
        else:
            self.left.proof_of_inclusion_rec(number, closest_power_of_2(len_leaves) // 2)
            print("1" + self.right.value, end=" ")

    # 4
    def check_proof_of_inclusion(self, str_to_find, inclusion_proof_3):
        """
        This function checks if the proof of inclusion is correct with a specific leaf
        :param str_to_find: The string of the leaf
        :param inclusion_proof_3: String containing the proof of inclusion
        :return: none
        """
        # Split the string of the inclusion proof to an array
        inclusion_proof_3_list = inclusion_proof_3.split(" ")
        # If the value of the root doesn't match the string in the array - the proof is wrong
        if self.value != inclusion_proof_3_list[0]:
            print("False")
            return

        # Pass every string in the proof and verify if there is a node with the same value
        curr_node = self
        # for i in range(len(inclusion_proof_3_list) - 1, 0, -1):
        for i in range(len(inclusion_proof_3_list) - 1, 0, -1):
            # By the first character the direction of the child determined
            direction = (inclusion_proof_3_list[i])[0]
            curr_compare = (inclusion_proof_3_list[i])[1:]
            # The father of the wanted value
            if i == 1:
                # Compare the right son
                if direction == "0" and curr_node.left == curr_compare:
                    curr_node = curr_node.right
                # Compare the lest son
                elif direction == "1" and curr_node.right == curr_compare:
                    curr_node = curr_node.left
                # If none of them aligning - the proof is wrong
                else:
                    print("False")
                    return
            # Pass over all the nodes until the father of the leaves
            else:
                # Compare the right son
                if direction == "0" and curr_node.left.value == curr_compare:
                    curr_node = curr_node.right
                # Compare the left son
                elif direction == "1" and curr_node.right.value == curr_compare:
                    curr_node = curr_node.left
                # If none of them aligning - the proof is wrong
                else:
                    print("False")
                    return

        # Check if the current node (which is a leaf) has the str_to_find as a value
        # The last node is a string and isn't a MerkleTree object
        # The string is stored in the leaf after it has been hashed
        hash_to_find = calculate_hash(str_to_find.encode('utf-8'))
        if curr_node != hash_to_find:
            print("False")
            return
        else:
            print("True")
            return

    # 5
    @staticmethod
    def generate_keys():
        """
        This function generate a public and a private keys using RSA algorithm
        :return: none
        """
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Create a textual private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        # Generate public key from the private key
        public_key = private_key.public_key()

        # Create a textual private key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        print(private_pem.decode('utf-8'))
        print(public_pem.decode('utf-8'))

    # 6
    def sign_root(self, private_key_string):
        """
        This function signs with a RSA private key on the root node of a Merkle Tree
        :param private_key_string: The string of the private key
        :return: none
        """
        # The value of the root node
        root = self.value.encode('utf-8')
        # Convert the string of the private key to an actual private key
        private_key = serialization.load_pem_private_key(private_key_string.encode('utf-8'), password=None)
        # Sign the root with the private key
        signature = private_key.sign(root,
                                     padding.PSS(
                                         mgf=padding.MGF1(hashes.SHA256()),
                                         salt_length=padding.PSS.MAX_LENGTH
                                     ),
                                     hashes.SHA256())

        # Encode signature with base 64 encoder and bytes encoder
        signature = base64.urlsafe_b64encode(signature).decode('utf-8')

        print(signature)

    # 7
    @staticmethod
    def verify_signature(public_key_string, signature, text):
        """
        This function verifies the signature of a given text and a public key
        :param public_key_string: string of a public key
        :param signature: the signature that need to be verified
        :param text: the text which was signed by a private key
        :return: nothing
        """
        # Convert the string of the public key to an actual public key
        public_key = serialization.load_pem_public_key(public_key_string.encode('utf-8'), backend=None)
        # Decode signature with base 64 encoder and bytes encoder
        signature = bytes(base64.b64decode(signature))
        # Try to verify the signature
        try:
            public_key.verify(signature,
                              text.encode('utf-8'),
                              padding.PSS(
                                  mgf=padding.MGF1(hashes.SHA256()),
                                  salt_length=padding.PSS.MAX_LENGTH
                              ),
                              hashes.SHA256()
                              )
            print("True")
        # The verification failed
        except InvalidSignature as e:
            print("False")


# Input validations
def handle_ex1(command_param_list: str, leaves: Leaves):
    """
    handles ex1 - add leaf to the tree
    :param command_param_list: list of leaves
    :param leaves: added leaf
    :return: none
    """
    leaves.add_leaf(command_param_list)


def handle_ex2(merkle_tree: MerkleTree, leaves: Leaves):
    """
    handles ex2 - displaying root hash value
    :param merkle_tree: Merkle Tree
    :param leaves: leaves
    """
    merkle_tree.display_root(leaves.get_leaves())


def handle_ex3(merkle_tree: MerkleTree, number: str, leaves: Leaves):
    """
    handles ex3 - return proof of inclusion to a leaf
    :param merkle_tree: Merkle Tree
    :param number: index of the wanted leaf
    :param leaves: leaves
    :return: none
    """
    if number.isnumeric() and int(number) < len(leaves.get_leaves()):
        merkle_tree.proof_of_inclusion(int(number), leaves.get_leaves())
    print("")


def handle_ex4(merkle_tree: MerkleTree, str_to_find: str, proof: str):
    """
    handles ex4 - check proof of inclusion
    :param merkle_tree: Merkle Tree
    :param str_to_find: value of the wanted leaf
    :param proof: string of the proof
    :return: none
    """
    merkle_tree.check_proof_of_inclusion(str_to_find, proof)


def handle_ex5(merkle_tree: MerkleTree):
    """
    handles ex5 - generate public and private keys using RSA algorithm
    :param merkle_tree: Merkle Tree
    :return: none
    """
    merkle_tree.generate_keys()


def handle_ex6(merkle_tree: MerkleTree, private_key: str):
    """
    handles ex6 - sign the root
    :param merkle_tree: Merkle Tree
    :param private_key: string
    :return: none
    """
    if "-----BEGIN RSA PRIVATE KEY-----" not in private_key or "-----END RSA PRIVATE KEY-----" not in private_key:
        print("")
        return
    else:
        merkle_tree.sign_root(private_key)


def handle_ex7(merkle_tree: MerkleTree, public_key_string: str, signature: str, text: str):
    """
    handles ex7 - signing validation
    :param merkle_tree: Merkle TRee
    :param public_key_string: string
    :param signature: string
    :param text: value of the wanted leaf
    :return: none
    """
    if "-----BEGIN PUBLIC KEY-----" not in public_key_string or "-----END PUBLIC KEY-----" not in public_key_string:
        print("")
        return
    else:
        merkle_tree.verify_signature(public_key_string, signature, text)


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
                if command_param_list is None:
                    print(" ")
                else:
                    proof = ""
                    for i in range(2, len(command_param_list)):
                        proof += command_param_list[i]
                        if i != len(command_param_list) - 1:
                            proof += " "

                    handle_ex4(merkle_tree, command_param_list[1], proof)

            elif command_type == "5":
                if len(command_param_list) == 1:
                    handle_ex5(merkle_tree)
                else:
                    print("")
            elif command_type == "6":
                private_key = command[2:] + '\n'
                line = command
                while line != "-----END RSA PRIVATE KEY-----":
                    line = input()
                    private_key += line+'\n'
                handle_ex6(merkle_tree, private_key)
            elif command_type == "7":
                public_key = command[2:] + '\n'
                line = command
                while line != "-----END PUBLIC KEY-----":
                    line = input()
                    public_key += line + '\n'

                enter = input()
                command2 = input()
                command2_param_list = command2.split(" ")
                signature = command2_param_list[0]
                text = command2_param_list[1]
                handle_ex7(merkle_tree, public_key, signature, text)

        except Exception as ex:
            print(ex)

        command = input()  # "command_type first_param"
        command_param_list = command.split(" ")
        # there are no params for the command
        command_type = command_param_list[0]


def main():
    l = Leaves()
    root = MerkleTree()
    input_handler(root, l)


if __name__ == '__main__':
    main()
