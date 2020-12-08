import argparse
import hashlib
import os
import json
from Crypto.Cipher import AES

#######################################################################################################################
#AES Functions
#######################################################################################################################
def pad(data):
    """
    Pad the provided data to be a multiple of the AES block size, then return the padded data

    @param data
    @return padded: The padded data
    """
    padded = data + (AES.block_size - len(data) % AES.block_size) * chr(AES.block_size - len(data) % AES.block_size)
    return padded


def unpad(data):
    """
    Remove the padding from the provided data, then return the unpadded data

    @param data
    @return unpadded: The unpadded data
    """
    unpadded = data[:-ord(data[len(data)-1:])]
    return unpadded


def aes_cbc_encrypt(keyFile, plaintextFile, ivFile, ciphertextFile, output=True):
    """
    Use AES to encrypt plaintext using a key

    @param keyFile: The file from which to read the encryption key
    @param plaintextFile: The file from wich to read the plaintext
    @param ivFile: The file to write the generated iv to
    @param ciphertextFile: The file to write the resulting ciphertext to
    """
    # Read key and plaintext files
    with open(keyFile, "r") as f:
        key = f.read()
    key = bytes.fromhex(key)

    with open(plaintextFile, "r") as f:
        plaintextString = f.read()
    
    plaintextPadded = pad(plaintextString)

    with open(ivFile, "r") as f:
        iv = bytes.fromhex(f.read())

    cipher = AES.new(key, AES.MODE_CBC, iv)

    result = cipher.encrypt(plaintextPadded).hex()

    with open(ciphertextFile, "w") as f:
        f.write(result)

    if output:
        print("Ciphertext: " + str(result))


def aes_ecb_encrypt(keyFile, input):
    """
    Use AES ECB to encrypt plaintext using a key

    @param keyFile: The file from which to read the encryption key
    @param input: The input string to encrypt

    @return encrypted input
    """
    # Read key file
    with open(keyFile, "r") as f:
        key = f.read()
        
    key = bytes.fromhex(key)
    
    plaintextPadded = pad(input)
    cipher = AES.new(key, AES.MODE_ECB)
    result = cipher.encrypt(plaintextPadded).hex()

    return result


def aes_decrypt(keyFile, ivFile, ciphertextFile):
    """
    Use AES to decrypt ciphertext using a key and iv

    @param keyFile: The file from which to read the encryption key
    @param ivFIle: The file containing the initialization vector
    @param ciphertextFile: The file from wich to read the ciphertext
    """
    with open(keyFile, "r") as f:
        key = bytes.fromhex(f.read())

    with open(ciphertextFile, "r") as f:
        ciphertext = bytes.fromhex(f.read())

    with open(ivFile, "r") as f:
        iv = bytes.fromhex(f.read())
    
    cipher = AES.new(key, AES.MODE_CBC, iv)

    result = unpad(cipher.decrypt(ciphertext)).decode()

    return str(result)


#######################################################################################################################
#Searchable Encryption functions
#######################################################################################################################


def keygen(prf_file, aes_file):
    """
    Generate a random 2 256-bit keys, then write to a file

    @param prf_file: The output file where the prf key is written
    @param aes_file: The output file where the aes key is written
    """
    prf_key = os.urandom(32)  
    prf_hexKey = prf_key.hex()
    with open(prf_file, "w") as f:
        f.write(prf_hexKey)

    aes_key = os.urandom(32)  
    aes_hexKey = aes_key.hex()
    with open(aes_file, "w") as f:
        f.write(aes_hexKey)

    print("PRF key generated: " + prf_hexKey)
    print("AES key generated: " + aes_hexKey)


def encrypt(skprf_file, skaes_file, index_file, files_dir, cipherfiles_dir):
    """
    Read in all the plaintext files in files_dir, then encrypt them and create a searchable 
    encryption index based on tokens found in the files

    @param skprf_file: File which ontains the secret key for the PRF (really AES-ECB-256 to simulate it)
    @param skaes_file: File which container the secret key for the CBC AES encryption
    @param index_file: The file the generated index gets stored in
    @param files_dir: The directory the plaintext files {f1,f2...fn} are read from
    @param cipherfiles_dir: The directory the encrypted files are written to
    """
    iv_file = "data/iv.txt"
    raw_data = {}
    reverse_indexed = {}
    reverse_indexed_enc = {}

    # Create an AES CBC IV for encrypting all files
    iv = os.urandom(16)
    with open(iv_file, "w") as f:
        f.write(iv.hex())

    # Read file data into raw_data, then encrypt each one with CBC AES
    for file in os.listdir(files_dir):
        filename = os.path.join(files_dir, file)
        cipher_filename = os.path.join(cipherfiles_dir, file.replace("f", "c"))
        with open(filename, "r") as f:
            d = f.read()
            raw_data[file] = d.split()

        aes_cbc_encrypt(skaes_file, filename, iv_file, cipher_filename, output=False)
        
    
    # Create a reverse-indexed plaintext dict
    for file in raw_data:
        for entry in raw_data[file]:
            if entry not in reverse_indexed:
                reverse_indexed[entry] = [file]
            else:
                reverse_indexed[entry].append(file)
    
    # Enrypt entries in the reverse-indexed dict, then write to the index file
    for entry in reverse_indexed:
        reverse_indexed[entry].sort()

        entry_enc = aes_ecb_encrypt(skprf_file, entry)
        reverse_indexed_enc[entry_enc] = [x.replace("f","c") for x in  reverse_indexed[entry]]

    with open(index_file, "w") as f:
        json.dump(reverse_indexed_enc, f, indent=4)

    print("Encrypted index generated: ")
    print(json.dumps(reverse_indexed_enc, indent=4))
    

def tokengen(keyword, skprf_file, token_file):
    """
    Generate a token from the passed keyword

    @param keyword: The keyword to generate the token from
    @param skprf_file: The file containing the secret key
    @param token_file: The file the token is written to
    """
    entry_enc = aes_ecb_encrypt(skprf_file, keyword)

    with open(token_file, "w") as f:
        f.write(entry_enc)

    print("Generated Token " + entry_enc)


def search(index_file, token_file, cipherfiles_dir, skaes_file, result_file):
    """
    Search for a given token in the index

    @param index_file: The file to read the index from
    @param token_file: The file containing the token
    @param cipherfiles_dir: The directory containing the encrypted files
    @param skaes_file: The files containing the aes key
    @param result_file: The file the result is written to
    """
    reverse_index = {}
    token = ""
    matched_files = []
    iv_file = "data/iv.txt"

    with open(index_file, "r") as f:
        reverse_index = json.load(f)

    with open(token_file, "r") as f:
        token = f.read()

    if token not in reverse_index:
        print("Token not found.")
        with open(result_file, "w") as f:
            f.write("")
        return
    
    # Get matching files from the index
    matched_files = reverse_index[token]
    result = '  '.join(matched_files) + "\n\n"

    # Decrypt the contents of all matching files, and add it to the result string
    for file in matched_files:
        path = os.path.join(cipherfiles_dir, file)
        decrypted = aes_decrypt(skaes_file, iv_file, path)
        result += file + " " + decrypted

    print(result)
    with open(result_file, "w") as f:
        f.write(result)

#######################################################################################################################
#Main function
#######################################################################################################################

if __name__ == "__main__":
    # Set up argument parser
    parser = argparse.ArgumentParser("")

    subparsers = parser.add_subparsers(help="Types of operations", dest="command")

    keygen_parser = subparsers.add_parser("keygen")
    enc_parser = subparsers.add_parser("enc")
    token_parser = subparsers.add_parser("token")
    search_parser = subparsers.add_parser("search")

    keygen_parser.add_argument("skprf", help="PRF secret key file")
    keygen_parser.add_argument("skaes", help="AES secret key file")

    enc_parser.add_argument("skprf", help="PRF secret key file")
    enc_parser.add_argument("skaes", help="AES secret key file")
    enc_parser.add_argument("index", help="Index file")
    enc_parser.add_argument("files", help="The folder containing all the plaintext files")
    enc_parser.add_argument("cipherfiles", help="The folder containing all the ciphertext files")

    token_parser.add_argument("keyword", help="A keyword")
    token_parser.add_argument("skprf", help="PRF secret key file")
    token_parser.add_argument("token", help="The token file")

    search_parser.add_argument("index", help="Index file")
    search_parser.add_argument("token", help="The token file")
    search_parser.add_argument("cipherfiles", help="The folder containing all the ciphertext files")
    search_parser.add_argument("skaes", help="AES secret key file")
    search_parser.add_argument("result", help="Results file")

    args = parser.parse_args()

    # Run the chosen function based on passed arguments
    if (args.command == "keygen"):
        keygen(args.skprf, args.skaes)
    elif (args.command == "enc"):
        encrypt(args.skprf, args.skaes, args.index, args.files, args.cipherfiles)
    elif (args.command == "token"):
        tokengen(args.keyword, args.skprf, args.token)
    elif (args.command == "search"):
        search(args.index, args.token, args.cipherfiles, args.skaes, args.result)

