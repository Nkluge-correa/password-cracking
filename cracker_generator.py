import random
import math
import pandas as pd
from hashlib import sha1


with open('dictionary.txt', encoding='utf8') as file_in:
    dictionary = []
    for line in file_in:
        dictionary.append(line.strip())


def dictionary_attack(dictionary_word, target_hash):
    pass_bytes = dictionary_word.encode('utf-8')
    pass_hash = sha1(pass_bytes)
    digest = pass_hash.hexdigest()
    if digest == target_hash:
        return True


leak = pd.read_excel('users_passwords_dump.xlsx')


def cracking(leak):
    print('Cracking...')
    for word in dictionary:
        for i in range(0, len(leak)):
            if dictionary_attack(word, leak['passwords'][i]) == True:
                user = leak['users'][i]
                print(f'{user} password is: ', word)
                break
            else:
                continue


with open('words_466k.txt', encoding='utf8') as file_in:
    word_password_bag = []
    for line in file_in:
        word_password_bag.append(line.strip())


def generate_password():
    valid = False
    while not valid:
        try:
            x = int(input('Choose a number of words: '))
            valid = True
        except ValueError:
            print('Please only input integer digits...')
        if valid is True:
            password = []
            for i in range(int(x)):
                item = random.choice(word_password_bag)
                password.append(item)
            password_txt = ' '.join(password)
            password_len = ''.join(password)
            print(f'Your password is: {password_txt}')
            print(
                f'\nThese words were choosen out of {len(word_password_bag)} possible words.')
            print(
                f'\nThe space of possible passwors you created is equal to {len(word_password_bag)}^{x} = {len(word_password_bag) ** int(x)}.\n')
            # 16 bits for each word
            print(
                f'Maximum number of operations to Brute Force your passaword: ~ {int(2 ** (16 * int(x)))}.')
            print(f'''
            Password Entropy (E): E = L * log2(R)\n

            -    E = password entropy;
            -    L = Password length, i.e., the number of characters in the password;
            -    R = Size of the pool of unique characters from which we build the password.\n

            This password has an entropy of:\n
                
                {round(len(password_len) * math.log2(94), 2)} bits = {len(password_len)} * log2({94})\n 
            
            -    < 28 bits = Very Weak  
            -    28 - 35 bits = Weak 
            -    36 - 59 bits = Reasonable 
            -    60 - 127 bits = Strong
            -    128 + bits = Very Strong\n
                
            >   Password tip: put a symbol in the middle of your password (that guarantees the 94 character pool size).\n

            -   To guess this password, character-by-character, via brute-force, it would take upm to:\n
                
                2 ** ({round(len(password_len) * math.log2(94), 2)}) - 1 = {int(2 ** (round(len(password_len) * math.log2(94) - 1, 2)))} guesses.
            ''')
