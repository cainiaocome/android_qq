#!/usr/bin/env python
#################################################################################
# Python implementation of the Tiny Encryption Algorithm (TEA)
# By Moloch
#
# About: TEA has a few weaknesses. Most notably, it suffers from 
#        equivalent keys each key is equivalent to three others, 
#        which means that the effective key size is only 126 bits. 
#        As a result, TEA is especially bad as a cryptographic hash 
#        function. This weakness led to a method for hacking Microsoft's
#        Xbox game console (where I first encountered it), where the 
#        cipher was used as a hash function. TEA is also susceptible 
#        to a related-key attack which requires 2^23 chosen plaintexts 
#        under a related-key pair, with 2^32 time complexity.
# 
#        Block size: 64bits
#          Key size: 128bits
#
##################################################################################


import os
import random
import getpass
import platform

from random import choice
from hashlib import sha256
from ctypes import c_uint32
from pprint import pprint
import struct
from string import ascii_letters, digits

if platform.system().lower() in ['linux', 'darwin']:
    INFO = "\033[1m\033[36m[*]\033[0m "
    WARN = "\033[1m\033[31m[!]\033[0m "
else:
    INFO = "[*] "
    WARN = "[!] "

### Magical Constants
DELTA = 0x9e3779b9
#SUMATION = 0xc6ef3720
SUMATION = (DELTA<<4) & 0xffffffff
ROUNDS = 16
BLOCK_SIZE = 2  # number of 32-bit ints
KEY_SIZE = 4 

def bytearray_to_hex_string( b ):
    return ur"".join("{:02x}".format( c ) for c in b)

def gen_random_bytearray( length ):
    result = bytearray()
    for x in range(length):
        result.extend( struct.pack('B', random.randint(0,255)))
    return result

def encrypt_block(v, k, verbose=False):
    y=v[0];
    z=v[1];
    sum=c_uint32(0);
    delta=0x9E3779B9;
    n=32
    w=[0,0]

    while(n>0):
        sum.value += delta
        y.value += ( z.value << 4 ) + k[0].value ^ z.value + sum.value ^ ( z.value >> 5 ) + k[1].value
        z.value += ( y.value << 4 ) + k[2].value ^ y.value + sum.value ^ ( y.value >> 5 ) + k[3].value
        n -= 1

    return (y,z)

def decrypt_block(v, k, verbose=False):
    y=v[0]
    z=v[1]
    sum=c_uint32(0xC6EF3720)
    delta=0x9E3779B9
    n=32
    w=[0,0]

    while(n>0):
        z.value -= ( y.value << 4 ) + k[2].value ^ y.value + sum.value ^ ( y.value >> 5 ) + k[3].value
        y.value -= ( z.value << 4 ) + k[0].value ^ z.value + sum.value ^ ( z.value >> 5 ) + k[1].value
        sum.value -= delta
        n -= 1

    return (y,z)
    
def to_c_array(data): # data: bytearray
    ''' Converts a bytearray to a list of c_uint32s '''
    c_array = struct.unpack_from('I'*(len(data)/4), data, 0)
    c_array = [c_uint32(x) for x in c_array]
    return c_array

def to_bytearray(c_array):
    ''' Converts a list of c_uint32s to a Python bytearray '''
    result = bytearray()
    for x in c_array:
        result = result + bytearray(x)
    return result

def add_padding(data, verbose=False): # data: bytearray
    result = bytearray()
    fill_n_or = 0xf8
    pad_len = (8-(len(data)+2)) %8 + 2
    pad = gen_random_bytearray( pad_len )
    result = bytearray(struct.pack('B', (fill_n_or | (pad_len-2)))) + pad + data + bytearray(7)
    return result

def remove_padding(data, verbose=False):
    pad_len = struct.unpack_from('B', data, 0)[0]
    pad_len = (pad_len & 0x7) + 2
    data = data[pad_len+1:-7]
    return data

def encrypt(data, key, verbose=False):
    '''
    Encrypt bytearray using TEA algorithm with a given key
    '''
    data = add_padding( data )
    data = to_c_array(data)
    key = to_c_array(key)
    cipher_text = []
    for index in range(0, len(data), 2):
        block = data[index:index + 2]
        block = encrypt_block(block, key, verbose)
        for uint in block:
            cipher_text.append(uint)
    return to_bytearray(cipher_text)

def decrypt(data, key, verbose=False):
    data = to_c_array(data)
    key = to_c_array(key)
    plain_text = []
    for index in range(0, len(data), 2):
        block = data[index:index + 2]
        decrypted_block = decrypt_block(block, key, verbose)
        for uint in decrypted_block:
            plain_text.append(uint)
    data = to_bytearray(plain_text)
    data = remove_padding( data )
    return data

### UI Code ###
if __name__ == '__main__':
    key = bytearray().fromhex('FB 02 13 51 41 4D 18 83 0B 28 1A 59 F2 3C 87 A9')
    print 'key:', bytearray_to_hex_string( key )
    print '-'*45

    v = bytearray( 'abcd' )
    print 'v:', bytearray_to_hex_string( v )
    print '-'*45

    endata = encrypt(v, key)
    print 'endata:', bytearray_to_hex_string(endata)
    print '-'*45

    dedata = decrypt(endata, key)
    print 'dedata:', bytearray_to_hex_string(dedata)
    print '-'*45
