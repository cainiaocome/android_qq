# -*- coding: utf-8 -*-
import time, re, gc, traceback, random, json, base64
from pprint import pprint
import hashlib

import logging
import requests
import sys
reload(sys)
sys.setdefaultencoding('utf-8')
import os.path
sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), os.path.pardir)))

import struct

def string_to_hex_string(s):
    return " ".join("{:02x}".format(ord(c)) for c in s)

def bytearray_to_hex_string( b ):
    return " ".join("{:02x}".format( c ) for c in b)

def gen_random_bytearray( length ):
    result = bytearray()
    for x in range(length):
        result.extend( struct.pack('B', random.randint(0,255)))
    return result

def qq_timestamp():
    t = int(time.time())
    t = struct.pack('L', t)
    t = bytearray(t)
    t.reverse()
    t = t[:4]
    return t

class Seq(object):
    def __init__(self, start=0, end=0x7fffff):
        self.value = start
        self.end = end
    def get_and_freeze(self):
        return self.value
    def get(self):
        if self.value > self.end:
            self.value = start
        else:
            self.value = self.value + 1
        return self.value

class qq_bytearray(bytearray):
    def append_u32len_plus_4_and_value( self, v ):
        l = bytearray( struct.pack('!I', len(v)+4) )
        return qq_bytearray( self + l + v )
    def append_u32len_and_value( self, v ):
        l = bytearray( struct.pack('!I', len(v)) )
        return qq_bytearray( self + l + v )
    def append_u16len_plus_4_and_value( self, v ):
        l = bytearray( struct.pack('!H', len(v)+4) )
        return qq_bytearray( self + l + v )
    def append_u16len_plus_2_and_value( self, v ):
        l = bytearray( struct.pack('!H', len(v)+2) )
        return qq_bytearray( self + l + v )
    def append_u16len_and_value( self, v ):
        l = bytearray( struct.pack('!H', len(v)) )
        return qq_bytearray( self + l + v )

    def append_random( self, l ):
        return qq_bytearray( self + gen_random_bytearray(l) )

    def append_zero( self, l ):
        return qq_bytearray( self + bytearray(l) )

    def append_u32(self, u32):
        tmp = bytearray( struct.pack('!I', u32) )
        return qq_bytearray(self + tmp)
    def insert_u32(self, u32):
        tmp = bytearray( struct.pack('!I', u32) )
        return qq_bytearray(tmp + self)

    def append_u16(self, u16):
        tmp = bytearray( struct.pack('!H', u16) )
        return qq_bytearray(self + tmp)
    def insert_u16(self, u16):
        tmp = bytearray( struct.pack('!H', u16) )
        return qq_bytearray(tmp + self)

    def append_u8(self, u8):
        tmp = bytearray( struct.pack('!B', u8) )
        return qq_bytearray(self + tmp)
    def insert_u8(self, u8):
        tmp = bytearray( struct.pack('!B', u8) )
        return qq_bytearray(tmp + self)

    def append_str(self, s):  # s: str or bytearray
        return qq_bytearray(self + bytearray(s))

    def insert_hex(self, s):  # s: hex representation
        return qq_bytearray(bytearray.fromhex(s) + self)
    def append_hex(self, s):  # s: hex representation
        return qq_bytearray(self + bytearray.fromhex(s))

    def __str__(self):
        return bytearray_to_hex_string(self)
