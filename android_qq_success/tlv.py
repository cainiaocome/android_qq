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

from binascii import unhexlify
import struct
import tea

from utils import *

class TLV(object):      # TYPE LENGTH VALUE
    def __init__(self):
        pass

    def logpacket(self, tlvname, p):
        logging.info( tlvname + '  ' + 'len:' + str(len(p)) + '  ' + 'vaule:' + str(p) + '\n' + '-'*45 + '\n' )
        
    def tlv_pack(self, cmd, b):
        p = qq_bytearray()
        p = p.append_hex( cmd )
        p = p.append_u16( len(b) )
        p = p.append_str( b )
        return p

    def tlv_18( self, uin ):  # uin: bytearray represent username( 4 bytes most )
        #00 18 //tlv18
        #00 16 //tlv长度22 如果太长不是tlv包
        #00 01 //_ping_version=1
        #00 00 06 00 //_sso_version=1536
        #00 00 00 10 //_appid
        #00 00 00 00 //_app_client_version
        #18 B4 A1 BC [QQ号码：414491068]
        #00 00 //0
        #00 00 //0
        p = qq_bytearray()
        p = p.append_hex( '00 01' )
        p = p.append_hex( '00 00 06 00' )
        p = p.append_hex( '00 00 00 10' )
        p = p.append_hex('00 00 00 00')
        p = p.append_str( uin )
        p = p.append_hex( '00 00' )
        p = p.append_hex( '00 00' )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack(cmd='00 18', b=p)

    def tlv_1( self, uin, t ):
        # 00 01 //tlv1
        # 00 14 //长度20
        # 00 01 //ip_ver=1
        # 3F AA 67 F9 //get_rand_32()
        # 18 B4 A1 BC [QQ号码：414491068]
        # 54 09 99 7F //get_server_cur_time
        # 00 00 00 00//_ip_addr
        # 00 00 //0
        # time ＝Xbin.Flip ( 取字节集左边 (到字节集 (Other.TimeStamp ()), 4))
        p = qq_bytearray()
        p = p.append_hex( '00 01' )
        p = p.append_str( gen_random_bytearray(4) )
        p = p.append_str( uin )
        p = p.append_str( qq_timestamp() )
        p = p.append_hex( '00 00 00 00' )
        p = p.append_hex( '00 00' )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack( cmd='00 01', b=p )

    def tlv_106( self, uin, passmd5, passmd5_2, tgtkey, imei, timestamp, appid ):   # uin:bytearray represent username
                                                                         # passmd5: bytearray
                                                                         # passmd5_2: bytearray
                                                                         # tgtkey: bytearray
                                                                         # imei: string
                                                                         # appid: 4 bytes unsigned int
        # 01 06
        # 00 70 [md5(md5(pass)+0 0 0 0+hexQQ)E8 FD 5B 08 BF 42 3C B9 F8 D4 23 30 F2 E2 E3 59 ]
        # 67 A4 4D 1D 59 08 97 15 92 03 BB E3 E8 7F 49 CC 65 A2 F6 E3 4F 68 DA 9E A2 E9 DA 90 DB 26 2D F5 A4 BD C0 52 51 F0 40 77 B5 50 25 42 AC 68 1B 57 35 61 97 65 36 6B AA 35 C5 E1 E6 C8 91 3B 3E 30 84 AA 6F 6C 32 29 97 FB DF 53 CA 3C B5 F8 F3 13 E4 FF AA 58 39 75 81 45 38 4A A2 BE CA 43 E0 7E 0A 83 71 17 5C 88 7C DE DE ED B8 12 E4 D5 C4 22
        # [
        # 00 03 //TGTGTVer=3
        # 29 A5 69 34 rand32
        # 00 00 00 05
        # 00 00 00 10
        # 00 00 00 00
        # 00 00 00 00
        # 18 B4 A1 BC [QQ:414491068]
        # 4D 1F C3 AC //时间
        # 00 00 00 00
        # 01
        # EB E0 80 63 34 8C 9E E1 FD 6B 5E 05 9A 72 84 C6 //MD5PASS
        # C5 2E 0F 5D A6 20 B5 EE 0B 94 F2 6F C3 05 4A 02 //TGTKey
        # 00 00 00
        # 00 01
        # 46 60 1E D3 C6 24 16 BF CA A2 9E 9E B8 9A D2 4E //imei_
        # 20 02 93 92 _sub_appid
        # 00 00 00 01 00 00
        # ]
        # time ＝Xbin.Flip 取字节集左边 (到字节集 (Other.TimeStamp ()), 4))
        p = qq_bytearray()
        p = p.append_hex( '00 03' )
        p = p.append_random( 4 )
        p = p.append_hex( '00 00 00 05' )
        p = p.append_hex( '00 00 00 10' )
        p = p.append_zero( 4 )
        p = p.append_zero( 4 )
        p = p.append_str( uin )
        p = p.append_str( timestamp )
        p = p.append_hex( '00 00 00 00 01' )
        p = p.append_str( passmd5 )
        p = p.append_str( tgtkey )
        p = p.append_hex( '00 00 00 00 01' )
        p = p.append_str( imei )
        p = p.append_u32( appid )
        p = p.append_hex( '00 00 00 01' )
        p = p.append_zero( 2 )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 06', tea.encrypt(p, passmd5_2))

    def tlv_116(self):
        # 01 16
        # 00 0A
        # 00
        # 00 00 7F 7C /mMiscBitmap
        # 00 01 04 00 mSubSigMap
        # 00 _sub_appid_list.length
        p = qq_bytearray()
        p = p.append_zero(1)
        p = p.append_hex( '00 00 7f 7c' )
        p = p.append_hex( '00 01 04 00' )
        p = p.append_zero(1)
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 16', p)

    def tlv_100(self, appid): # appid: uint32
        # 01 00 //tlv-100
        # 00 16
        # 00 01 //_db_buf_ver=1
        # 00 00 00 05 //_sso_ver=5
        # 00 00 00 10 //appid
        # 20 02 92 13 //_sub_appid
        # 00 00 00 00 //_app_client_version
        # 00 0E 10 E0 //_main_sigmap
        p = qq_bytearray()
        p = p.append_hex( '00 01' )
        p = p.append_hex( '00 00 00 05' )
        p = p.append_hex( '00 00 00 10' )
        p = p.append_u32( appid )
        p = p.append_zero(4)
        p = p.append_hex( '00 0e 10 e0' )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 00', p)

    def tlv_107(self):
        # 01 07 //tlv-107
        # 00 06
        # 00 00 //_pic_type
        # 00 //0
        # 00 00 //0
        # 01 //1
        p = qq_bytearray()
        p = p.append_zero(2)
        p = p.append_zero(1)
        p = p.append_zero(2)
        p = p.append_hex( '01' )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 07', p)

    def tlv_108(self, ksid): # ksid: bytearray
        # 01 08 // tlv108
        # 00 10 // len
        # 93 33 4E AD B8 08 D3 42 82 55 B7 EF 28 E7 E8 F5 //request_global._ksid
        p = qq_bytearray()
        p = p.append_str( ksid )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 08', p)

    def tlv_109(self, imei): #  imei: string
        # 01 09 //tlv-109
        # 00 10
        # 46 60 1E D3 C6 24 16 BF CA A2 9E 9E B8 9A D2 4E //_IMEI
        p = qq_bytearray()
        p = p.append_str( imei )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 09', p)

    def tlv_124(self, os_type, os_version, network_type, apn):  # os_type: str
                                                                # os_version: str
                                                                # network_type: short
                                                                # apn: str
        # 01 24 //tlv-124
        # 00 1C // len
        # 00 07 //os_type
        # 61 6E 64 72 6F 69 64
        # 00 05 //os_version
        # 34 2E 30 2E 34
        # 00 01 //_network_type
        # 00 00 //._sim_operator_name
        # 00 00 //0
        # 00 04 //_apn
        # 77 69 66 69
        p = qq_bytearray()
        p = p.append_u16( len(os_type) )
        p = p.append_str( os_type )
        p = p.append_u16( len(os_version) )
        p = p.append_str( os_version )
        p = p.append_u16( network_type )
        p = p.append_zero( 4 )
        p = p.append_str( apn )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 24', p)

    def tlv_128(self, device, imei):     # device: string
                                        # imei: string
        # 01 28 //tlv-128
        # 00 2B // len
        # 00 00 //0
        # 00 //request_global._new_install
        # 01 //request_global._read_guid
        # 00 //request_global._guid_chg
        # 01 00 00 00 //request_global._dev_report
        # 00 0C // device len
        # 48 55 41 57 45 49 20 55 39 35 30 38 //request_global._device=HUAWEI U9508
        # 00 10 // imei len
        # 46 60 1E D3 C6 24 16 BF CA A2 9E 9E B8 9A D2 4E //request_global._IMEI
        # 00 00 //0
        p = qq_bytearray()
        p = p.append_hex( 
                            '''00 00\
                             00\
                             01\
                             00\
                             01 00 00 00'''
                        )
        p = p.append_u16( len(device) )
        p = p.append_str( device )
        p = p.append_u16( len(imei) )
        p = p.append_str( imei )
        p = p.append_zero( 2 )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 28', p)

    def tlv_16e(self, device): # device:string
        # 01 6E //tlv-16e
        # 00 0C // len
        # 48 55 41 57 45 49 20 55 39 35 30 38 //request_global._device=HUAWEI U9508
        p = qq_bytearray()
        p = p.append_str ( device )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 6e', p)

    def tlv_144(self, tgtkey, tlv109, tlv124, tlv128, tlv16e): # all args are bytearray
        # 01 44
        # 00 80 (////_tgtgt_key)
        # 60 17 BF D3 F7 A4 7E C5 BC 07 47 98 B3 9B 12 C1
        # CC F6 87 13 7A 28 BB 62 18 3B 1A 43 F8 FE 07 87
        # CB CF 40 3D BD DB 93 0F A7 CC F4 71 67 67 70 9E
        # 33 14 CD E6 D7 CA 62 B4 48 FB 32 21 47 8F 40 B5
        # A0 8E CB 5E 31 70 26 44 EA 79 AD A7 76 00 2A 26
        # 56 92 38 EA 78 BB CC 4E E8 E3 F4 CD FE 19 AB 32
        # A6 BB 31 72 D7 25 93 94 4A EF A7 94 A9 59 B2 73
        # 55 95 4C FC AD C4 1A C2 15 C6 8F A1 39 48 F8 1A
        # [
        # 00 04 //get_tlv_144四个参数byte[]都有数据
        # 01 09 //tlv-109
        # 00 10
        # 46 60 1E D3 C6 24 16 BF CA A2 9E 9E B8 9A D2 4E //_IMEI
        # 01 24 //tlv-124
        # 00 1C
        # 00 07 61 6E 64 72 6F 69 64 00 05 34 2E 30 2E 34
        # 00 01 00 00 00 00 00 04 77 69 66 69
        # 01 28 //tlv-128
        # 00 2B
        # 00 00 //0
        # 00 //request_global._new_install
        # 01 //request_global._read_guid
        # 00 //request_global._guid_chg
        # 01 00 00 00 //request_global._dev_report
        # 00 0C
        # 48 55 41 57 45 49 20 55 39 35 30 38 //request_global._device=HUAWEI U9508
        # 00 10
        # 46 60 1E D3 C6 24 16 BF CA A2 9E 9E B8 9A D2 4E //request_global._IMEI
        # 00 00 //0
        # 01 6E //tlv-16e
        # 00 0C
        # 48 55 41 57 45 49 20 55 39 35 30 38 //request_global._device=HUAWEI U9508
        # ]
        p = qq_bytearray()
        p = p.append_u16( 4 )
        p = qq_bytearray( p + tlv109 + tlv124 + tlv128 + tlv16e )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack( '01 44', tea.encrypt(p, tgtkey) )
    def tlv_142(self, apk_id):   # apk_id: string
        # 01 42 //tlv142
        # 00 16 //len
        # 00 00 00 12 //len
        # 63 6F 6D 2E 74 65 6E 63 65 6E 74 2E 71 71 6C 69
        # 74 65 //request_global._apk_id=com.tencent.qqlite
        p = qq_bytearray()
        p = p.append_u32( len(apk_id) )
        p = p.append_str( apk_id )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 42', p)

    def tlv_145(self, imei): # imei:string
        # 01 45 //tlv-145
        # 00 10
        # 46 60 1E D3 C6 24 16 BF CA A2 9E 9E B8 9A D2 4E //request_global._IMEI
        p = qq_bytearray()
        p= p.append_str( imei )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 45', p)

    def tlv_154(self, sso_seq):  # sso_seq: int
        # 01 54 //tlv-154
        # 00 04
        # 00 01 19 6A //this._g._sso_seq
        p = qq_bytearray()
        p = p.append_u32( sso_seq )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 54', p)
    
    def tlv_141(self, network_type, apn):  # network_type: short
                                           # apn: string
        # 01 41 //tlv-141
        # 00 0C
        # 00 01 // this._version=1
        # 00 00 //request_global._sim_operator_name
        # 00 01 //request_global._network_type
        # 00 04 //len
        # 77 69 66 69 // request_global._apn
        p = qq_bytearray()
        p = p.append_hex( '00 01 00 00' )
        p = p.append_u16( network_type )
        p = p.append_u16( len(apn) )
        p = p.append_str( apn )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 41', p)

    def tlv_8(self):
        # 00 08 //tlv-8
        # 00 08 // len
        # 00 00 //0
        # 00 00 08 04 //request_global._local_id
        # 00 00 //0
        p = qq_bytearray()
        p = p.append_hex( '00 00' )
        p = p.append_hex( '00 00 08 04' )
        p = p.append_hex( '00 00' )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('00 08', p)

    def tlv_16b(self):
        # 01 6B  // type
        # 00 0F  // len
        # 00 01
        # 00 0B
        # 67 61 6D 65 2E 71 71 2E 63 6F 6D [game.qq.com]
        p = qq_bytearray()
        p = p.append_hex( '00 01' )
        p = p.append_hex( '00 0b' )
        p = p.append_str( 'game.qq.com' )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 6b', p)

    def tlv_147(self, apk_version, apk_sign): # apk_version:string apk_sign:bytearray
        # 01 47//tlv-147
        # 00 1D // len
        # 00 00 00 10 //appid
        # 00 05
        # 33 2E 30 2E 30 // request_global._apk_v
        # 00 10
        # A6 B7 45 BF 24 A2 C2 77 52 77 16 F6 F3 6E B6 8D //request_global._apk_sig
        p = qq_bytearray()
        p = p.append_hex( '00 00 00 10' )
        p = p.append_u16len_and_value( apk_version )
        p = p.append_u16len_and_value( apk_sign )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 47', p)

    def tlv_177(self):
        # 01 77 // type
        # 00 0E // len
        # 01
        # 53 FB 17 9B
        # 00 07
        # 35 2E 32 2E 33 2E 30 [5.2.3.0]
        p = qq_bytearray()
        p = p.append_hex( '01' )
        p = p.append_hex( '53 fb 17 9b' )
        p = p.append_hex( '00 07' )
        p = p.append_str( '5.2.3.0' )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 77', p)

    def tlv_187(self):
        # 01 87 // type
        # 00 10 // len
        # F8 FF 12 23 6E 0D AF 24 97 CE 7E D6 A0 7B DD 68
        p = qq_bytearray()
        p = p.append_hex( 'F8 FF 12 23 6E 0D AF 24 97 CE 7E D6 A0 7B DD 68' )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 87', p)
    
    def tlv_188(self):
        # 01 88
        # 00 10
        # 4D BF 65 33 D9 08 C2 73 63 6D E5 CD AE 83 C0 43
        p = qq_bytearray()
        p = p.append_hex( '4D BF 65 33 D9 08 C2 73 63 6D E5 CD AE 83 C0 43' )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 88', p)

    def tlv_191(self):
        # 01 91
        # 00 01
        # 00
        p = qq_bytearray()
        p = p.append_zero( 1 )
        self.logpacket( str(sys._getframe().f_code.co_name), p )
        return self.tlv_pack('01 91', p)
