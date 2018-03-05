# coding=UTF-8

import logging
import time
import struct

''' 2의 보수 계산 함수 (8비트)
'''
def complement8(num) :
    if 0x80 & num == 0 :
        return num
    else :
        return -(0xff ^ (num - 1))


''' 2의 보수 계산 함수 (16비트)
'''
def complement16(num) :
    if 0x8000 & num == 0 :
        return num
    else :
        return -(0xffff ^ (num - 1))


''' 2의 보수 계산 함수 (32비트)
'''
def complement32(num) :
    if 0x80000000 & num == 0 :
        return num
    else :
        return -(0xffffffff ^ (num - 1))


''' 로거 설정 함수
'''
def init_logger(logger_name, lv=logging.DEBUG) :
    FORMAT  = '\r%(levelname)8s   %(asctime)s  %(lineno)4d  %(funcName)25s  %(filename)20s   '
    FORMAT += ' %(message)s %(extra_info)s'
    logging.basicConfig(format=FORMAT)
    logger = logging.getLogger(logger_name)
    logger.setLevel(lv)

    return logger
    
def log_debug(logger, msg, extra_msg = "") :
    extra = { "extra_info" : ("\n\n" + extra_msg + "\n" if extra_msg != "" else "") }
    logger.debug(msg, extra=extra)

def log_exception(logger, msg, extra_msg = "") :
    extra = { "extra_info" : ("\n\n" + extra_msg + "\n" if extra_msg != "" else "") }
    logger.exception(msg, extra=extra)


''' 시간 카운트 로깅 랩퍼 함수
'''
def timerWrapper(fn):
    def wrapper(*args, **kw):
        start_time = time.time()
        result = fn(*args, **kw)
        end_time = time.time()
        log_info(init_logger('Timer'),"\'%s\' function: %.2fs" % (fn.__name__,end_time-start_time))
        return result
    return wrapper


''' IDA Pro 용 유틸
'''
def find_data_region(start, end) :
    state = 1 # 1,2 단계 존재
    s_addr = None
    e_addr = None
    data_list = []

    for i in range(start,end, 2) :
        color = idaapi.calc_prefix_color(i)
        if color == 6 : 
            if state == 1 :
                state = 2
                s_addr = i
            elif state == 2 :
                pass
        elif color != 7 and color != 6 :
            if state == 1 :
                pass
            elif state == 2 :
                e_addr = i
                state = 1
                data_list.append( (s_addr,e_addr) )

    return data_list


''' RC4 알고리즘
'''
def KSA(key):
    keylength = len(key)

    S = []
    for i in range(256):
        S.append(i)

    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % keylength]) % 256
        
        t = S[i]
        S[i] = S[j]
        S[j] = t

    return S

def PRGA(S,sz):
    i = 0
    j = 0
    cnt = 0
    ks = []

    while True:
        i = (i + 1) % 256
        j = (j + S[i]) % 256

        t = S[i]
        S[i] = S[j]
        S[j] = t

        K = S[(S[i] + S[j]) % 256]
        ks.append(K)
        cnt += 1
        if cnt == sz:
            return ks

def RC4(key,sz):
    S = KSA(key)
    return PRGA(S,sz)


def enc_rc4(key,plaintext):
    def convert_key(s):
        return [ord(c) for c in s]

    keystream = RC4(key,len(plaintext))
        
    for i in range(len(plaintext)):
        c = plaintext[i]
        keystream[i] = c ^ keystream[i]
    
    return bytes(keystream)



