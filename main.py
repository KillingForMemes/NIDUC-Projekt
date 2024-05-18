#!/usr/bin/env python

import binascii
import hashlib
import os
import random
import unittest
import csv

import bchlib

class BCHTestCase(unittest.TestCase):
    def exercise(*args, **kwargs):
        # create a bch object
        bch = bchlib.BCH(*args, **kwargs)
        max_data_len = bch.n // 8 - (bch.ecc_bits + 7) // 8

        print('max_data_len: %d' % (max_data_len,))
        print('ecc_bits: %d (ecc_bytes: %d)' % (bch.ecc_bits, bch.ecc_bytes))
        print('m: %d' % (bch.m,))
        print('n: %d (%d bytes)' % (bch.n, bch.n // 8))
        print('prim_poly: 0x%x' % (bch.prim_poly,))
        print('t: %d' % (bch.t,))

        # random data
        data = bytearray(os.urandom(max_data_len))

        # encode and make a "packet"
        ecc = bch.encode(data)
        print('encoded ecc:', binascii.hexlify(ecc).decode('utf-8'))
        packet = data + ecc

        # print hash of packet
        sha1_initial = hashlib.sha1(packet)
        print('packet sha1: %s' % (sha1_initial.hexdigest(),))

        def bitflip(packet):
            byte_num = random.randint(0, len(packet) - 1)
            bit_num = random.randint(0, 7)
            packet[byte_num] ^= (1 << bit_num)

        # make BCH_BITS errors
        for _ in range(bch.t + delta):
            bitflip(packet)

        # print hash of packet
        sha1_corrupt = hashlib.sha1(packet)
        print('packet sha1: %s' % (sha1_corrupt.hexdigest(),))

        # de-packetize
        data, ecc = packet[:-bch.ecc_bytes], packet[-bch.ecc_bytes:]

        # decode
        bch.data_len = max_data_len
        nerr = bch.decode(data, ecc)

        print('nerr:', nerr)
        #print('syn:', bch.syn)
        #print('errloc:', bch.errloc)

        # correct
        bch.correct(data, ecc)

        # packetize
        packet = data + ecc

        # print hash of packet
        sha1_corrected = hashlib.sha1(packet)
        print('packet sha1: %s' % (sha1_corrected.hexdigest(),))

        if sha1_initial.digest() == sha1_corrected.digest():
            print('Corrected!')
        else:
            print('Failed')

        return sha1_initial.digest() == sha1_corrected.digest()


# BCH(511, 493)
def test_t_eq_511():
    # 511 = 2^m - 1 -> m = 9
    # t = ilosc bledow do poprawy (max 31)
    # t = (n-k)/m = 2
    max_t = 56
    result = []
    for i in range(1, max_t + 1):
        failed_tests = 0
        for j in range(test_count):
            try:
                if not BCHTestCase.exercise(t=i, m=9):
                    failed_tests += 1
            except Exception as e:
                print(f"Test {j+1} failed with exception: {e}")
        result.append([i, (test_count - failed_tests) / test_count])
    return result

# BCH(255, 223)
def test_t_eq_255():
    # 255 = 2^m - 1 -> m = 8
    # t = 4
    max_t = 31
    result = []

    for i in range(1, max_t + 1):
        failed_tests = 0
        for j in range(test_count):
            try:
                if not BCHTestCase.exercise(t=i, m=8):
                    failed_tests += 1
            except Exception as e:
                print(f"Test {j+1} failed with exception: {e}")
        result.append([i, (test_count - failed_tests) / test_count])
    return result

# BCH(31, 26)
def test_t_eq_15():
    # 255 = 2^m - 1 -> m = 8
    # t = 4
    max_t = 5
    result = []

    for i in range(1, max_t + 1):
        failed_tests = 0
        for j in range(test_count):
            try:
                if not BCHTestCase.exercise(t=i, m=5):
                    failed_tests += 1
            except Exception as e:
                print(f"Test {j+1} failed with exception: {e}")
        result.append([i, (test_count - failed_tests) / test_count])
    return result

delta = 0   # additional errors
test_count = 1000

def save_to_file(filename, data):
    with open(filename, mode="w", newline = "") as file:
            writer = csv.writer(file)
            writer.writerows(data)

if __name__ == '__main__':
    result = test_t_eq_511()
    #result2 = test_t_eq_255()
    #result3 = test_t_eq_15()
    
    save_to_file("bch511.csv", result)
    #save_to_file("bch255.csv", result2)
    #save_to_file("bch31.csv",result3)
        
   