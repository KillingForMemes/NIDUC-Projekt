#!/usr/bin/env python

import binascii
import hashlib
import os
import random
import unittest

import bchlib

delta = 0   # additional errors

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
    failed_tests = 0
    total_tests = 10000
    for i in range(total_tests):
        try:
            if not BCHTestCase.exercise(t=2, m=9):
                failed_tests += 1
        except Exception as e:
            print(f"Test {i+1} failed with exception: {e}")
    print(f"Failed tests for BCH(511, 493): {failed_tests}/{total_tests}")

# BCH(255, 223)
def test_t_eq_255():
    # 255 = 2^m -> m = 8
    # t = 4
    failed_tests = 0
    total_tests = 1000
    for i in range(total_tests):
        try:
            if not BCHTestCase.exercise(t=15, m=8):
                failed_tests += 1
        except Exception as e:
            print(f"Test {i+1} failed with exception: {e}")
    print(f"Failed tests for BCH(255, 223): {failed_tests}/{total_tests}")

if __name__ == '__main__':
    test_t_eq_511()
    #test_t_eq_255()