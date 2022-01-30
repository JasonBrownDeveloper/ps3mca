#!/bin/python3

import argparse
import functools
import itertools
import operator
import pyDes
import struct
import usb.core

# You must provide the MagicGate keys here
 
key_left  = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
iv_left   = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

key_right = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
                   0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
iv_right  = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

challenge_iv = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])

commands = {
      "CS_AUTHORIZE":[0xF7, 0x01]
    , "CS_AUTH_00":[0xF0, 0x00]
    , "CS_AUTH_GET_VECTOR":[0xF0, 0x01] + [0x00] * 9
    , "CS_AUTH_GET_PLAIN":[0xF0, 0x02] + [0x00] * 9
    , "CS_AUTH_03":[0xF0, 0x03]
    , "CS_AUTH_GET_NONCE":[0xF0, 0x04] + [0x00] * 9
    , "CS_AUTH_05":[0xF0, 0x05]
    , "CS_AUTH_PUT_CHALLENGE1":[0xF0, 0x06] + [0x00] * 9
    , "CS_AUTH_PUT_CHALLENGE2":[0xF0, 0x07] + [0x00] * 9
    , "CS_AUTH_08":[0xF0, 0x08]
    , "CS_AUTH_09":[0xF0, 0x09]
    , "CS_AUTH_0A":[0xF0, 0x0A]
    , "CS_AUTH_PUT_CHALLENGE3":[0xF0, 0x0B] + [0x00] * 9
    , "CS_AUTH_0C":[0xF0, 0x0C]
    , "CS_AUTH_0D":[0xF0, 0x0D]
    , "CS_AUTH_0E":[0xF0, 0x0E]
    , "CS_AUTH_GET_RESPONSE1":[0xF0, 0x0F] + [0x00] * 9
    , "CS_AUTH_10":[0xF0, 0x10]
    , "CS_AUTH_GET_RESPONSE2":[0xF0, 0x11] + [0x00] * 9
    , "CS_AUTH_12":[0xF0, 0x12]
    , "CS_AUTH_GET_RESPONSE3":[0xF0, 0x13] + [0x00] * 9
    , "CS_AUTH_14":[0xF0, 0x14]
    , "CS_PUT_SENTINEL":[0x27, 0x5A]
    , "CS_GET_SPECS":[0x26] + [0x00] * 9
    , "CS_PUT_READ_INDEX":[0x23] + [0x00] * 5
    , "CS_GET_READ_8":[0x43, 0x08] + [0x00] * 9
    , "CS_PUT_WRITE_INDEX":[0x22] + [0x00] * 5
    , "CS_PUT_WRITE_8":[0x42, 0x08] + [0x00] * 9
    , "CS_IO_FIN":[0x81]
    , "CS_PUT_ERASE_INDEX":[0x21] + [0x00] * 5
    , "CS_ERASE_CONFIRM":[0x82]
    , "CS_ERASE_FIN":[0x12]
}

USE_ECC = 0x01

def request_response(command, data=None, reverse=True):
    global cardflags
    wMaxPacketSize = dev[0][(0,0)][0].wMaxPacketSize
    payload = commands[command]
    size = len(payload) + 3
    packet = [0xAA, 0x42, size, 0x00, 0x81] + payload + [0x00, 0x00]
    if data:
        if len(data) != payload.count(0x00) - 1:
            raise ValueError(command, "Data is not the correct length")

        if reverse:
            data = data[::-1]

        start = packet.index(0,5)
        packet = packet[:start] + data + [functools.reduce(operator.xor, data)] + packet[start+len(data)+1:]

    if args.trace: print("tx ", command, " ".join("0x{:02X}".format(b) for b in packet))
    dev.write(0x02, packet)
    response = dev.read(0x81, wMaxPacketSize)
    if args.trace: print("rx ", command, " ".join("0x{:02X}".format(b) for b in response))

    if response[:2] != bytearray([0x55, 0x5A]):
        raise ValueError(command)

    cardflags = response[packet.index(0x00,5)];

    if "GET" in command:
        if reverse:
            r = response[-2:-payload.count(0x00)-2:-1]
            if args.trace: print(" ".join("0x{:02X}".format(b) for b in r))
            return r[1:], r[0]
        else:
            s = packet.index(0x00,5)+1
            r = response[s:s+payload.count(0x00)]
            if args.trace: print(" ".join("0x{:02X}".format(b) for b in r))
            return r[:-1], r[-1]

def magic_gate():
    request_response("CS_AUTHORIZE")
    request_response("CS_AUTH_00")
    vector, ecc = request_response("CS_AUTH_GET_VECTOR")
    plain, ecc = request_response("CS_AUTH_GET_PLAIN")

    block = bytes([v ^ p for v, p in zip(vector, plain)])

    left = pyDes.triple_des(key_left, pyDes.CBC, iv_left).encrypt(block)
    right = pyDes.triple_des(key_right, pyDes.CBC, iv_right).encrypt(block)
    auth_key = left + right

    request_response("CS_AUTH_03")
    nonce, ecc = request_response("CS_AUTH_GET_NONCE")

    test_block = bytes([0xDE, 0xAD, 0xC0, 0xDE, 0xDE, 0xAD, 0xC0, 0xDE])

    challenge3 = pyDes.triple_des(auth_key, pyDes.CBC, challenge_iv).encrypt(test_block)
    challenge2 = pyDes.triple_des(auth_key, pyDes.CBC, challenge3).encrypt(bytes(nonce))
    challenge1 = pyDes.triple_des(auth_key, pyDes.CBC, challenge2).encrypt(bytes(vector))

    request_response("CS_AUTH_05")
    request_response("CS_AUTH_PUT_CHALLENGE1", data=list(challenge1))
    request_response("CS_AUTH_PUT_CHALLENGE2", data=list(challenge2))
    request_response("CS_AUTH_08")
    request_response("CS_AUTH_09")
    request_response("CS_AUTH_0A")
    request_response("CS_AUTH_PUT_CHALLENGE3", data=list(challenge3))
    request_response("CS_AUTH_0C")
    request_response("CS_AUTH_0D")
    request_response("CS_AUTH_0E")
    response1, ecc = request_response("CS_AUTH_GET_RESPONSE1")
    request_response("CS_AUTH_10")
    response2, ecc = request_response("CS_AUTH_GET_RESPONSE2")
    request_response("CS_AUTH_12")
    response3, ecc = request_response("CS_AUTH_GET_RESPONSE3")
    request_response("CS_AUTH_14")

    verify1 = pyDes.triple_des(auth_key, pyDes.CBC, challenge_iv).decrypt(bytes(response1))
    verify2 = pyDes.triple_des(auth_key, pyDes.CBC, response1).decrypt(bytes(response2))
    verify3 = pyDes.triple_des(auth_key, pyDes.CBC, response2).decrypt(bytes(response3))

    if list(nonce) == list(verify1) and list(test_block) == list(verify2):
        session_key = list(verify3)

    # Sometimes reading hangs if the sentinel isn't explicitly set
    request_response("CS_PUT_SENTINEL")

page_cache = {}
ecc_cache = {}
def read_page(num):
    if num in page_cache:
        return

    page = []
    request_response("CS_PUT_READ_INDEX", data=list(struct.pack(">I", num)))
    for _ in range(pagesize // 8):
        chunk, ecc = request_response("CS_GET_READ_8", reverse=False)
        if functools.reduce(operator.xor, chunk) != ecc:
            raise ValueError("Read ECC error")
        page += chunk

    if cardflags & USE_ECC:
        old_ecc = []
        for _ in range(((pagesize // 128) * 3 + 4) // 8):
            chunk, ecc = request_response("CS_GET_READ_8", reverse=False)
            if functools.reduce(operator.xor, chunk) != ecc:
                raise ValueError("Read ECC error")
            old_ecc+= chunk

    request_response("CS_IO_FIN")

    if cardflags & USE_ECC and old_ecc[-1] != erased:
        def parityOf(int_type):
            parity = 1
            while (int_type):
                parity = 1 - parity
                int_type = int_type & (int_type - 1)
            return(str(parity))

        for j in range(pagesize // 128):
            line_parity = []
            column_parity = 0xFF
            for i in range(128):
                line_parity.append(parityOf(page[j*128+i]))
                column_parity = column_parity ^ page[j*128+i]

            c = ['0','0']
            for i in range(3):
                c.insert(1  , parityOf(column_parity & int("".join(itertools.islice(itertools.cycle(['1']*2**i + ['0']*2**i), 8)), 2)))
                c.insert(i+3, parityOf(column_parity & int("".join(itertools.islice(itertools.cycle(['0']*2**i + ['1']*2**i), 8)), 2)))

            lo = []
            le = []
            for i in range(7):
                lo.append(parityOf(int("".join(itertools.compress(line_parity, itertools.cycle([1]*2**i + [0]*2**i))), 2)))
                le.append(parityOf(int("".join(itertools.compress(line_parity, itertools.cycle([0]*2**i + [1]*2**i))), 2)))

            new_ecc = [int("".join(c), 2), int("".join(lo[::-1]), 2), int("".join(le[::-1]), 2)]

            def countSetBits(n):
                if (n == 0):
                    return 0
                else:
                    return (n & 1) + countSetBits(n >> 1)

            # Detect errors
            test_ecc = [a ^ b for a, b in zip(old_ecc[j*3:j*3+3], new_ecc)]
            bits = sum(countSetBits(n) for n in test_ecc)
            if bits == 10:
                print("Data Error")
                page[(j*128)+(127-test_ecc[1])] ^= 1 << (test_ecc[0] >> 4)
                # TODO commit page
            elif bits == 1:
                print("ECC Error")
                old_ecc[j*3:j*3+3] = new_ecc
                # TODO commit ecc
            elif bits != 0:
                pass
                #print("Unrecoverable Error found in page", num, "chunk", j)

    page_cache[num] = page
    ecc_cache[num] = old_ecc

def write_page(num, data=None, ecc=None):
    if data is None:
        raise ValueError("write page no data")

    if cardflags & USE_ECC and ecc is None:
        raise ValueError("write page no ecc")

    request_response("CS_PUT_WRITE_INDEX", data=list(struct.pack(">I", num)))
    for i in range(pagesize // 8):
        request_response("CS_PUT_WRITE_8", data=data[i*8:i*8+8], reverse=False)

    if cardflags & USE_ECC:
        # chunks are 128 bytes, 3 bytes per ecc, 4 byte padding
        for i in range(((pagesize // 128) * 3 + 4) // 8):
            request_response("CS_PUT_WRITE_8", data=ecc[i*8:i*8+8], reverse=False)

    request_response("CS_IO_FIN")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-s", "--specs", action="store_true")
    group.add_argument("-d", "--dump", type=argparse.FileType('w+b'))
    group.add_argument("-e", "--erase", nargs="*", metavar=("begin", "end"))
    group.add_argument("-l", "--load",  type=argparse.FileType('rb'))
    group.add_argument("-u", "--update", nargs="*", metavar=("new", "ref"), type=argparse.FileType('rb'))
    group.add_argument("--test", action="store_true")
    parser.add_argument("-t", "--trace", action="store_true")
    args = parser.parse_args()

    dev = usb.core.find(idVendor=0x054c, idProduct=0x02ea)
    if dev is None:
        raise ValueError("ps3mca is not connected")
    dev.set_configuration()

    magic_gate()

    specs, ecc = request_response("CS_GET_SPECS")
    cardsize, blocksize, pagesize = struct.unpack(">IHH", specs);
    erased = 0x00 if cardflags & 0x10 else 0xff
    eccsize = 16 if cardflags & USE_ECC else 0

    if args.specs:
        # Report specs
        if functools.reduce(operator.xor, specs) != ecc:
            print("Specs ECC error")

        print("Pages {:X}".format(cardsize))
        print("Page {}, Block {}, Card {} MB".format(pagesize, blocksize, ((cardsize * pagesize) // 1024 // 1024)))
        if cardflags & USE_ECC:
            print("ECC")
        if cardflags & 0x08:
            print("Bad Blocks Management")
        print("Erase value 0x{:02X}".format(erased))

        # Read Card Header
        read_page(0)

        if ecc_cache[0][-1] == erased:
            print("Page 0 erased")

        if "Sony PS2 Memory Card Format " != "".join(chr(i) for i in page_cache[0][0x00:0x00+28]):
            print("Not a Sony formatted card")

        print("Format Version: " + "".join(chr(i) for i in page_cache[0][0x1C:0x1C+12]))

        # Read Erase Block
        erase_block_location = struct.unpack("<I", bytes(page_cache[0][0x44:0x44+4]))[0] * struct.unpack("<H", bytes(page_cache[0][0x2C:0x2C+2]))[0]
        read_page(erase_block_location)

        if page_cache[erase_block_location][0] != erased:
            # TODO recover erase block
            print("Card has erase block")

        # Read Root Directory
        data_offset = struct.unpack("<I", bytes(page_cache[0][0x34:0x34+4]))[0]
        root_offset = struct.unpack("<I", bytes(page_cache[0][0x3C:0x3C+4]))[0]
        pages_per_cluster = struct.unpack("<H", bytes(page_cache[0][0x2A:0x2A+2]))[0]
        page = (data_offset + root_offset) * pages_per_cluster
        for i in range(2):#pages_per_cluster):
            read_page(page + i)

        try:
            if ("." != bytes(page_cache[page][0x40:0x40+32]).decode("ascii").rstrip('\0')
            or ".." != bytes(page_cache[page+1][0x40:0x40+32]).decode("ascii").rstrip('\0')):
                raise Exception()
        except:
            print("Couldn't find root directory")

    elif args.dump:
        for i in range(cardsize):
            print("Dumping Page {:X}".format(i), end="\r")
            read_page(i)
            args.dump.write(bytes(page_cache[i]))
            args.dump.write(bytes(ecc_cache[i]))
        print("")
    elif args.erase is not None:
        if len(args.erase) == 2:
            begin = (int(args.erase[0]) / blocksize) * blocksize
            end = ((int(args.erase[1]) / blocksize) + 1) * blocksize
        elif len(args.erase) == 1:
            begin = (int(args.erase[0]) / blocksize) * blocksize
            end = begin + blocksize
        elif len(args.erase) == 0:
            begin = 0
            end = cardsize
        else:
            print("argparse is dumb and can't specify a range for the number of arguments")
            print("--erase takes 0, 1 or 2 arguments")
            print("0, will erase the whole card")
            print("1, will erase the block containing the page")
            print("2, will erase the blocks containing the pages from arg 1 to arg 2")
            quit()

        print("Erasing pages {:X}".format(begin), end=" ")
        print("to {:X}".format(end)) if begin != end else print("")
        for i in range(begin, end, blocksize):
            print("Erasing Page {:X}".format(i), end="\r")
            request_response("CS_PUT_ERASE_INDEX", data=list(struct.pack(">I", i)))
            request_response("CS_ERASE_CONFIRM")
            request_response("CS_ERASE_FIN")
        print("")
    elif args.load:
        dump = args.load.read()
        for i in range(cardsize):
            print("Uploading Page {:X}".format(i), end="\r")
            write_page(i, data=list(dump[i*(pagesize+eccsize):(i+1)*(pagesize+eccsize)][:pagesize]), ecc=list(dump[i*(pagesize+eccsize):(i+1)*(pagesize+eccsize)][pagesize:]))
        print("")
    elif args.update is not None:
        if len(args.update) not in (1, 2):
            print("argparse is dumb and can't specify a range for the number of arguments")
            print("--update takes 1 or 2 arguments")
            print("1, will read the card comparing each page")
            print("2, will use the reference image to determine which pages to update")
            quit()

        if len(args.update) == 2:
            dump = args.update[1].read()
            for i in range(cardsize):
                page_cache[i] = bytearray(dump[i*(pagesize+eccsize):(i+1)*(pagesize+eccsize)][:pagesize])
                ecc_cache[i] = bytearray(dump[i*(pagesize+eccsize):(i+1)*(pagesize+eccsize)][pagesize:])
        elif len(args.update) == 1:
            for i in range(cardsize):
                print("Reading Page {:X}".format(i), end="\r")
                read_page(i)

        dump = args.update[0].read()
        blocks = set()
        for i in range(cardsize):
            if bytes(page_cache[i]) != dump[i*(pagesize+eccsize):(i+1)*(pagesize+eccsize)][:pagesize]:
                blocks.add(i // blocksize)

        for j in sorted(blocks):
            print("\033[K" "Erasing Page {:X}".format(j*blocksize), end="\r")
            request_response("CS_PUT_ERASE_INDEX", data=list(struct.pack(">I", j*blocksize)))
            request_response("CS_ERASE_CONFIRM")
            request_response("CS_ERASE_FIN")

            for i in range(j*blocksize,(j+1)*blocksize):
                print("\033[K" "Uploading Page {:X}".format(i), end="\r")
                write_page(i, data=list(dump[i*(pagesize+eccsize):(i+1)*(pagesize+eccsize)][:pagesize]), ecc=list(dump[i*(pagesize+eccsize):(i+1)*(pagesize+eccsize)][pagesize:]))
        print("")

    print("done")
