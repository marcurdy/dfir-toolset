#!/usr/bin/python

from binascii import unhexlify
import sys

def writeToStdout(content):
    sys.stdout.write(content)

def HexToBin(hex):
    res = ''
    length = len(hex)
    idx = 1
    while idx < length:
        res += unhexlify(hex[idx:idx+2])
        idx += 3
    return res

def cArrayToBin(carray):
    bytes = carray.split('\\x')
    res = ''
    for b in bytes:
        res += HexToBin(b)
    return res

def unicodeToBin(unicode):
    bytes = unicode.split('%u')
    binary = ''

    for uni in bytes:
        binary += swapHexToBin(uni)

    return binary

def swapHexToBin(bytes):
    if(len(bytes) == 0):
        return ''

    if(len(bytes) != 4):
        print "Error swapping bytes! (%s)" % bytes
        sys.exit(1)

    a = bytes[2:4]
    b = bytes[0:2]

    return unhexlify(a) + unhexlify(b)

#- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -#
# - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - #
#- - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -#

if len(sys.argv) < 2:
    f = sys.stdin
else:
    filename = sys.argv[1]
    f = file(filename, 'r')

content = f.read()

# strip newlines, whitespace, etc..
content = content.replace('\n', '')
content = content.replace(';', '')
content = content.replace('\r', '')
content = content.replace('\t', '')
content = content.replace(' ', '')
content = content.replace('+', '')
content = content.replace('"', '')
content = content.replace("'", '')

if content[0:2] == '%u':
    res = unicodeToBin(content)
    writeToStdout(res)
elif content[0:2] == '\\x':
    res = cArrayToBin(content)
    writeToStdout(res)
else:
    res = HexToBin(content)
    writeToStdout(res)
