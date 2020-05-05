import argparse
import struct


class SHA1:
    """
    A class to simulate and implement the SHA-1 hashing process.
    """

    def __init__(self, data):
        """
        :param - input data of the user

        Initialize the class with the input data and some 5 x 8-bit hexadecimal constants h0-->h4.
        They correspond to (1732584193, 4023233417, 2562383102, 271733878, 3285377520) in decimal 
        and (01100111010001010010001100000001, 01100111010001010010001100000001, 01100111010001010010001100000001, 
        01100111010001010010001100000001, 11000011110100101110000111110000) in binary.
        """
        self.data = data
        self.ascii2bin()
        self.h = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0
        ]

    @staticmethod
    def left_rotate(n, b):
        """
        :param - the number 'n' to left rotate
        :param - number of bits 'b' by which 'n' is left rotated
        
        Left rotate a 32-bit integer 'n' by 'b' bits. The value is ANDed with 0xFFFFFFFF so that even if n is not a 32-bit 
        integer, comes into action when n is greater than 32-bits, the output will always be a 32-bit integer.
        Example - when 4294967295 (decimal value of 0xFFFFFFFF) is left rotated by 1 bit:
            - the output is the same, 4294967295, when ANDed with 0xFFFFFFFF
            - the output is 8589934591 when it is not ANDed with 0xFFFFFFFF

        :return - returns the left rotated value
        """
        return ((n << b) | (n >> (32 - b))) & 0xFFFFFFFF

    def ascii2bin(self):
        """
        Converts the ASCII values of self.data to binary.
        """
        self.data = ''.join(format(x, 'b').zfill(8) for x in self.data)

    def padding(self):
        """
        Appends '1' to self.data and pads the input message with 0's to make it congruent with the value 448 % 512 and 
        then pads a 64-bit representation of the length of input message. The length of self.data is exactly a multiple 
        of 512 after this function is executed.
        """
        length = len(self.data)
        # Appending a 1 at the end
        self.data += "1"

        fillValue = (len(self.data) // 512) + 1
        # Calculating number of 0's to append
        fillValue = (fillValue * 512) - 64

        if len(self.data) % 512 != 448:
            # Padding 0's till they are congruent with 448 % 512
            self.data = self.data.ljust(fillValue, '0')

        bitLength = bin(length)[2:]
        bitLength = bitLength.zfill(64)
        # Appending the 64-bit length representation at the end
        self.data += bitLength

    def split2chunks(self):
        """
        Splits the data into 512-bit (or) 64 byte chunks.
        """
        self.chunks = [self.data[i: i + 512]
                       for i in range(0, len(self.data), 512)]

    def chunks2words(self):
        """
        Break the chunks to 16 x 32-bit (or) 4 byte words.
        """
        self.words16 = [[chunk[i: i + 32]
                         for i in range(0, 512, 32)] for chunk in self.chunks]

    def extend_words(self):
        """
        Takes the first 16 words and extends it to 80 for each chunk.
        """
        self.words80 = [[0] * 80] * len(self.words16)
        for i in range(len(self.words16)):
            for j in range(len(self.words16[i])):
                self.words80[i][j] = int(self.words16[i][j], 2)

        for i in range(0, len(self.words16)):
            for j in range(16, 80):
                temp = self.left_rotate(
                    (self.words80[i][j-3] ^ self.words80[i][j-8] ^ self.words80[i][j-14] ^ self.words80[i][j-16]), 1)
                self.words80[i][j] = temp

    def hash(self):
        self.padding()
        self.split2chunks()
        self.chunks2words()
        self.extend_words()

        for i in range(0, len(self.words80)):
            a, b, c, d, e = self.h
            for j in range(0, len(self.words80[i])):

                # Function 1
                if 0 <= j <= 19:
                    f = d ^ (b & (c ^ d))
                    k = 0x5A827999
                # Function 2
                elif 20 <= j <= 39:
                    f = b ^ c ^ d
                    k = 0x6ED9EBA1
                # Function 3
                elif 40 <= j <= 59:
                    f = (b & c) | (b & d) | (c & d)
                    k = 0x8F1BBCDC
                # Function 4
                elif 60 <= j <= 79:
                    f = b ^ c ^ d
                    k = 0xCA62C1D6

                # Update the values of a, b, c, d, e
                temp = (self.left_rotate(a, 5) + f + e +
                        k + self.words80[i][j]) & 0xFFFFFFFF
                e = d
                d = c
                c = self.left_rotate(b, 30)
                b = a
                a = temp

            # Update the h values after each cycle
            self.h = (
                self.h[0] + a & 0xFFFFFFFF,
                self.h[1] + b & 0xFFFFFFFF,
                self.h[2] + c & 0xFFFFFFFF,
                self.h[3] + d & 0xFFFFFFFF,
                self.h[4] + e & 0xFFFFFFFF
            )

        print(hex(self.h[0]), hex(self.h[1]), hex(
            self.h[2]), hex(self.h[3]), hex(self.h[4]))


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument('-f')
    parser.add_argument('s')
    hashObject = input("Enter the string to hash > ")
    hashObject = bytes(hashObject, 'utf-8')
    s = SHA1(hashObject).hash()


if __name__ == "__main__":
    # print(SHA1('').left_rotate(4294967295, 1))
    main()
