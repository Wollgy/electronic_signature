"""
@author: libor_komanek
"""
import random
from math import gcd

y: tuple[int, int] = 10**18+1, 10**19-1  # interval for generation of p and q prime numbers
X: int = 10  # uniform number of bits for a character
z: int = 12  # characters per block
block_size: int = z * X  # bits per block


def isPrime(n: int, k: int = 8) -> bool:
	"""Determines whether the given number is a probable prime number using the Miller–Rabin primality test.

	:param n: number to be tested for primality
	:param k: number of rounds of testing to perform, defaults to 8
	:return: whether n has been determined to most likely be a prime number
	"""
	# Cannot be a number lower than 2 or an even number other than 2
	if n == 2:
		return True
	if n < 2 or n % 2 == 0:
		return False
	s: int = 0
	d: int = n - 1
	while d % 2 == 0:
		d >>= 1
		s += 1
	assert (2 ** s * d == n - 1)

	for i in range(k):  # k rounds of testing for primality
		a: int = random.randrange(2, n)
		if pow(a, d, n) == 1:
			return True
		for j in range(s):
			if pow(a, 2 ** j * d, n) == n - 1:
				return True
		return False
	return True


def generateRandomPrimeNumber(low: int, high: int) -> int:
	"""Generates a random prime number from the given range.

	:param low: the lower point of the range for generation
	:param high: the higher point of the range for generation
	:return: randomly generated prime number in the given range
	"""
	# The range needs to start with an odd number in order to correctly generate an odd prime number
	if low % 2 == 0:
		low += 1
	# Try 1000 times, if a prime number is not found, it is possible one doesn't exist in the given range
	for i in range(1000):
		random_number = random.randrange(low, high, 2)  # generate a random odd number in range
		if isPrime(random_number):
			return random_number
	raise Exception("Prime number generation timed out!")


def generateKeyPairs(p: int = None, q: int = None) -> tuple[int, int, int]:
	"""Generate new values forming the private and public keys.

	:param p: optional value of p; will be generated randomly if not supplied
	:param q: optional value of q; will be generated randomly if not supplied
	:return: (n, e, d) values forming the private and public keys
	"""
	if p is None:
		p = generateRandomPrimeNumber(y[0], y[1])
	if q is None:
		q = generateRandomPrimeNumber(y[0], y[1])
	if isPrime(p) is False or isPrime(q) is False:
		raise Exception("Both 'p' and 'q' must be prime numbers!")
	n: int = p * q
	phi: int = (p - 1) * (q - 1)
	e: int or None = None  # initial value
	while e is None:
		pick = random.randint(2, phi - 1)
		if gcd(pick, phi) == 1:
			e = pick
	d: int = pow(e, -1, phi)
	return n, e, d


def encrypt(text: str, modulus: int, exponent: int) -> str:
	"""Encrypts the given text using RSA Cipher.

	:param text: string to be encrypted
	:param modulus: value of the modulus (n)
	:param exponent: value of the exponent (e or d)
	:return: sequence of integers in the form of a string
	"""
	# 1) Convert text to list of ASCII values
	ascii_list: list[int] = [ord(char) for char in text]

	# 2) Convert ASCII integers to binary with uniform (X) number of bits
	bit_list: list[str] = [f"{char:0{X}b}" for char in ascii_list]

	# 3) Convert the individual chunks of bits into larger blocks
	bit_str: str = "".join(bit_list)
	missing_bits = len(bit_str) % block_size
	if missing_bits:
		bit_str = "0"*(block_size - missing_bits) + bit_str
	blocks_bit: list[str] = [bit_str[i:i + block_size] for i in range(0, len(bit_str), block_size)]

	# 4) Convert bit sequences in blocks into integers
	blocks_int: list[int] = [int(block, 2) for block in blocks_bit]

	# 5) Encrypt each block
	blocks_encrypted: list[int] = [pow(m, exponent, modulus) for m in blocks_int]

	# Convert the blocks to string and return result
	result: str = " ".join([str(block) for block in blocks_encrypted])
	return result


def decrypt(text: str, modulus: int, exponent: int) -> str:
	"""Decrypts the given text using RSA Cipher. The text is expected to be a string containing an integer
	or a sequence of integers separated by spaces.

	:param text: encrypted sequence of integers to be decrypted
	:param modulus: value of the modulus (n)
	:param exponent: value of the exponent (e or d)
	:return: the original string before encryption
	"""
	# 1) Convert string to list of encrypted integers (the text is expected to have each block separated by a space)
	blocks_encrypted: list[int] = [int(block) for block in text.split(" ")]

	# 2) Decrypt each block
	blocks_int: list[int] = [pow(c, exponent, modulus) for c in blocks_encrypted]

	# 3) Convert integers in blocks into binary
	blocks_bit: list[str] = [bin(block).replace("0b", "") for block in blocks_int]

	# 4) Fill in zeros at the start of the binary
	blocks_bit = [block.zfill(block_size) for block in blocks_bit]

	# 5) Split the blocks into chunks with individual characters
	bit_str: str = "".join(blocks_bit)
	bit_list: list[str] = [bit_str[i: i + X] for i in range(0, len(bit_str), X)]

	# 6) Get rid of the "blank" chunks only containing unneccessary zeros
	bit_list_without_blanks: list[str] = [char for char in bit_list if int(char) != 0]

	# 7) Convert binary to integers (ASCII values)
	ascii_list: list[int] = [int(char, 2) for char in bit_list_without_blanks]

	# 8) Convert ASCII values to characters
	characters: list[str] = [chr(char) for char in ascii_list]

	# Join the characters in a string and return this result
	result = "".join(characters)
	return result
