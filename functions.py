"""
@author: libor_komanek
"""
import os
import platform
import pathlib
import datetime
import base64


def getCrossPlatformFileCreationDate(absolute_path: str) -> float:
	"""Determines the creation date of the specified file.

	The correct date should always be returned if the
	running OS is Windows or macOS and should work correctly for other Unix-based systems which store the creation date
	in a similar way.

	Returns the date of last metadata change if a creation date is not found (likely because the running OS is a
	Unix-based system which does not store the creation dates or stores them in an unexpected way).

	:param absolute_path: the path to the file
	:return: creation date of the file if one was found, otherwise the last metadata change date
	"""
	if platform.system() == "Windows":
		return os.path.getmtime(absolute_path)
	stat = os.stat(absolute_path)
	try:
		return stat.st_birthtime  # for macOS and some other Unix based systems
	except AttributeError:
		# likely a Unix system which does not store file creation dates - returns the last modified date
		return stat.st_ctime


def getFileInfo(absolute_path: str) -> dict:
	"""Gathers information about a file and returns i in the form of a dictionary.

	Gathers this information:

	- name - name of the file (without the extension)
	- extension - the extension/type of the file
	- absolute_path - absolute path to the file
	- file_size - size of the file in bytes (formatted as a string to include the unit)
	- created_date - the date the file was created, formatted
	- modified_date - the date the file was last modified, formatted

	:param absolute_path: the path to the file
	:return: dictionary with information about the file
	"""
	name, extension = os.path.splitext(os.path.basename(absolute_path))
	created_date: float = getCrossPlatformFileCreationDate(absolute_path)
	modified_date: float = pathlib.Path(absolute_path).stat().st_mtime
	info: dict = {
		"name": name,
		"extension": extension,
		"absolute_path": absolute_path,
		"file_size": str(os.path.getsize(absolute_path)) + " B",
		"created_date": datetime.datetime.fromtimestamp(created_date).strftime("%d/%m/%Y %H:%M:%S"),
		"modified_date": datetime.datetime.fromtimestamp(modified_date).strftime("%d/%m/%Y %H:%M:%S")
	}
	return info


def encodeWithBase64(message: str) -> str:
	"""Encodes the specified message using the Base64 encoding function.

	:param message: message to be encoded
	:return: encoded string
	"""
	message_bytes: bytes = message.encode("ascii")
	base64_bytes: bytes = base64.b64encode(message_bytes)
	base64_ascii: str = base64_bytes.decode("ascii")
	return base64_ascii


def decodeWithBase64(encoded_message: str) -> str:
	"""Decodes the specified message which has been encoded usign the Base64 encoding function.

	:param encoded_message: message encoded using Base64 encoding
	:return: decoded string
	"""
	base64_bytes: bytes = encoded_message.encode("ascii")
	message_bytes: bytes = base64.b64decode(base64_bytes)
	message: str = message_bytes.decode("ascii")
	return message


def encodeKeyWithBase64(modulus: int, exponent: int) -> str:
	"""Takes the individual parts (modulus and exponent) of a private or public RSA key and
	encodes it using the Base64 encoding.

	:param modulus: value of the modulus (n)
	:param exponent: value of the exponent (e or d)
	:return: encoded public or private key
	"""
	message: str = f"{modulus} {exponent}"
	result = encodeWithBase64(message)
	return result


def decodeKeyWithBase64(encoded_key: str) -> tuple[int, int]:
	"""Decodes the specified encoded key using the Base64 encoding and returns a tuple holding the values of
	the individual parts of an RSA key (modulus and exponent).

	:param encoded_key: RSA key encoded using the Base64 encoding
	:return: tuple holding the values of modulus and exponent
	"""
	decoded_message = decodeWithBase64(encoded_key)
	modulus, exponent = decoded_message.split()
	return int(modulus), int(exponent)
