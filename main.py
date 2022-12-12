"""
@author: libor_komanek
"""
import os
import hashlib
import sys
import rsa
import functions
from PyQt6 import uic
from PyQt6.QtWidgets import QApplication, QMainWindow, QMessageBox, QFileDialog
from zipfile import ZipFile

qtCreatorFile: str = "ElectronicSignature.ui"
Ui_MainWindow, QtBaseClass = uic.loadUiType(qtCreatorFile)


class App(QMainWindow, Ui_MainWindow):
	def __init__(self):
		QMainWindow.__init__(self)
		Ui_MainWindow.__init__(self)
		self.setupUi(self)
		# Default variable values
		self.loaded_file_path: str or None = None
		self.public_key_path: str or None = None
		self.public_key: tuple[int, int] or None = None
		self.private_key_path: str or None = None
		self.private_key: tuple[int, int] or None = None
		# Link buttons to methods
		self.buttonLoadFile.clicked.connect(self.loadFile)
		self.buttonGenerateKeys.clicked.connect(self.generateRSAKeys)
		self.buttonLoadPublicKey.clicked.connect(lambda: self.loadKeyFile(True))
		self.buttonLoadPrivateKey.clicked.connect(lambda: self.loadKeyFile(False))
		self.buttonSignFile.clicked.connect(self.signFile)
		self.buttonVerifySignature.clicked.connect(self.verifySignature)

	def loadFile(self) -> None:
		"""Opens up a dialog for selecting an existing file, stores its path
		and displays information about this file in GUI."""
		try:
			file: str = QFileDialog.getOpenFileName(self, "Select your file")[0]
			if len(file) < 1:
				raise Exception("No file selected.")
			self.loaded_file_path = file
			self.displayFileInfo()
		except Exception as e:
			self.showErrorMessage(e)

	def generateRSAKeys(self) -> None:
		"""Opens up a dialog for selecting a directory where the generated RSA keypairs should be exported."""
		try:
			# Figure out where the keys should be stored
			directory: str = QFileDialog.getExistingDirectory(self, "Choose a directory to save the RSA keys")
			if len(directory) < 1:
				raise Exception("No directory selected.")
			public_key_path: str = f"{directory}/rsa_key.pub"
			private_key_path: str = f"{directory}/rsa_key.priv"

			# Generate the key pairs and encode them in base64
			n, e, d = rsa.generateKeyPairs()
			public_key_base64: str = functions.encodeKeyWithBase64(n, e)
			private_key_base64: str = functions.encodeKeyWithBase64(n, d)

			# Export the key pairs
			with open(public_key_path, "w") as file:
				file.write(f"RSA {public_key_base64}")
			with open(private_key_path, "w") as file:
				file.write(f"RSA {private_key_base64}")

			# Update class variables and GUI
			self.public_key = n, e
			self.fieldPublicKeyPath.setText(public_key_path)
			self.private_key = n, d
			self.fieldPrivateKeyPath.setText(private_key_path)
		except Exception as e:
			self.showErrorMessage(e)

	def loadKeyFile(self, public: bool) -> None:
		"""Opens up a dialog for selecting a file holding the public or private key, depending on the value of
		the 'public' argument.

		The loaded key is stored in a class variable for future use and the path to the key file is displayed in GUI.

		:param public: whether a public key should be requested (suggests a private key is requested if False)
		"""
		try:
			# Private key version variables
			caption: str = "Choose the file with your private key"
			filters: str = "*.priv"
			# Public key version variables
			if public:
				caption = "Choose the file with your public key"
				filters = "*.pub"

			# Determine the path to the file
			path: str = QFileDialog.getOpenFileName(self, caption, filter=filters)[0]
			if len(path) < 1:
				raise Exception("No file selected.")

			# Try to get the encoded key from the chosen file
			with open(path, "r") as file:
				prefix, encoded_key = file.readline().split()
			if prefix != "RSA" or len(encoded_key) < 1:
				raise Exception("Invalid RSA key file.")

			# Decode the key and update class variables and GUI
			if public:
				self.public_key_path = path
				self.public_key = functions.decodeKeyWithBase64(encoded_key)
				self.fieldPublicKeyPath.setText(path)
			else:
				self.private_key_path = path
				self.private_key = functions.decodeKeyWithBase64(encoded_key)
				self.fieldPrivateKeyPath.setText(path)
		except Exception as e:
			self.showErrorMessage(e)

	def signFile(self) -> None:
		"""Opens up a dialog for selecting a directory where the ZIP archive with the signature file and the file
		being signed should be created. Then proceeds to generate a signature."""
		try:
			# Verify everything needed is ready
			if self.loaded_file_path is None:
				raise Exception("You need to load a file first.")
			if self.private_key is None:
				raise Exception("A private key is required to sign a file.")

			# Figure out where the ZipFile with the original file and the signature should be stored
			caption: str = "Choose a directory to save the signature and the file being signed."
			directory: str = QFileDialog.getExistingDirectory(self, caption)

			# Get a fingerprint of the loaded file using the SHA3-512 hash function
			with open(self.loaded_file_path, "rb") as file:
				file_hash: str = hashlib.sha3_512(file.read()).hexdigest()

			# Encrypt the fingerprint using the RSA private key and encode it to base64
			encrypted_hash: str = rsa.encrypt(file_hash, self.private_key[0], self.private_key[1])
			encrypted_hash_base64: str = functions.encodeWithBase64(encrypted_hash)

			# Create a ZipFile with the original file and the signature inside it
			loaded_file_basename: str = os.path.basename(self.loaded_file_path)
			zipfile_path: str = f"{directory}/{loaded_file_basename}.zip"
			with ZipFile(zipfile_path, "w") as zipfile:
				zipfile.write(self.loaded_file_path, loaded_file_basename)  # original file
				zipfile.writestr(f"{loaded_file_basename}.sign", f"RSA_SHA3-512 {encrypted_hash_base64}")  # signature
			self.showInformativeMessage(
				"The file has been signed.",
				"You can find the Zip file containing the original file along with the signature here:\n"
				f"{zipfile_path}")
		except Exception as e:
			self.showErrorMessage(e)

	def verifySignature(self) -> None:
		"""Opens up a dialog for selecting a ZIP archive with a signature and the original signed file inside
		and then proceeds to verify the file's fingerprint matches the decrypted signature."""
		try:
			# Verify everything needed is ready
			if self.public_key is None:
				raise Exception("A public key is required to verify a file's signature.")

			# Get the absolute path to the ZipFile, open it and get the paths to the signature and original file
			caption: str = "Choose the Zip file with signature and the original file insided"
			filters: str = "*.zip"
			zipfile_path: str = QFileDialog.getOpenFileName(self, caption, filter=filters)[0]
			with ZipFile(zipfile_path, "r") as zipfile:
				# Verify there's the expected number of files in the archive
				if len(zipfile.namelist()) != 2:
					raise Exception("Invalid archive. Unexpected number of files found inside.")
				# Find the signature and signed file
				for file in zipfile.namelist():
					if file.endswith(".sign"):
						signature_file: str = file
					else:
						signed_file: str = file
				# If the two expected files were not found, the archive is declared invalid
				if not signature_file or not signed_file:
					raise Exception("Invalid archive. Required files not found inside.")
				# Get the signature file content and verify if its format is valid
				prefix, signature_encrypted_hash_base64 = zipfile.read(signature_file).decode("utf-8").split()
				print(prefix, signature_encrypted_hash_base64)
				if prefix != "RSA_SHA3-512" or not signature_encrypted_hash_base64:
					raise Exception("Invalid signature file.")
				# Get the encrypted signature hash and the hash of the signed file
				signed_file_hash: str = hashlib.sha3_512(zipfile.read(signed_file)).hexdigest()
				signature_encrypted_hash: str = functions.decodeWithBase64(signature_encrypted_hash_base64)

			# Decrypt the signature hash and verify the two hashes match
			signature_hash: str = rsa.decrypt(signature_encrypted_hash, self.public_key[0], self.public_key[1])
			if signed_file_hash == signature_hash:
				self.showInformativeMessage("Success!", "The signature has been verified.")
			else:
				self.showInformativeMessage("Failed!", "The signature failed verification.")
		except Exception as e:
			self.showErrorMessage(e)

	def displayFileInfo(self) -> None:
		"""Fills the GUI fields with information gathered about the loaded file."""
		try:
			if self.loaded_file_path is None:
				raise Exception("No file has been loaded yet!")
			info: dict = functions.getFileInfo(self.loaded_file_path)

			self.fieldFileName.setText(info['name'])
			self.fieldExtension.setText(info['extension'])
			self.fieldAbsolutePath.setText(info['absolute_path'])
			self.fieldFileSize.setText(info['file_size'])
			self.fieldCreatedDate.setText(info['created_date'])
			self.fieldModifiedDate.setText(info['modified_date'])
		except Exception as e:
			self.showErrorMessage(e)

	@staticmethod
	def showErrorMessage(e: Exception) -> None:
		"""Shows a popup message with information about an Exception.

		:param e: the exception that occurred
		"""
		print(e)  # Also print out the exception to console
		msg = QMessageBox()
		msg.setIcon(QMessageBox.Icon.Critical)
		msg.setWindowTitle("Ooops!")
		msg.setText("Something went wrong!")
		msg.setInformativeText(str(e))
		msg.setBaseSize(400, 200)
		msg.exec()

	@staticmethod
	def showInformativeMessage(title: str, message: str) -> None:
		"""Shows a popup message with the specified message.

		:param title: the title of the message
		:param message: the message to be displayed
		"""
		print(f"{title} > {message}")
		msg = QMessageBox()
		msg.setIcon(QMessageBox.Icon.Information)
		msg.setWindowTitle("Informative message")
		msg.setText(title)
		msg.setInformativeText(message)
		msg.setBaseSize(400, 200)
		msg.exec()


if __name__ == '__main__':
	app = QApplication(sys.argv)
	window = App()
	window.show()
	sys.exit(app.exec())
