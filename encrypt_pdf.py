import PyPDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os


def encrypt_pdf(input_file, output_file, password):
    """
    Encrypts a PDF file with a given password.

    Args:
        input_file (str): The path to the input PDF file.
        output_file (str): The path to the output encrypted PDF file.
        password (str): The password used for encryption.

    Returns:
        None
    """
    # Генерація ключа та IV на основі пароля
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC)
    iv = cipher.iv

    # Відкриття PDF-файлу
    with open(input_file, "rb") as f_in, open(output_file, "wb") as f_out:
        reader = PyPDF2.PdfFileReader(f_in)
        writer = PyPDF2.PdfFileWriter()

        # Копіювання сторінок з оригінального PDF у новий
        for page_num in range(reader.numPages):
            writer.addPage(reader.getPage(page_num))

        # Додавання шифрування до нового PDF
        writer.encrypt(password)

        # Запис нового PDF-файлу
        writer.write(f_out)


# Інтерфейс користувача
def main():
    input_file = input("Enter the path of the PDF file to encrypt: ")
    output_file = input("Enter the output file name: ")
    password = input("Enter the password for encryption: ")

    encrypt_pdf(input_file, output_file, password)
    print(f"File '{input_file}' has been encrypted as '{output_file}' with the password provided.")


if __name__ == "__main__":
    main()
