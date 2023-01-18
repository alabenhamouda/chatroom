from cryptography import x509
from cryptography.hazmat. backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives. serialization import (Encoding,
                                                           PrivateFormat, NoEncryption)


def request_certificate():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    builder = x509.CertificateSigningRequestBuilder()
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, u'USER:mfdutra'),
        x509.NameAttribute(NameOID.COUNTRY_NAME, u'US'),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u'California'),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u'Menlo Park'),
    ]))

    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )

    request = builder.sign(
        private_key, hashes.SHA256(), default_backend())

    with open('./mfdutra.csr', 'wb') as f:
        f.write(request.public_bytes(Encoding.PEM))

    with open('./mfdutra.key', 'wb') as f:
        f.write(private_key.private_bytes(Encoding.PEM,
                PrivateFormat.TraditionalOpenSSL, NoEncryption()))


def load_certificate(certificate_path):
    with open(certificate_path, "rb") as cert_file:
        cert_data = cert_file.read()
        certificate = x509.load_pem_x509_certificate(
            cert_data, default_backend())
        return certificate


def encrypt_message(message: str, certificate):
    public_key = certificate.public_key()
    encrypted_message = public_key.encrypt(
        bytes(message, 'utf-8'),
        padding.PKCS1v15()
    )
    return encrypted_message


def decrypt_message(ciphertext):
    pem_key = open(username + ".key", 'rb').read()
    private_key = serialization.load_pem_private_key(
        pem_key, password=None, backend=default_backend())
    return private_key.decrypt(ciphertext, padding.PKCS1v15()).decode("utf-8")


# request_certificate()
username = "mfdutra"
certificate = load_certificate("../ca/mfdutra.crt")
cipher = encrypt_message("degla fsfs", certificate=certificate)
msg = decrypt_message(cipher)
print(msg)
