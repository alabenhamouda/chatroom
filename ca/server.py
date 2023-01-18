from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
import datetime
import uuid
import socket


def create_certificate(certificate_request_path: str):
    pem_csr = open(certificate_request_path, 'rb').read()
    csr = x509.load_pem_x509_csr(pem_csr, default_backend())

    pem_cert = open('ca.crt', 'rb').read()
    ca = x509.load_pem_x509_certificate(pem_cert, default_backend())
    pem_key = open('ca.key', 'rb').read()

    ca_key = serialization.load_pem_private_key(
        pem_key, password=bytes("degla", 'utf-8'), backend=default_backend())

    builder = x509.CertificateBuilder()
    builder = builder.subject_name(csr.subject)
    builder = builder.issuer_name(ca.subject)
    builder = builder.not_valid_before(datetime.datetime.now())
    builder = builder.not_valid_after(datetime.datetime.now() +
                                      datetime.timedelta(7))  # days
    builder = builder.public_key(csr.public_key())
    builder = builder.serial_number(int(uuid. uuid4()))
    for ext in csr.extensions:
        builder = builder.add_extension(ext.value, ext.critical)

    certificate = builder.sign(
        private_key=ca_key,
        algorithm=hashes.SHA256(),
        backend=default_backend()
    )

    with open('mfdutra.crt', 'wb') as f:
        f.write(certificate.public_bytes(serialization. Encoding.PEM))


def init_socket():
    host = "127.0.0.1"
    port = 65432
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print("listening")
        while True:
            client, ip = s.accept()
            certificate = client.recv(4096)
            cert = x509.load_pem_x509_certificate(
                certificate, default_backend())
            print(cert.issuer)


if __name__ == '__main__':
    # create_certificate('../client/mfdutra.csr')
    init_socket()
