from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
import datetime
import uuid
import socket
import threading

DELIMETER = b"$END_MESSAGE$"
users_socket = {}


def create_certificate(username, pem_csr):
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

    with open(f'{username}.crt', 'wb') as f:
        f.write(certificate.public_bytes(serialization. Encoding.PEM))
    print("Certificate successfully created")


def read_message(client: socket):
    chunk = client.recv(4096)
    return chunk


def get_certificate(username: str):
    with open(f"{username}.crt", 'rb') as cert:
        certificate = cert.read()
        return certificate


def handle_initiate_comm(client: socket):
    data = read_message(client)
    username, other_username, new_host, new_port = [
        x.decode("utf-8") for x in data.split(DELIMETER)]
    users_socket[other_username] = {
        "host": new_host, "port": new_port, "initiator": username}
    certificate = get_certificate(other_username)
    client.sendall(certificate)


def handle_accept_comm(client: socket):
    data = read_message(client)
    username, other_username = [
        x.decode("utf-8") for x in data.split(DELIMETER)]
    if username in users_socket.keys():
        connection_details = users_socket[username]
        certificate = get_certificate(
            connection_details["initiator"])
        host = connection_details["host"]
        port = connection_details["port"]
        data = bytearray()
        data.extend(host.encode('utf-8') + DELIMETER)
        data.extend(port.encode('utf-8') + DELIMETER)
        data.extend(certificate)
        client.sendall(bytes(data))


def handle_certificate_request(client: socket):
    data = read_message(client)
    username, certificate = data.split(DELIMETER)
    username = username.decode('utf-8')
    create_certificate(username, certificate)


def handle_client(client: socket):
    while True:
        print("waiting for op")
        operation = read_message(client)
        print(operation)
        client.sendall(b"OK")
        if operation == b"OP_REQ_CERT":
            handle_certificate_request(client)
        elif operation == b"OP_INIT_COMM":
            handle_initiate_comm(client)
        elif operation == b"OP_ACC_COMM":
            handle_accept_comm(client)


def init_socket():
    host = "127.0.0.1"
    port = 65433
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        print("listening")
        while True:
            client, ip = s.accept()
            thread = threading.Thread(
                target=handle_client, args=(client,)).start()


if __name__ == '__main__':
    # create_certificate('../client/mfdutra.csr')
    init_socket()
