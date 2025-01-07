import socket
import time

HOST = '172.232.108.92'  # The server's hostname or IP address
PORT = 5000         # The port used by the server

while True:
    # Create a TCP/IP socket
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        # Connect to the server
        client_socket.connect((HOST, PORT))
        
        message = "Hello, Server!"
        client_socket.sendall(message.encode())

        # Receive a response
        data = client_socket.recv(1024)
        print(f"Received from server: {data.decode()}")
        
        time.sleep(5)  # Sleep for 1 second before sending the next message

    except (BrokenPipeError, ConnectionResetError) as e:
        print("Connection error:", e)
        break  # Exit the loop if there's an error
    finally:
        client_socket.close()
