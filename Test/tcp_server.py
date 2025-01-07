import socket
import time

# Define the server address and port
HOST = '192.168.1.3'  # localhost
PORT = 3000         # port to listen on

# Create a TCP/IP socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to the address and port
server_socket.bind((HOST, PORT))

# Listen for incoming connections
server_socket.listen()

print(f"Server listening on {HOST}:{PORT}")

try:
    while True:
        # Wait for a connection
        client_socket, client_address = server_socket.accept()
        print(f"Connection from {client_address}")

        while True:  # Loop to handle multiple messages from the same client
            # Receive data from the client
            data = client_socket.recv(1024)
            if not data:
                print("No more data from client. Closing connection.")
                break  # Exit the loop if no more data is received

            print(f"Received data: {data.decode()}")
            # Send a response back to the client
            response = "Message received!"
            client_socket.sendall(response.encode())

        # Close the connection
        client_socket.close()

except KeyboardInterrupt:
    print("Server is shutting down.")
finally:
    server_socket.close()
