import time

filename = 'example.txt'

while True:
    # Open the file in read mode to read contents
    with open(filename, 'r') as file:
        content = file.read()
        print("Read data from the file")
    
    # Open the file in append mode to add new content
    with open(filename, 'a') as file:
        file.write("New data added.\n")
        print("New data written to the file.")

    # Wait for a short time before the next iteration
    time.sleep(2)  # Adjust the sleep time as needed
