'''
    ##  Implementation of peer
    ##  Each peer has a client and a server side that runs on different threads
    ##  150114822 - Eren Ulaş
'''

from socket import *
import threading
import time
import select
import logging

# Server side of peer
class PeerServer(threading.Thread):
    # Peer server initialization
    def __init__(self, username, peerServerPort):
        threading.Thread.__init__(self)
        # keeps the username of the peer
        self.username = username
        # tcp socket for peer server
        self.tcpServerSocket = socket(AF_INET, SOCK_STREAM)
        # port number of the peer server
        self.peerServerPort = peerServerPort
        # if 1, then user is already chatting with someone
        # if 0, then user is not chatting with anyone
        self.isChatRequested = 0
        # keeps the socket for the peer that is connected to this peer
        self.connectedPeerSocket = None
        # keeps the ip of the peer that is connected to this peer's server
        self.connectedPeerIP = None
        # keeps the port number of the peer that is connected to this peer's server
        self.connectedPeerPort = None
        # online status of the peer
        self.isOnline = True
        # keeps the username of the peer that this peer is chatting with
        self.chattingClientName = None
    

    # main method of the peer server thread
    def run(self):
        print("Peer server started...")    
        # gets the ip address of this peer
        # first checks to get it for windows devices
        # if the device that runs this application is not windows
        # it checks to get it for macos devices
        hostname=gethostname()
        try:
            self.peerServerHostname=gethostbyname(hostname)
        except gaierror:
            import netifaces as ni
            self.peerServerHostname = ni.ifaddresses('en0')[ni.AF_INET][0]['addr']

        # ip address of this peer
        #self.peerServerHostname = 'localhost'
        # socket initializations for the server of the peer
        self.tcpServerSocket.bind((self.peerServerHostname, self.peerServerPort))
        self.tcpServerSocket.listen(4)
        # inputs sockets that should be listened
        inputs = [self.tcpServerSocket]
        # server listens as long as there is a socket to listen in the inputs list and the user is online
        while inputs and self.isOnline:
            # monitors for the incoming connections
            try:
                readable, writable, exceptional = select.select(inputs, [], [])
                # If a server waits to be connected enters here
                for s in readable:
                    # if the socket that is receiving the connection is 
                    # the tcp socket of the peer's server, enters here
                    if s is self.tcpServerSocket:
                        # accepts the connection, and adds its connection socket to the inputs list
                        # so that we can monitor that socket as well
                        connected, addr = s.accept()
                        connected.setblocking(0)
                        inputs.append(connected)
                        # if the user is not chatting, then the ip and the socket of
                        # this peer is assigned to server variables
                        if self.isChatRequested == 0:     
                            print(self.username + " is connected from " + str(addr))
                            self.connectedPeerSocket = connected
                            self.connectedPeerIP = addr[0]
                    # if the socket that receives the data is the one that
                    # is used to communicate with a connected peer, then enters here
                    else:
                        # message is received from connected peer
                        messageReceived = s.recv(1024).decode()
                        # logs the received message
                        logging.info("Received from " + str(self.connectedPeerIP) + " -> " + str(messageReceived))
                        # if message is a request message it means that this is the receiver side peer server
                        # so evaluate the chat request
                        if len(messageReceived) > 11 and messageReceived[:12] == "CHAT-REQUEST":
                            # text for proper input choices is printed however OK or REJECT is taken as input in main process of the peer
                            # if the socket that we received the data belongs to the peer that we are chatting with,
                            # enters here
                            if s is self.connectedPeerSocket:
                                # parses the message
                                messageReceived = messageReceived.split()
                                # gets the port of the peer that sends the chat request message
                                self.connectedPeerPort = int(messageReceived[1])
                                # gets the username of the peer sends the chat request message
                                self.chattingClientName = messageReceived[2]
                                # prints prompt for the incoming chat request
                                print("Incoming chat request from " + self.chattingClientName + " >> ")
                                print("Enter OK to accept or REJECT to reject:  ")
                                # makes isChatRequested = 1 which means that peer is chatting with someone
                                self.isChatRequested = 1
                            # if the socket that we received the data does not belong to the peer that we are chatting with
                            # and if the user is already chatting with someone else(isChatRequested = 1), then enters here
                            elif s is not self.connectedPeerSocket and self.isChatRequested == 1:
                                # sends a busy message to the peer that sends a chat request when this peer is 
                                # already chatting with someone else
                                message = "BUSY"
                                s.send(message.encode())
                                # remove the peer from the inputs list so that it will not monitor this socket
                                inputs.remove(s)
                        # if an OK message is received then ischatrequested is made 1 and then next messages will be shown to the peer of this server
                        elif messageReceived == "OK":
                            self.isChatRequested = 1
                        # if an REJECT message is received then ischatrequested is made 0 so that it can receive any other chat requests
                        elif messageReceived == "REJECT":
                            self.isChatRequested = 0
                            inputs.remove(s)
                        # if a message is received, and if this is not a quit message ':q' and 
                        # if it is not an empty message, show this message to the user
                        elif messageReceived[:2] != ":q" and len(messageReceived)!= 0:
                            print(self.chattingClientName + ": " + messageReceived)
                        # if the message received is a quit message ':q',
                        # makes ischatrequested 1 to receive new incoming request messages
                        # removes the socket of the connected peer from the inputs list
                        elif messageReceived[:2] == ":q":
                            self.isChatRequested = 0
                            inputs.clear()
                            inputs.append(self.tcpServerSocket)
                            # connected peer ended the chat
                            if len(messageReceived) == 2:
                                print("User you're chatting with ended the chat")
                                print("Press enter to quit the chat: ")
                        # if the message is an empty one, then it means that the
                        # connected user suddenly ended the chat(an error occurred)
                        elif len(messageReceived) == 0:
                            self.isChatRequested = 0
                            inputs.clear()
                            inputs.append(self.tcpServerSocket)
                            print("User you're chatting with suddenly ended the chat")
                            print("Press enter to quit the chat: ")

                        
            # handles the exceptions, and logs them
            except OSError as oErr:
                logging.error("OSError: {0}".format(oErr))
            except ValueError as vErr:
                logging.error("ValueError: {0}".format(vErr))
            
# Client side of peer
class PeerClient(threading.Thread):
    # variable initializations for the client side of the peer
    def __init__(self, ipToConnect, portToConnect, username, peerServer, responseReceived):
        threading.Thread.__init__(self)
        # keeps the ip address of the peer that this will connect
        self.ipToConnect = ipToConnect
        # keeps the username of the peer
        self.username = username
        # keeps the port number that this client should connect
        self.portToConnect = portToConnect
        # client side tcp socket initialization
        self.tcpClientSocket = socket(AF_INET, SOCK_STREAM)
        # keeps the server of this client
        self.peerServer = peerServer
        # keeps the phrase that is used when creating the client
        # if the client is created with a phrase, it means this one received the request
        # this phrase should be none if this is the client of the requester peer
        self.responseReceived = responseReceived
        # keeps if this client is ending the chat or not
        self.isEndingChat = False


    # main method of the peer client thread
    def run(self):
        print("Peer client started...")
        # connects to the server of other peer
        self.tcpClientSocket.connect((self.ipToConnect, self.portToConnect))
        # if the server of this peer is not connected by someone else and if this is the requester side peer client then enters here
        if self.peerServer.isChatRequested == 0 and self.responseReceived is None:
            # composes a request message and this is sent to server and then this waits a response message from the server this client connects
            requestMessage = "CHAT-REQUEST " + str(self.peerServer.peerServerPort)+ " " + self.username
            # logs the chat request sent to other peer
            logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + requestMessage)
            # sends the chat request
            self.tcpClientSocket.send(requestMessage.encode())
            print("Request message " + requestMessage + " is sent...")
            # received a response from the peer which the request message is sent to
            self.responseReceived = self.tcpClientSocket.recv(1024).decode()
            # logs the received message
            logging.info("Received from " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + self.responseReceived)
            print("Response is " + self.responseReceived)
            # parses the response for the chat request
            self.responseReceived = self.responseReceived.split()
            # if response is ok then incoming messages will be evaluated as client messages and will be sent to the connected server
            if self.responseReceived[0] == "OK":
                # changes the status of this client's server to chatting
                self.peerServer.isChatRequested = 1
                # sets the server variable with the username of the peer that this one is chatting
                self.peerServer.chattingClientName = self.responseReceived[1]
                # as long as the server status is chatting, this client can send messages
                while self.peerServer.isChatRequested == 1:
                    # message input prompt
                    messageSent = input(self.username + ": ")
                    # sends the message to the connected peer, and logs it
                    self.tcpClientSocket.send(messageSent.encode())
                    logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + messageSent)
                    # if the quit message is sent, then the server status is changed to not chatting
                    # and this is the side that is ending the chat
                    if messageSent == ":q":
                        self.peerServer.isChatRequested = 0
                        self.isEndingChat = True
                        break
                # if peer is not chatting, checks if this is not the ending side
                if self.peerServer.isChatRequested == 0:
                    if not self.isEndingChat:
                        # tries to send a quit message to the connected peer
                        # logs the message and handles the exception
                        try:
                            self.tcpClientSocket.send(":q ending-side".encode())
                            logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> :q")
                        except BrokenPipeError as bpErr:
                            logging.error("BrokenPipeError: {0}".format(bpErr))
                    # closes the socket
                    self.responseReceived = None
                    self.tcpClientSocket.close()
            # if the request is rejected, then changes the server status, sends a reject message to the connected peer's server
            # logs the message and then the socket is closed       
            elif self.responseReceived[0] == "REJECT":
                self.peerServer.isChatRequested = 0
                print("client of requester is closing...")
                self.tcpClientSocket.send("REJECT".encode())
                logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> REJECT")
                self.tcpClientSocket.close()
            # if a busy response is received, closes the socket
            elif self.responseReceived[0] == "BUSY":
                print("Receiver peer is busy")
                self.tcpClientSocket.close()
        # if the client is created with OK message it means that this is the client of receiver side peer
        # so it sends an OK message to the requesting side peer server that it connects and then waits for the user inputs.
        elif self.responseReceived == "OK":
            # server status is changed
            self.peerServer.isChatRequested = 1
            # ok response is sent to the requester side
            okMessage = "OK"
            self.tcpClientSocket.send(okMessage.encode())
            logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + okMessage)
            print("Client with OK message is created... and sending messages")
            # client can send messsages as long as the server status is chatting
            while self.peerServer.isChatRequested == 1:
                # input prompt for user to enter message
                messageSent = input(self.username + ": ")
                self.tcpClientSocket.send(messageSent.encode())
                logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> " + messageSent)
                # if a quit message is sent, server status is changed
                if messageSent == ":q":
                    self.peerServer.isChatRequested = 0
                    self.isEndingChat = True
                    break
            # if server is not chatting, and if this is not the ending side
            # sends a quitting message to the server of the other peer
            # then closes the socket
            if self.peerServer.isChatRequested == 0:
                if not self.isEndingChat:
                    self.tcpClientSocket.send(":q ending-side".encode())
                    logging.info("Send to " + self.ipToConnect + ":" + str(self.portToConnect) + " -> :q")
                self.responseReceived = None
                self.tcpClientSocket.close()
                


class UDPChatRoom:
    def __init__(self, tcpClientSocket, udpPort ,username ,udp_ip):
        self.udpSocket = socket(AF_INET, SOCK_DGRAM)
        self.udpSocket.bind(('', udpPort))
        self.participants = {}  # key: username, value: (IP, port)
        self.tcpClientSocket = tcpClientSocket
        self.currentChatRoom = None
        self.username = username
        self.udp_ip = udp_ip
        # self.udp_port = udpPort
        self.udpPort=udpPort


    def create_chat_room(self):
            chat_room_name = input("Enter the name for the new chat room: ")
            logging.info(f"Attempting to create chat room: {chat_room_name}")
            create_chat_room_message = f"CREATE_CHAT_ROOM {chat_room_name}"
            self.tcpClientSocket.send(create_chat_room_message.encode())

            response = self.tcpClientSocket.recv(1024).decode()
            logging.info(f"Received response from registry: {response}")
            if response == "chat-room-created " + chat_room_name:
                print(f"Chat room '{chat_room_name}' created successfully.")
            elif response == "chat-room-already-exists":
                print(f"A chat room with the name '{chat_room_name}' already exists.")
            else:
                print(f"Failed to create chat room '{chat_room_name}'. Unexpected response from server.")

    def join_chat_room(self):
        chat_room_name = input("Enter the name of the chat room to join: ")
        logging.info(f"Attempting to join chat room: {chat_room_name}")

        # The udp_ip sent here is not used in the response, as the server sends a fixed udp_ip
        join_chat_room_message = f"JOIN_CHAT_ROOM {chat_room_name} {self.username} {self.udp_ip} {self.udpPort}"
        self.tcpClientSocket.send(join_chat_room_message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info(f"Received response from server: {response}")
        try:
            response_parts = response.split(' ', 2)  # Split only on the first two spaces
            if response_parts[0] == "joined-chat-room":
                self.currentChatRoom = response_parts[1]
                if len(response_parts) > 2:  # Check if participant info is provided
                    participants_info = response_parts[2].split(';')
                    for participant in participants_info:
                        username, udp_info = participant.split('@')
                        udp_ip, udp_port = udp_info.split(':')
                        self.add_participant(username, (udp_ip, int(udp_port)))
                else:
                    logging.info("No participants in the chat room.")

            elif response_parts[0].startswith("error-join-chat-room"):
                logging.error(f"Error joining chat room: {response}")
                print(f"Error joining chat room: {response_parts[1]}")
            else:
                raise ValueError("Invalid server response format")
        except ValueError as ve:
            logging.error(f"Error parsing response: {ve}")
            print("Error joining chat room: Invalid server response format.")
        except Exception as e:
            logging.error(f"Error joining chat room: {e}")
            print("An unexpected error occurred while trying to join the chat room.")




    def leave_chat_room(self):
        if not self.currentChatRoom:
            print("You are not currently in any chat room.")
            return
        confirm = input(f"Are you sure you want to leave the chat room '{self.currentChatRoom}'? (yes/no): ")
        if confirm.lower() == 'yes':
            logging.info(f"Attempting to leave chat room: {self.currentChatRoom}")
            leave_chat_room_message = f"LEAVE_CHAT_ROOM {self.currentChatRoom}"
            self.tcpClientSocket.send(leave_chat_room_message.encode())
            try:
                self.tcpClientSocket.settimeout(5.0)
                response = self.tcpClientSocket.recv(1024).decode()
                logging.info(f"Received response from server: {response}")
                if response.startswith("left-chat-room"):
                    print(f"Left chat room '{self.currentChatRoom}' successfully.")
                    self.remove_participant(self.username)
                    self.currentChatRoom = None
                elif response == "failed-leave-chat-room":
                    print(f"Failed to leave chat room '{self.currentChatRoom}'.")
                else:
                    print("Unexpected response from server when trying to leave chat room.")
            except socket.timeout:
                print("Request to leave chat room timed out.")
                logging.error("Timeout occurred while trying to leave chat room.")
            except Exception as e:
                print("An error occurred while trying to leave the chat room.")
                logging.error(f"Error leaving chat room: {e}")
            finally:
                self.tcpClientSocket.settimeout(None)
        else:
            print("Leaving chat room canceled.")


    def handle_chat_room_update(self, message):
        message_parts = message.split()
        message_type = message_parts[0]
        if message_type == "joined-chat-room":
            chat_room_name, joining_peer, udp_info = message_parts[1], message_parts[2], message_parts[3]
            udp_ip, udp_port = udp_info.split(':')
            print(f"{joining_peer} has joined the chat room: {chat_room_name}")
            self.add_participant(joining_peer, (udp_ip, int(udp_port)))
        elif message_type == "left-chat-room":
            chat_room_name, leaving_peer = message_parts[1], message_parts[2]
            print(f"{leaving_peer} has left the chat room: {chat_room_name}")
            self.remove_participant(leaving_peer)

    def add_participant(self, username, addr):
        self.participants[username] = addr
        self.send_message(f"{username} joined the chat room", username)

    def remove_participant(self, username):
        if username in self.participants:
            self.send_message(f"{username} left the chat room", username)
            del self.participants[username]


    def send_message(self, message, sender_username):
        for username, addr in self.participants.items():
            if username != sender_username:
                self.udpSocket.sendto(message.encode(), addr)

    def listen_for_messages(self):
        while True:
            try:
                message, addr = self.udpSocket.recvfrom(1024)
                decoded_message = message.decode()
                print(f"Received message from {addr}: {decoded_message}")

                if ": " in decoded_message:
                    username, content = decoded_message.split(": ", 1)
                    if username in self.participants:
                        self.send_message(decoded_message, username)
                    else:
                        print(f"Message from unknown participant {username}: {content}")
            except Exception as e:
                logging.error(f"Error in listen_for_messages: {e}")
                # Consider breaking the loop or handling the error appropriately

    def start(self):
        listener_thread = threading.Thread(target=self.listen_for_messages)
        listener_thread.daemon = True  # Set as a daemon thread
        listener_thread.start()




# main process of the peer
class peerMain:
    # peer initializations
    def __init__(self):
        # ip address of the registry
        self.registryName = input("Enter IP address of registry: ")
        #self.registryName = 'localhost'
        # port number of the registry
        self.registryPort = 11411
        # tcp socket connection to registry
        self.tcpClientSocket = socket(AF_INET, SOCK_STREAM)
        self.tcpClientSocket.connect((self.registryName,self.registryPort))
        # login info of the peer
        self.loginCredentials = (None, None)
        # online status of the peer
        self.isOnline = False
        # server port number of this peer
        self.peerServerPort = None
        # server of this peer
        self.peerServer = None
        # client of this peer
        self.peerClient = None
        # timer initialization
        self.timer = None
        self.chatRooms = {} 
        self.UDPChatRoom= None

        # Main loop for user interaction
    def run(self):
        choice = "0"
        logging.basicConfig(filename="peer.log", level=logging.INFO)
        while choice != "3":
            choice = input("Choose: \n1. Create account\n2. Login\n3. Logout\n4. Search\n5. Start a chat\n6. Create a chat room\n7. Join a chat room\n8. Leave a chat room\nEnter your choice: ")

            if choice == "1":
                username = input("Enter username: ")
                password = input("Enter password: ")
                self.createAccount(username, password)

            elif choice == "2" and not self.isOnline:
                username = input("Enter username: ")
                password = input("Enter password: ")
                peerServerPort = int(input("Enter a port number for peer server: "))
                peerUDPPort = int(input("Enter a port number for peer UDP communication: "))

                status = self.login(username, password, peerServerPort ,peerUDPPort)
                if status == 1:
                    self.isOnline = True
                    self.loginCredentials = (username, password)
                    self.peerServerPort = peerServerPort
                    self.peerUDPPort=peerUDPPort
                    # Initialize and start the peer server
                    self.peerServer = PeerServer(self.loginCredentials[0], self.peerServerPort)
                    self.peerServer.start()
                   
                    

            elif choice == "3" and self.isOnline:
                self.logout(1)
                self.isOnline = False
                self.loginCredentials = (None, None)
                self.peerServer.isOnline = False
                self.peerServer.tcpServerSocket.close()
                if self.peerClient is not None:
                    self.peerClient.tcpClientSocket.close()
                print("Logged out successfully")

            elif choice == "4" and self.isOnline:
                username = input("Username to be searched: ")
                searchStatus = self.searchUser(username)
                if searchStatus is not None and searchStatus != 0:
                    print(f"IP address of {username} is {searchStatus}")

            elif choice == "5" and self.isOnline:
                self.start_chat()

            elif choice == "6":  
                if self.isOnline:
                    self.UDPChatRoom.create_chat_room()
                else:
                    print("You must be logged in to create a chat room.")


            elif choice == "7" and self.isOnline:
                # Join a chat room
                self.UDPChatRoom.join_chat_room()

            elif choice == "8" and self.isOnline:
                # Leave the current chat room
                if self.UDPChatRoom.currentChatRoom:
                    self.UDPChatRoom.leave_chat_room()
                else:
                    print("You are not currently in any chat room.")

            elif choice == "OK" and self.isOnline:
                okMessage = "OK " + self.loginCredentials[0]
                logging.info(f"Send to {self.peerServer.connectedPeerIP} -> {okMessage}")
                self.peerServer.connectedPeerSocket.send(okMessage.encode())
                self.peerClient = PeerClient(self.peerServer.connectedPeerIP, self.peerServer.connectedPeerPort, self.loginCredentials[0], self.peerServer, "OK")
                self.peerClient.start()
                self.peerClient.join()

            elif choice == "REJECT" and self.isOnline:
                self.peerServer.connectedPeerSocket.send("REJECT".encode())
                self.peerServer.isChatRequested = 0
                logging.info(f"Send to {self.peerServer.connectedPeerIP} -> REJECT")

            elif choice == "CANCEL":
                if self.isOnline and self.timer:
                    self.timer.cancel()
                break
        self.tcpClientSocket.close()

    # account creation function
    def createAccount(self, username, password):
        # join message to create an account is composed and sent to registry
        # if response is success then informs the user for account creation
        # if response is exist then informs the user for account existence
        message = "JOIN " + username + " " + password
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info("Received from " + self.registryName + " -> " + response)
        if response == "join-success":
            print("Account created...")
        elif response == "join-exist":
            print("choose another username or login...")

    # login function
    def login(self, username, password, peerServerPort ,peerUDPPort):

        # Compose a login message including both TCP and UDP details
        message = f"LOGIN {username} {password} {peerServerPort} {peerUDPPort}"
        logging.info(f"Send to {self.registryName}:{self.registryPort} -> {message}")
        self.tcpClientSocket.send(message.encode())

        response = self.tcpClientSocket.recv(1024).decode()
        logging.info(f"Received from {self.registryName} -> {response}")

        if response == "login-success":
            print("Logged in successfully...")
            self.UDPChatRoom = UDPChatRoom(self.tcpClientSocket, peerUDPPort, username, udp_ip=self.registryName) 
            self.UDPChatRoom.start()
            return 1
        elif response == "login-account-not-exist":
            print("Account does not exist...")
            return 0
        elif response == "login-online":
            print("Account is already online...")
            return 2
        elif response == "login-wrong-password":
            print("Wrong password...")
            return 3
    
    def logout(self, option):
        # Check if the user is logged in before attempting to logout
        if self.isOnline:
            # Send logout request with the username if the user is explicitly logging out
            message = "LOGOUT " + self.loginCredentials[0] if option == 1 else "LOGOUT"
            logging.info(f"Send to {self.registryName}:{self.registryPort} -> {message}")
            self.tcpClientSocket.send(message.encode())
            if self.UDPChatRoom and self.UDPChatRoom.currentChatRoom:
                self.UDPChatRoom.leave_chat_room()
        else:
            print("You are not currently logged in.")
        
    # function for searching an online user
    def searchUser(self, username):
        # a search message is composed and sent to registry
        # custom value is returned according to each response
        # to this search message
        message = "SEARCH " + username
        logging.info("Send to " + self.registryName + ":" + str(self.registryPort) + " -> " + message)
        self.tcpClientSocket.send(message.encode())
        response = self.tcpClientSocket.recv(1024).decode().split()
        logging.info("Received from " + self.registryName + " -> " + " ".join(response))
        if response[0] == "search-success":
            print(username + " is found successfully...")
            return response[1]
        elif response[0] == "search-user-not-online":
            print(username + " is not online...")
            return 0
        elif response[0] == "search-user-not-found":
            print(username + " is not found")
            return None
        
#--------------------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------------------------------------
#--------------------------------------------------------------------------------------------------------------------------------

    def start_chat(self):
        # User enters the username of the peer they want to chat with
        target_username = input("Enter the username of the user to start chat: ")
        logging.info(f"Attempting to start chat with {target_username}")
        # Send a CHAT request to the registry server
        chat_request_message = f"CHAT {target_username}"
        self.tcpClientSocket.send(chat_request_message.encode())
        logging.info(f"Sent CHAT request for {target_username} to registry")
        # Wait for a response from the registry server
        response = self.tcpClientSocket.recv(1024).decode()
        logging.info(f"Received response from registry: {response}")
        response_parts = response.split()
        # Check the response and handle accordingly
        if response_parts[0] == "chat-success":
            target_ip, target_port = response_parts[1].split(':')
            logging.info(f"Chat with {target_username} at {target_ip}:{target_port} can be initiated")
            # Create and start a PeerClient instance to connect to the target peer
            print(f"Starting chat with {target_username} at {target_ip}:{target_port}")
            self.peerClient = PeerClient(target_ip, int(target_port), self.loginCredentials[0], self.peerServer, None)
            self.peerClient.start()
            self.peerClient.join()
        elif response_parts[0] == "chat-user-not-online":
            logging.warning(f"{target_username} is not online")
            print(f"{target_username} is not online.")
        else:
            logging.error(f"Failed to start chat with {target_username}")
            print(f"Failed to start chat with {target_username}.")



# peer is started
if __name__ == "__main__":
    main = peerMain()
    main.run() 