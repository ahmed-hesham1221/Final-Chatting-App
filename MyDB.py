import logging
import hashlib
import os
from pymongo import MongoClient
from pymongo.errors import ServerSelectionTimeoutError
import datetime
import socket



class DB:
    def __init__(self, connection_string='mongodb+srv://AhmedsDB:ahmed1@cluster0.pyefwwr.mongodb.net/?retryWrites=true&w=majority', db_name='MyApp'):
        self.client = MongoClient(connection_string)
        self.db = self.client[db_name]

    def is_connection_working(self):
        try:
            self.client.server_info()
            logging.info("Connection to the database is working")
            return True
        except ServerSelectionTimeoutError:
            logging.error("Connection to the database is not working.")
            return False

    def is_account_exist(self, username):
        count = self.db.accounts.count_documents({'username': username})
        return count > 0

    def register(self, username, password):
        if self.is_account_exist(username):
            return False

        salt = os.urandom(16)
        hashed_password = hashlib.sha256(salt + password.encode()).hexdigest()
        account = {'username': username, 'password': hashed_password, 'salt': salt, 'online': False}
        self.db.accounts.insert_one(account)
        return True

    def validate_login(self, username, password):
        user = self.db.accounts.find_one({"username": username})
        if user:
            hashed_password = hashlib.sha256(user["salt"] + password.encode()).hexdigest()
            return hashed_password == user["password"]
        return False
    
    def authenticate_user(self, username, password):
        """
        Authenticate a user by verifying their username and password.
        Returns True if the user is authenticated, False otherwise.
        """
        # First, check if the account exists
        if not self.is_account_exist(username):
            logging.info(f"Authentication failed: User {username} does not exist.")
            return False

        # Validate the login credentials
        if self.validate_login(username, password):
            logging.info(f"User {username} successfully authenticated.")
            return True
        else:
            logging.info(f"Authentication failed: Incorrect password for user {username}.")
            return False
    
    
    # def user_login(self, username, ip, port):
    #     try:
    #         # Update the user's TCP and UDP address in a single operation
    #         self.db.accounts.update_one(
    #             {'username': username},
    #             {'$set': {'online': True, 'ip': ip, 'port': port}}
    #         )
    #         logging.info(f"User {username} logged in with UDP address and marked as online.")
    #     except Exception as e:
    #         logging.error(f"Error in user_login: {e}")
        

    def user_login(self, username, ip, tcp_port, udp_port):
        try:
            # Update the user's online status, IP, TCP port, and UDP port
            self.db.accounts.update_one(
                {'username': username},
                {'$set': {
                    'online': True, 
                    'ip': ip, 
                    'tcp_port': tcp_port, 
                    'udp_port': udp_port
                }}
            )
            logging.info(f"User {username} logged in with IP: {ip}, TCP port: {tcp_port}, UDP port: {udp_port} and marked as online.")
        except Exception as e:
            logging.error(f"Error in user_login: {e}")


    # def user_logout(self, username):
    #     try:
    #         # Clear only the TCP address and mark the user as offline
    #         self.db.accounts.update_one(
    #             {'username': username},
    #             {'$set': {'online': False, 'ip': None, 'port': None}}
    #         )
    #         logging.info(f"User {username} logged out and marked as offline.")
    #     except Exception as e:
    #         logging.error(f"Error in user_logout: {e}")
            


    def user_logout(self, username):
        try:
            # Clear the online status, IP, TCP port, and UDP port
            self.db.accounts.update_one(
                {'username': username},
                {'$set': {
                    'online': False, 
                    'ip': None, 
                    'tcp_port': None, 
                    'udp_port': None
                }}
            )
            logging.info(f"User {username} logged out, IP and port information cleared, and marked as offline.")
        except Exception as e:
            logging.error(f"Error in user_logout: {e}")


    def get_peer_addresses(self, username):
        """ Retrieve  TCP  IP and port of an online user """
        try:
            user = self.db.accounts.find_one({'username': username, 'online': True}, {'ip': 1, 'port': 1})
            if user:
                return {'tcp_ip': user['ip'], 'tcp_port': user['port']}
            else:
                return None
        except Exception as e:
            logging.error(f"Error in get_peer_addresses: {e}")
            return None



    def is_account_online(self, username):
        """ Check if a user is currently online """
        try:
            user = self.db.accounts.find_one({'username': username}, {'online': 1})
            return user and user.get('online', False)
        except Exception as e:
            logging.error(f"Error in is_account_online: {e}")
            return False
        

    def create_chat_room(self, chat_room_name, creator_username):
        if self.db.chat_rooms.count_documents({'name': chat_room_name}) > 0:
            logging.info(f"Chat room '{chat_room_name}' already exists.")
            return False

        chat_room = {
            'name': chat_room_name,
            'creator': creator_username,
            'members': [{'username': creator_username}]
        }
        self.db.chat_rooms.insert_one(chat_room)
        logging.info(f"Chat room '{chat_room_name}' created successfully.")
        return True
    

    def add_to_chat_room(self, chat_room_name, username, udp_ip, udp_port):
        try:
            udp_port = int(udp_port)

            # Prepare the member information
            member_info = {'username': username, 'udp_ip': udp_ip, 'udp_port': udp_port}

            # Add the user with their UDP details to the chat room's members list
            self.db.chat_rooms.update_one(
                {'name': chat_room_name},
                {'$addToSet': {'members': member_info}}
            )
            logging.info(f"User {username} with UDP IP {udp_ip} and port {udp_port} added to chat room '{chat_room_name}'.")
            return True
        except Exception as e:
            logging.error(f"Error in add_to_chat_room: {e}")
            return False

        

    def remove_from_chat_room(self, chat_room_name, username):
        try:
            # Remove the user from the chat room's members list
            self.db.chat_rooms.update_one(
                {'name': chat_room_name},
                {'$pull': {'members': username}}
            )
            logging.info(f"User {username} removed from chat room '{chat_room_name}'.")
            return True
        except Exception as e:
            logging.error(f"Error in remove_from_chat_room: {e}")
            return False
        

    def get_chat_room_participants(self, chat_room_name):
        try:
            chat_room = self.db.chat_rooms.find_one({'name': chat_room_name}, {'_id': 0, 'members': 1})
            if chat_room and 'members' in chat_room:
                participants = [
                    {**member, 'udp_port': int(member.get('udp_port', 0))}
                    for member in chat_room['members']
                ]
                return participants
            else:
                logging.info(f"No participants found for chat room '{chat_room_name}' or chat room does not exist.")
                return []
        except Exception as e:
            logging.error(f"Error in get_chat_room_participants: {e}")
            return []





    

    def post_message(self, room_name, message, peer_id):
        """
        Post a message in a chat room.
        """
        try:
            self.db.messages.insert_one({
                'room_name': room_name, 
                'message': message, 
                'sender': peer_id, 
                'timestamp': datetime.datetime.utcnow()
            })
            logging.info(f"Message posted in chat room '{room_name}' by peer '{peer_id}'.")
            return True
        except Exception as e:
            logging.error(f"Error posting message in chat room '{room_name}': {e}")
            return False

    def get_messages(self, room_name):
        """
        Retrieve messages from a chat room.
        """
        try:
            messages = list(self.db.messages.find(
                {'room_name': room_name}, 
                {'_id': 0, 'room_name': 0}
            ).sort('timestamp', 1))
            logging.info(f"Retrieved messages from chat room '{room_name}'.")
            return messages
        except Exception as e:
            logging.error(f"Error retrieving messages from chat room '{room_name}': {e}")
            return []


    # def create_chat_room(self):
    #     # Prompt the user for the chat room name
    #     chat_room_name = input("Enter the name for the new chat room: ")
    #     logging.info(f"Attempting to create chat room: {chat_room_name}")
    #     # Send a CREATE_CHAT_ROOM request to the registry server
    #     create_chat_room_message = f"CREATE_CHAT_ROOM {chat_room_name}"
    #     self.tcpClientSocket.send(create_chat_room_message.encode())
    #     # Wait for a response from the registry server
    #     response = self.tcpClientSocket.recv(1024).decode()
    #     logging.info(f"Received response from registry: {response}")
    #     # Inform the user based on the response from the registry
    #     if response == "chat-room-created " + chat_room_name:
    #         print(f"Chat room '{chat_room_name}' created successfully.")
    #     elif response == "chat-room-already-exists":
    #         print(f"A chat room with the name '{chat_room_name}' already exists.")
    #     else:
    #         print(f"Failed to create chat room '{chat_room_name}'. Unexpected response from server.")


# def join_chat_room(self):
    #     chat_room_name = input("Enter the name of the chat room to join: ")
    #     logging.info(f"Attempting to join chat room: {chat_room_name}")
    #     # Include UDP address in the join request
    #     join_chat_room_message = f"JOIN_CHAT_ROOM {chat_room_name}"
    #     self.tcpClientSocket.send(join_chat_room_message.encode())
        
    #     response = self.tcpClientSocket.recv(1024).decode()
    #     logging.info(f"Received response from registry: {response}")
    #     if response.startswith("joined-chat-room"):
    #         print(f"Joined chat room '{chat_room_name}' successfully.")
    #         # Parse and update UDPChatRoom with received participants' info
    #         participants_info = response.split(' ')[1:]  # Assuming the format is "joined-chat-room [participant info]"
    #         for participant in participants_info:
    #             username, udp_info = participant.split('@')
    #             udp_ip, udp_port = udp_info.split(':')
    #             self.udpChatRoom.join_chat_room(username, udp_ip, int(udp_port))
    #         self.currentChatRoom = chat_room_name
    #     elif response == "failed-join-chat-room":
    #         print(f"Failed to join chat room '{chat_room_name}'.")
    #     else:
    #         print(f"Unexpected response from server when trying to join chat room '{chat_room_name}'.")



    # def leave_chat_room(self):
    #     if not self.currentChatRoom:
    #         print("You are not currently in any chat room.")
    #         return
    #     confirm = input(f"Are you sure you want to leave the chat room '{self.currentChatRoom}'? (yes/no): ")
    #     if confirm.lower() == 'yes':
    #         logging.info(f"Attempting to leave chat room: {self.currentChatRoom}")
    #         # Retrieve the local peer's UDP address
    #         local_udp_ip, local_udp_port = self.udp_ip, self.udp_port  # Assuming these are stored in peerMain
    #         try:
    #             # Send a LEAVE_CHAT_ROOM request with UDP info to the registry server
    #             leave_chat_room_message = f"LEAVE_CHAT_ROOM {self.currentChatRoom} {local_udp_ip} {local_udp_port}"
    #             self.tcpClientSocket.send(leave_chat_room_message.encode())
    #             # Set a timeout for response reception
    #             self.tcpClientSocket.settimeout(5.0)
    #             response = self.tcpClientSocket.recv(1024).decode()
    #             logging.info(f"Received response from registry: {response}")
    #             # Handle the response
    #             if response.startswith("left-chat-room"):
    #                 print(f"Left chat room '{self.currentChatRoom}' successfully.")
    #                 # Remove self from local UDPChatRoom state
    #                 self.udpChatRoom.leave_chat_room(self.loginCredentials[0])
    #                 # Update local chat room state
    #                 self.currentChatRoom = None
    #                 if self.currentChatRoom in self.chatRooms:
    #                     self.chatRooms.get(self.currentChatRoom, set()).discard(self.loginCredentials[0])
    #             else:
    #                 print(f"Failed to leave chat room '{self.currentChatRoom}'.")
    #         except socket.timeout:
    #             print("Request to leave chat room timed out.")
    #             logging.error("Timeout occurred while trying to leave chat room.")
    #         except Exception as e:
    #             print("An error occurred while trying to leave the chat room.")
    #             logging.error(f"Error leaving chat room: {e}")
    #         finally:
    #             # Reset the timeout
    #             self.tcpClientSocket.settimeout(None)
    #     else:
    #         print("Leaving chat room canceled.")



    # def handle_chat_room_update(self, message):
    #     message_parts = message.split()
    #     message_type = message_parts[0]
    #     if message_type == "joined-chat-room":
    #         chat_room_name, joining_peer, udp_info = message_parts[1], message_parts[2], message_parts[3]
    #         udp_ip, udp_port = udp_info.split(':')
    #         print(f"{joining_peer} has joined the chat room: {chat_room_name}")
    #         self.udpChatRoom.join_chat_room(joining_peer, udp_ip, int(udp_port))
    #     elif message_type == "left-chat-room":
    #         chat_room_name, leaving_peer = message_parts[1], message_parts[2]
    #         print(f"{leaving_peer} has left the chat room: {chat_room_name}")
    #         self.udpChatRoom.leave_chat_room(leaving_peer)