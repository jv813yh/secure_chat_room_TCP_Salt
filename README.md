# secure_chat_room_TCP_Salt

The program can be compiled using a makefile and they are added .bat files for easy launch for Windows of server and client applications. The server uses the loopback address and listens on port 8080 (The values can change, they are given from the command line when calling both source codes).

The client can exchange secure data with other connected ones
clients. The server provides a chat room service where each client connects to the server
can send and receive data from other connected users. It's used
console window for communication between clients and server. Data is being entered
from the command line interface (CLI), which means that the application demonstrates working with smaller ones
data.

The applications use the external TweetNaCl library to perform cryptography
operations used by the Salt channelv2 protocol to secure transmissions
data and user protection. The program demonstrates the use of cryptography
Salt channelv2 protocol to establish a secure connection between
multiple clients and servers. I use the TCP protocol as the communication channel.

# Runable on Windows and Linux with makefile.
Salt-channel protocol: https://github.com/assaabloy-ppi/salt-channel-c

Cryptographic protection is provided TweetNaCl API: https://github.com/assaabloy-ppi/salt-channel-c/blob/master/src/external/tweetnacl_modified/tweetnacl_modified_wrapper.c

