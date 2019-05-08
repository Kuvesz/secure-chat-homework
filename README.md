# Documentation

This part is about the working prototype of our homework project. You have to remember that this was made in a very short time and is a prototype so probably not all functions will work properly or at all.

## Basic architecture

The basic architecture of the application is server based and as such the user is not expected to trust anyone other than himself/herself and the communication partners. This makes it necessary to encrypt all messages transmittied through the server in a way that makes it impossible to read any sensitive data even if an attacker has access to the server.
The idea behind all this is that the first user that connects generates a key that is used to encrypt all messages between users. This key is then only sent through the server when a new user joins and then only after recieving the public key of the newly connected user and using that to encrypt the key. The public key of the new user is of course public (so it's not sensitive information to send unencrypted) and only the new user can decode anything encrypted with it.

## Identification of users

The very basics of identification is built upon presumed previous knowedlege of the server and all clients (not implemented). This means that all users are supposed to keep a whitelist of all accepted public keys (this public key is differnet to the one used for encryption), these public keys are used only for one thing, signing messages. All parties have one that is unique to them, even the server, which is only important in one case (when the first user joins).

## Message types

We use 3 differnet kinds of messages (ENC means encrypted, after the `-` is the method):
* INI - Used by newly connected users to identify themselvs and get the key used for the rest of the communcation.

![INI](/images/ini.png)

* KEY - Used to send the key used for the communication to the newly connected user.

![KEY](/images/key.png)

* DAT - Most messages are DAT messages, these are the ones that are used for the actual communication.

![DAT](/images/dat.png)

## How it all works

* The first thing that exists by itself is the server awaiting connections, than the first user (Alice) joins and since she doesn't know that she's the first to join sends an INI message to the server which is supposed to forward it to all other participants, but since there are none it sends back an INI message to Alice signed by the server's own public key. From this Alice knows that she's the first and generates the key that will be used for the actual conversations between users.
* After that the next user (Bob) joins and sends an INI message to the server, which forward is to Alice who in turn sends back a KEY message that is encrypted with Bob's public key (recieved in the INI message) and signed by Alice's public key. The KEY message contains the key generated by Alice that is used for the actual communiction.
* If a third user joins the same happens as before but he/she might recieve the key used for the communication from multiple sources as nobody exactly is ever declared as a "master". This is important in case the first user (Alice) leaves, since this way nobody needs to be notified that she left and the communication can continue without her and new users can join it as long as somebody remains online. If not than we start form the very beggining.
* The messages themselves (DAT) are sent encrypted with the key originally generated by the first user and signed by the sender.
We use 512 bit AES cypher and 4096 bit RSA cypher just to be sure. (@Dika, correct me here).

The connection of a new user (that is not the first) looks something like this:

![NEWUSER](/images/newuser.png)

## Installation guide

### Prerequisites
You need to have python and pycryptodome installed, installation instructions for python 3 available here:

[Install Python](https://www.python.org/downloads/)

You can install the pycryptodome library with pip:
> pip install pycryptodome

### Installation

Now you're ready to clone this repository like this:

> git clone https://github.com/Kuvesz/secure-chat-homework.git

And change the directory:

> cd secure-chat-homework

You're all set!

## Basic usage

You should run the server with `python server.py` and from a different terminal or command line window connect to it by startin a client like `python client.py`. You can have as many clients as you like but we only tested with up to 3.
