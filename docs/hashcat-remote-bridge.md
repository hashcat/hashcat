The Assimilation Bridge in Hashcat is a new feature that allows an attack to be distributed across different hardware platforms. This proof-of-concept explores the possibility of splitting the Argon2id algorithm to run them on two different platforms in different physical locations.

Here's how it works:

There are two software components: Hashcat and legion (https://github.com/fse-a/legion)
* Hashcat is launched on an Ubuntu machine with a GPU. This includes the IP addresses of the remote GPU computers to be used and the port number on which they listen for connections. e.g 1.1.1.1:80
* On the GPU computer(s), the Java application legion is launched, providing the same port number to listen for connections from Hashcat. For Argon2id, it is also important to reserve enough memory with the -Xmx option so that the Java process can handle high memory parameters.

Once Hashcat is started, it connects to the remote computers and receives information regarding the number and type of GPUs available at the remote (the 'unit class' string). Next, the passwords are divided into blocks. Each block gets its own bridge unit and its own connection to a GPU computer. Once it starts a password block the first part is calculated on the Hashcat computer. The intermediate results are then send to the various GPU computers. They do the 'heavy' middle calculations and send the results back to their bridge unit. Once the last results are in, Hashcat calculates the final part and checks to see if the password has been found. If the password is not found, Hashcat will continue on with the next password block.

Various concepts are tested with this: 
* Sensitive information such as your private hash, salt and dictionaries remain local and are not shared with third parties because only the middle part of the algorithm is run elsewhere.
* Note that if the private hash and salt were to be compromised, it would provide an attacker recovery of the password at Blake2b speed.
* It creates the ability to use a significant amount of computing capacity in the short term without the need for additional hardware purchase and subsequent maintenance.

Note: The remote bridge plugin is provided solely as a proof of concept (PoC) for experimentation and learning. It has only been tested on Windows and Linux (Ubuntu).

Here is a command-line example which will crack with 'hashcat' as password:

hashcat : ./hashcat -a 3 -m 76000 '$argon2id$v=19$m=1048576,t=3,p=3$2XsI78UNmyI=$W+DIZS8IGMaJo+ru2Uhq5GfOUdDP+cXthKlHBCy60fA=' hashc?l?l --bridge-parameter1=<ip-addres:port-number>

legion : java -Xmx6G -Xms6G --enable-native-access=ALL-UNNAMED -jar legion.jar <port-number>

Network protocol description

Hashcat initiates a TCP connection to each configured Legion Java worker over IPv4. The custom, unencrypted binary protocol then proceeds as follows:

1. Handshake: The Legion worker sends a length-prefixed unit-class string identifying its compute capability.
2. Configuration: Hashcat sends the hash mode and Argon2id parameters as 32-bit network-byte-order integers. The worker responds with its preferred chunk size for these parameters.
3. Work submission: Hashcat sends the candidate count, intermediate Argon2id state blocks, and a MD5 checksum of these state blocks. The number of blocks sent depends on the parallelism and the number of candidates (2 x parallelism x candidate count) Each block is 1024 bytes.
4. Result retrieval: The worker returns the processed state blocks and an MD5 checksum. The number of blocks that are returned is the number of candidates. Hashcat verifies the checksum and completes the computation locally. A zero candidate count signals shutdown.

Security considerations: The protocol provides no encryption, peer authentication, or cryptographic transport integrity. The MD5 checksums detect accidental truncation or corruption. Use a trusted network or an encrypted tunnel (e.g., SSH) when communicating across untrusted networks.