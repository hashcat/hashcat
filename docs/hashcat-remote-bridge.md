The Assimilation Bridge in Hashcat is a new feature that allows an attack to be distributed across different hardware platforms. This proof-of-concept explores the possibility of splitting the Argon2id algorithm to run them on two different platforms in different physical locations.

Here's how it works: 

There are two software components: Hashcat and legion (https://github.com/fse-a/legion)
•	Hashcat is launched on an Ubuntu machine with a GPU. This includes the IP addresses of the remote GPU computers to be used and the port number on which they listen for connections. e.g 1.1.1.1:80
•	On the GPU computer(s), the Java application legion is launched, providing the same port number to listen for connections from Hashcat. For Argon2id, it is also important to reserve enough memory with the -Xmx option so that the Java process can handle high memory parameters.

Once Hashcat is started, the passwords are divided into blocks. Each block gets its own bridge unit and its own connection to a GPU computer. Once it starts a password block the first part is calculated on the Hashcat computer. The intermediate results are then send to the various GPU computers. They do the 'heavy' middle calculations and send the results back to their bridge unit. Once the last results are in, Hashcat calculates the final part and checks to see if the password has been found. If the password is not found, Hashcat will continue on with the next password block. 

Various concepts are tested with this: 
•	Sensitive information such as your private hash and dictionaries remain local and are not shared with third parties because only the middle part of the algorithm is run elsewhere. 
•	It creates the ability to use a significant amount of computing capacity in the short term without the need for additional hardware purchase and subsequent maintenance.


Here is a command-line examples which will crack with ‘hashcat’ as password:

hashcat : ./hashcat -a 3 -m 75000 '$argon2id$v=19$m=1048576,t=3,p=3$2XsI78UNmyI=$W+DIZS8IGMaJo+ru2Uhq5GfOUdDP+cXthKlHBCy60fA=' hashc?l?l --bridge-parameter1=<ip-addres:port-number>

legion : java -Xmx6G -Xms6G --enable-native-access=ALL-UNNAMED -jar legion.jar <port-number>

The legion application is intended as proof-of-concept and not for production. Please restart it between sessions if you have any trouble.