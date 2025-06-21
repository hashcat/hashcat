The Assimilation Bridge in Hashcat is a new feature that allows an attack to be distributed across different hardware platforms. Nowadays, a GPU is usually the most efficient for cracking passwords, but there are also a number of anti-GPU algorithms including Scrypt and Argon. These algorithms are slow on a GPU and relatively fast on a CPU. This proof-of-concept explores the possibility of splitting the Scrypt and Argon2id algorithms to run them on two different platforms in different physical locations.


Here's how it works: 

There are two software components: Hashcat and hasher (https://github.com/fse-a/hasher)
•	Hashcat is launched on an Ubuntu machine with a GPU. This includes the IP addresses of the CPU computers to be used and the port number on which they listen for connections.
•	On the CPU computer(s), the Java application hasher-1.0.0 is launched, providing the same port number to listen for connections from Hashcat. For Argon2id, it is also important to reserve enough memory with the -Xmx option so that the Java process can handle high memory parameters.

Once Hashcat is started, the passwords are divided into blocks. Each block gets its own bridge unit and its own connection to a CPU computer. Once it starts a password block the first part is calculated on the GPU. The intermediate results are then send to the various CPU computers. They do the 'heavy' middle calculations and send the results back to their bridge unit. Once the last results are in, Hashcat calculates the final part on the GPU and checks to see if the password has been found. If the password is not found, Hashcat will continue on with the next password block.


Various concepts are tested with this: 
•	Sensitive information such as your private hash and dictionaries remain local and are not shared with third parties because only the middle part of the algorithm is run elsewhere. 
•	It creates the ability to use a significant amount of computing capacity in the short term without the need for additional hardware purchase and subsequent maintenance.


Here are two command-line examples which will crack with ‘hashcat’ as password:

Scrypt : ./hashcat -a 3 -m 71100 SCRYPT:32768:8:2:Mzg3MjYzNzYwMzE0NDE=:Fyfhr5Wdqet+eV/PGFkiXs8zqDafM4G4vYqvE/8LkwE= hash?l?l?l --bridge-parameter1=<port-number> --bridge-parameter2=<ip-address> --bridge-parameter3=<workitemcount>

Argon : ./hashcat -a 3 -m 71000 '$argon2id$v=19$m=1048576,t=3,p=3$2XsI78UNmyI=$W+DIZS8IGMaJo+ru2Uhq5GfOUdDP+cXthKlHBCy60fA=' hashc?l?l?l --bridge-parameter1==<port-number> --bridge-parameter2==<ip-address> --bridge-parameter3=<workitemcount> 

hasher : java -Xmx6G -Xms6G -jar hasher-0.0.1-SNAPSHOT.jar <port-number>

For the remote Argon2id bridge, bridge-parameter 3 is important as you can set the workitem count with this. So far we recommend a workitem count that is 2x or 3x the number of available processors in the machine where you are running the hasher application. If you are using the high-memory parameter for Argon2id you also need to use the –Xmx and –Xms parameters. This should be the number of processors x 1GB + 1GB for some other work. The hasher application is intended as proof-of-concept and not for production. Please restart it between sessions if you have any trouble. 
