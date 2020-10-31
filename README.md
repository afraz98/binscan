# binscan
## Description

Develop an application that reports information about binaries to a file for analysis and retrieval.
This application is responsible for analyzing executable ELF files and storing the information gathered into
a file on disk. Since the information collected could contain sensitive data, any information stored on disk
must be obfuscated/encrypted in some way to prevent unauthorized access.

## Requirements

(3 pts) The application shall only analyze binaries built in the ELF64 format for an intel architecture.
Files that are not ELF64 files shall not be analyzed beyond identifying that it is not an ELF64 file for an
intel architecture.

The application shall collect and output to STDOUT at least all of the following classes of information
about each binary it analyzes:

2.1. (5 pts) One of the attributes shall a **SHA-1 hash of the file’s .text section.**

2.2. (5 pts) One of the attributes must be the **count of all unique instructions.** The output should be
the instruction and the number of times it appears (e.g., ‘mov, 50’)

2.3. (8 pts) One of the attributes shall be the **Renyi quadratic entropy of the file’s .text section.**

2.4. (8 pts) One of the attributes shall be a **list of external imported functions** by the binary and a
count of the number of calls to each.

2.5. (8 pts) The fifth attribute is developer defined; it should be obvious to the user what the
attribute is. 1

(10 pts) The software shall define and use an **original binary format for persistent storage of data on
disk** (i.e., the stored data must be retrievable across different executions of the software), and the
stored date must include all the data printed to STDOUT.

(8 pts) The software shall **obfuscate or encrypt the file contents on disk** to increase the difficulty of
individuals examining the file contents in the case of a compromise or unauthorized system access.

(2 pts) The software shall provide an **authentication mechanism** prior to retrieving and displaying
information from the binary file.

(8 pts) The software shall be able to **retrieve and display information about previously analyzed
binaries from the data store for a specific user and provide the ability to delete records using an
administrator mode.** That is to say that a valid user should be able to view previously analyzed
binaries from the data store and only a superuser/administrator has the ability to view and remove
any record from the data store.

+ (1 pts) The software shall run on in the Linux bash shell.

+ (1 pts) The software shall use the libelf library for parsing information from ELF files.

+ (1 pts) The software shall use the openssl library for SHA-1 calculation.

+ (1 pts) The software shall use the capstone library for binary disassembly.

(8 pts) The software shall contain at least one intentional software vulnerability that is attackable via
either user input or malformed files.

(10 pts) The software shall contain at least one function written in Intel assembly. This function must
be used functionally as part of your implementation of the requirements. It cannot just be a copy of
the “AddValues” sample function.

+ (1 pts) All functions not provided by the sample source shall be written in C or intel assembly. Note:
command line tools may not be invoked from the application to collect the required attributes. The
software must use original routines or previously specified libraries for collection.

+ (1 pts) The software shall be built for and run on Linux for a 64-bit intel architecture.

+ (1 pts) The software shall compile and run on the class VMs.
