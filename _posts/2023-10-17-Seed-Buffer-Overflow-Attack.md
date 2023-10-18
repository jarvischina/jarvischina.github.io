---
title: MBuffer Overflow Vulnerability Lab
date: 2023-10-01 9:42:38 +0800
categories: [STUDY, algorithm]
tags: [algorithm]     # TAG names should always be lowercase
---
Operating Systems Security – Project 3

Buffer Overflow Vulnerability Lab

2
![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.001.png)NYIT/VOLUME 1/©2023 IEEE

JJJJJ



Operating Systems Security – Project 4
1. # Introduction
Buffer Overflow occurs when a computer program attempts to write data to a buffer (a type of memory area), but the capacity of the buffer was insufficient to accommodate the written data, resulting in excess data covering the contents of adjacent memory areas. This may cause program exceptions and crashes. Malicious users can exploit this vulnerability to execute malicious code or control programs. In This lab, We will run a program with a buffer overflow leak. We need to develop a solution that utilizes this leak and ultimately obtains root privileges. In addition to attacks, we also need to understand several protection schemes implemented in the operating system to resist buffer overflow attacks.

**The BUF SIZE value for this lab is:  \_12\_.**
1. # Turning off Configuration
   1. ## *Address Space Randomization*
In Ubuntu, we need to disable the Address Space Randomization because The Ubuntu system uses address space randomization to randomize the starting address of the heap and stack. This makes it difficult to guess the exact address to simulate a stack overflow. When setting the value of **'kernel.randomize\_va\_space'**, there are three parameters representing different meanings: 0 means disable ASLR completely; 1 means Partially enabling ASLR, but only randomizing the address space of shared libraries, not the address space of executable files; 2 is to enable ASLR and randomize the address space of executable files, which is the default setting.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.002.png)

1. We use a non-root user to execute the **'sudo sysctl -w kernel.randomize\_va\_space=0'** command.
   1. ## *The StackGuard Protection Scheme.*
The StackGuard Protection Scheme is a technology used to protect software applications from buffer overflow attacks. Its goal is to detect and block attackers' attempts to insert malicious code on a program's stack or modify function return addresses. In the presence of this protection, buffer overflow attacks will not work. We can disable this protection during the compilation using the **'-fno-stack-protector'** option.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.003.png)

1. We use the **'-fno-stack-protector'** option to disable StackGuard.
   1. ## *Non-Executable Stack*
Non-Executable Stack is used to ensure that the stack memory area is non-executable code. Using it reduces the possibility of an attacker exploiting a buffer overflow vulnerability to execute malicious code. When a stack is marked "non-executable," even if an attacker successfully overflows the buffer, he or she cannot execute code directly on the stack. By default, the stack is set to non-executable. To change this, we need to use the following options when compiling the program: For executable stack, we use **'-z execstack'**; For non-executable stack, we use **'-z execstack'**.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.004.png)

1. We use the **'-z execstack'** option to disable Non-Executable Stack.

1. ## *Configuring /bin/sh (Ubuntu 16.04 VM only)*
In Ubuntu 16.04 virtual machine, the symbolic link of **'/bin/sh'** points to **'/bin/dash'**, but **'/bin/dash'** has a security mechanism. When it detects that it is executing in the Set-UID process, it immediately drops privileges and changes the valid user ID to the actual user ID of the process, so we cannot execute our code in the privileged process. We can use **'sudo ln -sf /bin/zsh /bin/sh'** to avoid dropping privileges. It creates a new symbolic link through the 'ln' command, linking **'/bin/sh'** to **'/bin/zsh'**, thereby redirecting **'/bin/sh'** to **'/bin/zsh'**. This will not trigger the dropping of privileges for **'/bin/dash'**.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.005.png)

1. We use the **'sudo ln -sf /bin/zsh /bin/sh'** to avoid dropping privileges.

Here are three questions
1) ### *As my environment is an Amazon cloud server, **gcc** is not installed by default. We need to install **gcc** before compiling C files. The specific commands are as follows.*
**$ sudo apt-get install software properties common python software properties**

**$ sudo add opt repository ppa: ubuntu toolchain r/test**

**$ sudo apt get update**

**$ sudo apt-get install gcc-7**

**$ gcc - v**

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.006.png)

1. Install **gcc**.
   1) ### *We pointed '**/bin/sh'** to **'/bin/zsh'**, but **zsh** is not installed by default, so we need to use the command to install **zsh**.*
**$ sudo apt update**

**$ sudo apt install zsh**

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.007.png)

1. Install **zsh**, and we find **sh->/bin/zsh**.
   1) ### *After our experiment is over, we should remember to change the link to **'/bin/sh'** back. We use the following command.*
**$ sudo ln -sf /bin/dash /bin/sh**
1. # Task1: Running Shellcode
   1. ## *What is the Shellcode.*
Shellcode is a special computer program that can complete some system calls, usually written as binary code. It performs different execution operations based on different tasks, with the main purpose of exploiting system vulnerabilities or vulnerabilities to obtain a high-privileged shell and then gain control of the target machine. 

In Figure 7, we can see a case of testshellcode. We use **'gcc - z execstack - o testshellcode testshellcode.c'** to compile this code and then execute the following command. As shown in Figure 8, we can observe that after the command is executed, the current user can obtain the root shell. (The original experimental code is missing **# include<unistd. h>**, so I added it directly here, Otherwise, the compilation will not pass. I won't do screenshots here.)

**$ sudo chown root testshellcode**

**$ sudo chmod 4755 testshellcode**

**$ ./testshellcode** 

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.008.png)

1. testshellcode.c

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.009.png)

1. get root shell.

In Figure 9, we can see a shell code. The main function of the shellcode is to execute the execve() system call to execute  **'/bin/sh'**.

Firstly, the third instruction pushes **'//sh'** instead of **'/sh'** onto the stack. This is because we need a 32-bit number here, while **'/sh'** only has 24 bits. Fortunately, **'//'** is equivalent to **'/'**, so we can avoid using double slashes.

Secondly, before calling the **execve()**, we need to store name [0] (the address of the string), name (the address of the array), and '**NULL'** in the **'%ebx'**, **'%ecx'**, and **'%edx'** registers, respectively. Line 5 stores name [0] in **'%ebx'**; Line 8 stores the name in **'%ecx'**; Set **'%edx'** to zero in line 9. There are other methods to set **'%edx'** to zero (e.g., **xorl %edx, %edx**); The **'cdq'** used here is just a shorter instruction: it copies the sign (31st bit) of the value in the EAX register (now 0) to each bit position in the EDX register, basically setting **'%edx'** to 0.

Thirdly, when we set **'%al'** to 11 and execute **'int $0x80'**, the system call **execve()** is executed.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.010.png)

1. call\_shellcode.c

In this section, as the originally provided code is 32-bit, we need to update Linux to position 32 and install Linux installation support in advance. We need to use the following command.

**$ sudo apt get update**

**$ sudo apt get install lib32z1 libc6 dev i386**

**$ sudo apt get install lib32readline6 dev**

**$ linux32**

**$ /bin/bash**

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.011.png)

1. We execute **'gcc -m32 -g -z execstack -o call\_shellcode2 call\_shellcode.c'**, and compile to generate an executable file, we found that we called  **'/bin/sh'**.
   1. ## *The Vulnerable Program.*
The following code first reads the input from a file named **badfile**, and then passes this input to another buffer in the function **bof()**. The maximum length of the original input is 517 bytes, but the buffer in **bof()** is only 12 bytes, which is less than 517. Due to strcpy() not checking boundaries, a buffer overflow may occur.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.012.png)

1. We modify the BUF\_SIZE to 240, and we create a badfile, which is empty.

According to the previous requirements, we need to turn off StackGuard protection and make the stack executable, so we use the **'-fno-stack-protector'** and **'-z execstack'** options. The command is **'gcc -m32 -g -o stack -z execstack -fno-stack-protector stack.c'**. In addition, we also need to set the Set\_UID, similar to project3, which sets the program to Set\_UID program; the valid user is root. Then, we can see that the stack executable file has been successfully generated, and the valid user is root.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.013.png)

1. We compared the two execution results and found that they were consistent. Because the badfile file is empty.
1. # Task 2: Exploiting the Vulnerability
There is a piece of code here, and we need to complete the rest of it marked in red. When the implementation of the exploit is complete, the code will be placed at the end of the stack. In the main method, the **memset** function is used to initialize the buffer buffer to a 517-byte NOP (NoOperation) instruction (0x90). The NOP instruction is usually used as a placeholder to fill the buffer. When the NOP instruction is executed, it will have no effect and move to the next instruction. We need to fill the buffer to trigger the vulnerability. This requires us to write the shell code into the buffer. The size of the buffer is related to the size of the overflow in the vulnerable program and the size of the buffer. The file pointers used to create badfile are the same size.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.014.png)

1. We need to complete the **'exploit.c'**.

We can load the shellcode into the badfile, but it won't be executed because our instruction pointer won't point to it. One thing we can do is change the return address to point to the shellcode. So we need to do a few things:

(1) Find the address of the current buffer in **'stack.c'**.

(2) Find the return address.

(2) Write malicious code into badfile.

(3) Modify the memory location of the return address to our malicious code address. But this step is difficult. We can't calculate the address exactly, but we can guess. To increase the chance of success, we add some NOPs at the beginning of the malicious code; so if we can jump to any of these NOPs and then execute the next instruction sequentially, we can eventually find the malicious code.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.015.png)

1. Stack overflow attack.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.016.png)

1. Badfile.

In order to know the return address and buffer address, we use GDB to disassemble the program to know where the return address is assigned to write the code.

First, we need to install gdb and **peda**. **peda** is a visual tool that can make memory debugging look more friendly. Below are the commands.

**git clone https://github.com/longld/peda.git ~/peda**

**echo "source ~/peda/peda.py" >> ~/.gdbinit**

**echo "DONE! debug your program with gdb and enjoy"**

Then, we use the following command to perform gdb debugging on the stack. Set a breakpoint at the **bof** function, and run to the breakpoint.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.017.png)

1. Set a breakpoint at the bof function, and run the code.

We check the addresses of the buffer and **ebp** registers at this time. Since the function has just entered, as shown in Figure 14, the return address of the function stored in the previous stack frame is at the current location. The stack frame base address + 4 (the 32-bit system is 4 bytes) is the position of the stack frame, which is the current **ebp** register + 4.

We get the address of **$ebp** as **0xffffd3a8**, and the return address is **0xffffd3a8+4**, which is equal to **0xffffd3ac**. The address of the buffer is **0xffffd394**. We subtract the address of the buffer from the return address to get the data length that the buffer needs to construct to accurately cover the return address. That is the distance length in Figure 15. After calculation, **0xffffd394-0xffffd3ac=0x18** is obtained (in Figure 17). That is 24 in Decimal 10. So we got the distance of 24, so we still use x90 to represent the first 24 of the badfile. That is

**strcpy(buffer,"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\ x90\x90\x??\x??\x??\x??");**

Bits 25-28 need to be replaced with our malicious code address. We also need to add code to **'exploit.c'** and write the shellcode to the buffer+250 position. This is done because we can fill the previous byte bits with nop to improve the success rate of guessing. In this way, even if the address of the malicious code is not obtained, the NOP can still be hit, and our malicious code can be executed. So the code is as follows **strcpy(buffer + 250, shellcode);**

We also need to calculate the 25-28 bit address; that is, just add 250 to our initial buffer address. After calculation, we get **0xffffd394+250=0xffffd48e**(in Figure 17). This **0xffffd48e** address is the 25-28 bit address we need to replace. Note that the writing order is reversed. That is the following code:

**strcpy(buffer,"\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\x90\ x90\x90\x8e\xd4\xff\xff");**

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.018.png)

1. In gdb, we use p &buffer; p $ebp; p 0xffffd3ac-0xffffd394 to get the address.

We can see that, as shown in Figure 18, I have drawn the corresponding stack address, as well as the return address and the address of the malicious code.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.019.png)

1. Stack address.

Then, we need to modify the **'exploit.c'** program, as shown in Figure 19, by adding two lines. Then, we compile the exploit. c program and use the **'gcc -m32 -o exploit exploit.c'** command. First, let's run the attack command **'./exploit'**. We can view our badfile, which has already been written to some addresses and corresponding malicious code (In Figure 19). 

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.020.png)

1. Update the code of exploit.c, use vi command.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.021.png)

1. Compile and execute the attack code.

At last, we run the vulnerability program **'./stack'** again and observe the results.

Bingo, we obtained root privileges through an attack!

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.022.png)

1. We get the root shell.

1. # Task 3: Defeating dash’s Countermeasure
**'/bin/dash'** fixed the issue with **'zsh'**, which automatically downgrades when the root user is inconsistent with the owner, but we can still attack it. We can invoke another shell program. This approach requires another shell program, such as **'zsh'**, to be present in the system. Another approach is to change the real user ID of the victim process to zero before invoking the dash program. We can achieve this by invoking **setuid(0)** before executing **execve()** in the shellcode. In this task, we will use this approach. We will first change the **'/bin/sh'** symbolic link so it points back to **'/bin/dash'**. The required commands are shown below:

**sudo ln -sf /bin/dash /bin/sh**

We create **'dash\_shell\_test.c'** files and **'dash\_shell\_testuid0.c'** files, and the content of the code is shown in Figures 22 and 23. The only difference between them is that they have an additional line of code, **'setuid (0)'**. Then, we compile **'dash\_shell\_test.c'** and **'dash\_shell\_testuid0.c'** separately and give them root ownership. The required commands are shown below:

**$ gcc dash\_shell\_test.c -o dash\_shell\_test**

**$ sudo chown root dash\_shell\_test**

**$ sudo chmod 4755 dash\_shell\_test**

**$ gcc dash\_shell\_testuid0.c -o dash\_shell\_testuid0**

**$ sudo chown root dash\_shell\_testuid0**

**$ sudo chmod 4755 dash\_shell\_testuid0**

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.023.png)

1. Create and execute the 'dash\_shell\_test.c'.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.024.png)

1. Create and execute the dash\_shell\_testuid0.c

We can see **'./dash\_shell\_testuid0'** still obtained root privileges because the **setuid (0)** function is used to set the valid user ID of the current process to 0, which is the user ID of the root.

Due to a change in the direction of the **'/bin/sh'** instruction, we need to execute **'./stack'**, and we won't be able to get root anymore. We can see the results in Figure 24.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.025.png)

1. We can't get the root shell.

Now, we need to update the **'exploit.c'** file. Add some instructions to attack again.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.026.png)

1. Update the **'exploit.c'** file for the dash attack

The updated shellcode adds four instructions: 

(1) set **ebx** to zero in Line 2, 

(2) set eax to **0xd5** via Line 1 and 3 (**0xd5** is setuid()'s system call number) 

(3) execute the system call in Line 4. 

Using this shellcode, we can attempt the attack on the vulnerable program when **'/bin/sh'** is linked to **'/bin/dash'**.After we complete the modifications, we need to use the same 32-bit command, **'gcc -m32 -o exploit exploit.c'** to compile and then execute stack after compiling. We can see that the result is consistent with the execution result of **'./dash\_shell\_testuid0'**, obtaining the root shell. The above process is shown in Figures 26 and 27.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.027.png)

1. We use **'gcc -m32 -o exploit exploit.c'** to compile and we can see the badfile.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.028.png)

1. The result is that we have obtained the root shell.
1. # Task4: Defeating Address Randomization
Due to the use of Linux 32-bit systems, the base address space of the stack is only 2^19 times, which is not that large. And it is easy to execute. This means that we can engage in violent attacks. Even if ASLR technology for address space layout randomization is enabled at this time, the attack can still be completed within a certain amount of time. Because it only needs to be executed 524,288 times.

Firstly, we need to open the address space randomization technology ASLR. We use the **'sudo /sbin/sysctl -w kernel.randomize\_va\_space=2'**,** as shown in Figure 28. 

Then, executing the **'./stack'**, we found an error and were unable to obtain the root shell. This error, **'Segmentation fault (core dumped)'** indicates that our program attempted to access a memory segment that was not allocated to it.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.029.png)

1. The result is that we have obtained the root shell.

Finally, We create **'attack.sh'** file and edit it to include the code from Figure 30. Then, execute this violent method to repeatedly attack the stack. If the attack is successful, the script will stop; Otherwise, it will continue to run.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.030.png)

1. Create **'attack.sh'** to attack the **'stack'** 

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.031.png)

1. Loop attack script.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.032.png)

1. Loop attack success.

In Figure 31, we found that we can continue to increase permissions through the **setuid** function and obtain the true root permission shell after 39 minutes.

This also means that in the case of randomization of address space layout, using brute force cracking can successfully attack!
1. # Task 5: Turn on the StackGuard Protection
Before completing this task, we must first turn off address randomization. Otherwise, we will not know which measures protect our code from being attacked. In the previous task, we disabled the StackGuard protection mechanism in GCC when compiling the program. But in this task, we need to recompile the program **'stack.c'** with StackGuard turned on. So we need to execute the following command to recompile: **'gcc -m32 -g -o stack2 -z execstack stack.c'**. We do not use the **-fno-stack-protector** option.

Tips: In GCC version 4.3.3 and above, StackGuard is enabled by default. Therefore, you have to disable StackGuard using the switch mentioned before. In earlier versions, it was disabled by default. If you use an older GCC version, you may not have to disable StackGuard.

We don't need be concerned about it, our gcc version is greater than 4.3.3.

The result is in Figure 32. Due to Stackguard, our code execution failed, and we could not obtain the root shell normally. This is because of StackGuard's protection. StackGuard improves security by modifying the stack layout. It inserts a canary value in the middle of the stack frame. When we overwrite the return address, StackGuard checks if the canary value has been modified. If the sentinel value is modified, indicating that a stack overflow has occurred, StackGuard will start protection and terminate the execution of malicious code.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.033.png)

1. Turn on the StackGuard Protection, we can not get the root shell.
1. # Task 6: Turn on the Non-executable Stack Protection
Non-executable Stack Protection, also known as NX bit, represents the **no-executable** feature in the CPU, which separates code from data marked as **non-executable** memory areas. (It can use a different technique called **return-to-libc** attack to defeat this protection).

Before completing this task, we must first turn off address randomization, otherwise, we will not know which measures protect our code from being attached.

In this task, we need to recompile the stack using the following command:

**'gcc -m32 -g -o stack3 -fno-stack-protector -z noexecstack stack.c'**

In Figure 33, we run **'./stack3 again'**, and the result is very obvious, which is **'Segmentation fault'**. The reason for this issue is that we canceled the executable of the stack, and the code we wrote to the return value address was not executed, so we were unable to obtain the root shell again.

![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.034.png)

1. Non-executable Stack Protection: we get a **'Segmentation fault'**, and we can not get the root shell.
##### Conclusion
Through Seed's buffer overflow experiment, we have learned some basic principles and risks in the field of computer security. In the daily work of writing programs, we need to handle privilege permissions and stack overflow vulnerabilities very carefully to ensure system security. Here are my thoughts:

1) Be cautious when using the **strcpy** method, as this may cause buffer overflow and allow the program to run malicious code.
1) Setuid is very powerful, but the incorrect configuration of Setuid permissions may lead to potential security vulnerabilities. We need to use them carefully because **'/bin/dash'** may also be attacked by malicious code.
1) Address Space Layout Randomization, StackGuard protection, and stack non-executable can all prevent buffer overflow attacks to some extent, but Address Space Layout Randomization protection is not very good because brute force cracking can attack it, allowing us to obtain the root shell.

##### References

1. Wenliang Du. (2020). Computer & Internet Security: A Hands-on Approach.
13
![](/assets/img/20231017/Aspose.Words.a8819b46-3772-44f4-820f-6783b858ab15.035.png)NYIT/VOLUME 1/©2023 IEEE
