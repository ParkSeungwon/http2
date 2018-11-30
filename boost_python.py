
# coding: utf-8

# In[1]:


from tls_crypt import *

def str2list(s) :
    r = []
    for c in s: r.append(ord(c))
    return r

def add_padding(l):
    padding = 15 - len(l) % 16
    for i in range(padding + 1): l.append(padding)
    return l

def remove_padding(l):
    padding = l[-1] + 1
    for i in range(padding): l.pop()
    return l

def list2str(l) :
    r = ''
    for c in l: r += chr(c)
    return r

def hex2list(s):
    assert len(s) % 16 == 0
    l = []
    str = ''
    for c in s:
        str += c
        if len(str) == 2:
            l.append(int(str, 16))
            str = ''
    return l

aes = AES()
client_key = 0x231a650ecfc578bea4b0467adaab33c2
server_key = 0x45ec5fe99527a6f2c9c3889fcd2e65c1
msg = '1400000c48037b71499792961515c436f4c6330f8748593625435272724d39632cdf4c060b0b0b0b0b0b0b0b0b0b0b0b'
iv = 0x4c63014c671a8bae25b22def0f57ce79
aes.key(server_key)
aes.iv(iv)
enc = aes.encrypt(hex2list(msg))
print enc
dec = aes.decrypt(enc)
print dec
#'e4228485b936b34af05bcb0e3aabd962206ad5f954708a1c901106dd9dd05de44408a5b9d376a437c399d144cc80990c'
#print hexdump(s)


# <h2>AES</h2>

# In[2]:


s = 'hello world'
print s
s = str2list(s)
print s
add_padding(s)
print s
s = aes.encrypt(s)#should be multiple of 16
print s

s = aes.decrypt(s)
print s
remove_padding(s)
print s
s = list2str(s)
print s


# <h2>Base64</h2>

# In[3]:


s = 'message to encode'
print s
s = str2list(s)
print s
s = base64_encode(s)
print s
s = base64_decode(s)
print s
s = list2str(s)
print s


# <h2>SHA hash & pem file read</h2>

# In[4]:


sha = SHA1()
print sha.hash(str2list(s))
sha = SHA256()
print sha.hash(str2list(s))
sha = SHA512()
print sha.hash(str2list(s))
mac = HMAC()
mac.key(str2list(s))
print mac.hash(str2list(s))
jv = eval (pem2json('../dndd2/cert.pem'))
print jv


# In[10]:


prf = PRF()
prf.label('client finished')
prf.seed(str2list(s))
prf.secret(str2list(s))
print [i for i in prf.get_n_byte(40)]

