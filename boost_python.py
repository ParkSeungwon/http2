#!/usr/bin/python
# coding: utf-8

# In[1]:


from tls_crypt import *


# In[2]:


aes = AES()


# In[3]:


sha = SHA256()


# In[4]:


print sha.hash([123,245,111,121])


# In[5]:


aes.key(0x12345678912345678)


# In[6]:


aes.iv(long(0x123456789))


# In[7]:


print aes.show()


# In[8]:


enc = aes.encrypt([12,23,45,4,5,6,7,8,9,0,1,2,3,4,5,6])
print enc


# In[9]:


print aes.decrypt(enc)


# In[10]:


print base64_decode('fdsafas')


# In[11]:


print base64_decode('fdaf')


# In[12]:


print base64_encode([125,214,159,12,21])


# In[13]:


jv = eval (pem2json('../dndd2/cert.pem'))


# In[14]:


print jv

