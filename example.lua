local key = string.rep("O",32)
local nonce = string.rep("O",12)
local msg = "O.O"
local e = chacha20(key,nonce,0,msg)--encrypt the msg
print(e)
local d = chacha20(key,nonce,0,e)--decrypt the ciphertext
print(d)--should be the same
