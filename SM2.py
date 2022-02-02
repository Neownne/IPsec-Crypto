"""
ALi 2017.12.23
for python3
"""

"""
国家密码管理局推荐的曲线参数
椭圆曲线方程:y^2 = x^3+a*x+b
曲线参数:
p=FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFF
a=FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF 00000000 FFFFFFFF FFFFFFFC
b=28E9FA9E 9D9F5E34 4D5A9E4B CF6509A7 F39789F5 15AB8F92 DDBCBD41 4D940E93
n=FFFFFFFE FFFFFFFF FFFFFFFF FFFFFFFF 7203DF6B 21C6052B 53BBF409 39D54123
Gx=32C4AE2C 1F198119 5F990446 6A39C994 8FE30BBF F2660BE1 715A4589 334C74C7
Gy=BC3736A2 F4F6779C 59BDCEE3 6B692153 D0A9877C C62A4740 02DF32E5 2139F0A0
"""
import random
import math

def SM2_Create(a, p, n, G):#SM2密钥对的生成
	d_B = random.randint(1, n-2)
	P_B = SM2_Mulyipoint(d_B, G, a, p)
	return [d_B, P_B]

def SM2_Encrypt(a, b, p, n, G, P_B, M):#加密
	h = int((p**0.5+1)**2/n)
	klen = len(M)*8
	t = '0'
	b = True
	while int(t, 2) == 0:
		k = random.randint(1, n-1)
		C_1 = SM2_Mulyipoint(k, G, a, p)
		C_1 = "00000100"+bin(C_1[0]).replace('0b', '').rjust(256, '0')+bin(C_1[1]).replace('0b', '').rjust(256, '0')
		S = SM2_Mulyipoint(h, P_B, a, p)
		if S == [float('inf'), float('inf')]:
			print("ERROR")
			C = "0000"
			break
		else:
			b = False
			[x_2, y_2] = SM2_Mulyipoint(k, P_B, a, p)
			t = SM2_KDF(bin(x_2).replace('0b', '').rjust(256, '0')+bin(y_2).replace('0b', '').rjust(256, '0'), klen)
	if b == False:
		M = "".join([bin(ord(i)).replace('0b', '').rjust(8, '0') for i in M])
		C_2 = bin(int(M, 2) ^ int(t, 2)).replace('0b', '').rjust(klen, '0')
		C_3 = SM3(bin(x_2).replace('0b', '').rjust(256, '0')+M+bin(y_2).replace('0b', '').rjust(256, '0'))
		C = C_1+C_2+C_3
	return C

def SM2_Decrypt(a, b, p, n, G, d_B, C):#解密
	h = int((p**0.5+1)**2/n)
	klen = len(C)-520-256
	C_1 = C[0:520]
	C_2 = C[520:520+klen]
	C_3 = C[520+klen:776+klen]
	x_1 = int(C_1[8:264], 2)
	y_1 = int(C_1[264:520], 2)
	M = "\0"
	L = y_1**2%p
	R = (x_1**3+a*x_1+b)%p
	if L == R:
		S = SM2_Mulyipoint(h, [x_1, y_1], a, p)
		if S != [float('inf'), float('inf')]:
			[x_2, y_2] = SM2_Mulyipoint(d_B, [x_1, y_1], a, p)
			t = SM2_KDF(bin(x_2).replace('0b', '').rjust(256, '0')+bin(y_2).replace('0b', '').rjust(256, '0'), klen)
			if int(t, 2) != 0:
				M = bin(int(C_2, 2) ^ int(t, 2)).replace('0b', '').rjust(klen, '0')
				u = SM3(bin(x_2).replace('0b', '').rjust(256, '0')+M+bin(y_2).replace('0b', '').rjust(256, '0'))
				if u == C_3:
					M = "".join([chr(i) for i in [int(M[j:j+8], 2) for j in range(0, len(M), 8)]])	
				else:
					print("ERROR")
			else:
				print("ERROR")
		else:
			print("ERROR")
	else:
		print("ERROR")
	return M

def SM2_KDF(Z, klen):#KDF
	c = "00000000000000000000000000000001"
	H = []
	i = 0
	while i < math.ceil(klen/256):
		H.append(SM3(Z+c))
		c = bin((int(c, 2)+1)).replace('0b', '').rjust(32, '0')
		i += 1
	if klen/32-math.ceil(klen/256) == 0:
		H_H = H[math.ceil(klen/256)-1]
	else:
		H_H = H[math.ceil(klen/256)-1][:klen-256*math.floor(klen/256)]
	H.pop()
	K = ""
	i = 0
	while i < len(H):
		K = K+H[i]
		i += 1
	K = K+H_H
	return K

def SM2_Mulyipoint(k, P, a, p):#多倍点运算
	k_b = bin(k).replace('0b', '')#按2^i分层逐层运算
	i = len(k_b)-1
	R = P
	if i > 0:
		k = k-2**i
		while i > 0:
			R = SM2_Pluspoint(R, R, a, p)
			i -= 1
		if k > 0:
			R = SM2_Pluspoint(R, SM2_Mulyipoint(k, P, a, p), a, p)
	return R

def SM2_Pluspoint(P, Q, a, p):#双倍点运算
	if (math.isinf(P[0]) or math.isinf(P[1])) and (~math.isinf(Q[0]) and ~math.isinf(Q[1])):#OP = P
		R = Q
	elif (~math.isinf(P[0]) and ~math.isinf(P[1])) and (math.isinf(Q[0]) or math.isinf(Q[1])):#PO = P
		R = P
	elif (math.isinf(P[0]) or math.isinf(P[1])) and (math.isinf(Q[0]) or math.isinf(Q[1])):#OO = O
		R = [float('inf'), float('inf')]
	else:
		if P != Q:
			l = SM2__Mod_Decimal(Q[1]-P[1], Q[0]-P[0], p)
		else:
			l = SM2__Mod_Decimal(3*P[0]**2+a, 2*P[1], p)
		x = SM2_Mod(l**2-P[0]-Q[0], p)
		y = SM2_Mod	(l*(P[0]-x)-P[1], p)
		R = [x, y]
	return R

def SM2_Mod(a, b):#摸运算
	if math.isinf(a):
		return float('inf')
	else:
		return a%b

def SM2__Mod_Decimal(n, d, b):#小数的模运算
	if d == 0:
		x = float('inf')
	elif n == 0:
		x = 0
	else:
		a = bin(b-2).replace('0b', '')
		y = 1
		i = 0
		while i < len(a):#n/d = x mod b => x = n*d^(b-2) mod b
			y = (y**2)%b#快速指数运算
			if a[i] == '1':
				y = (y*d)%b
			i += 1
		x = (y*n)%b
	return x

def SM3(m):#SM3杂凑算法，m是消息
	m= SM3_Fill(m)
	V_n = SM3_Iterate(m)	
	return V_n

def SM3_Fill(m):#填充
	l = len(m)#m转换成的01串的长度
	k = (448-l-1)%512#k满足l+1+k = 448 mod 512的最小非负整数
	l_b = bin(l).replace('0b', '').rjust(64, '0')#l的64位二进制表示
	m = m+'1'+'0'*k+l_b#在消息后添加1个1、k个0和64位的l
	return m

def SM3_Iterate(m):#迭代
	IV = 0x7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e#初始值
	IV_b = bin(IV).replace('0b', '').rjust(256, '0')#初始值转换为01串
	n = int(len(m)/512)#n = (l+k+65)/512
	B = [m[i:i+512] for i in range(0, 512*n, 512)]#填充后的消息按512比特分组B(0)B(1)...B(n-1)
	V = [IV_b]#V(0)的初值为IV
	i = 0
	while i < n:#0 to n-1
		V.append(SM3_CF(V[i], B[i]))#V(i+1) = CF(V(i), B(i)) CF是压缩函数
		i += 1
	return V[n]

def SM3_W(B):#消息拓展
	W = [B[i:i+32] for i in range(0, 512, 32)]#B(i)划分为16个字W(0)W(1)...W(15)
	i = 16
	while i < 68:#j = 16 to 63
		W.append(SM3_NOR(SM3_NOR(SM3_P1(SM3_NOR(SM3_NOR(W[i-16], W[i-9]), SM3_ROL(W[i-3], 15))), SM3_ROL(W[i-13], 7)), W[i-6]))#W(j) = P1(W(j-16)^W(j-9)^(W(j-3)<<<15))^(W(j-13)<<<7)^W(j-6)
		i += 1
	W_W = []	
	i = 0
	while i < 64:#j = 0 to 63
		W_W.append(SM3_NOR(W[i], W[i+4]))#W'(j) = W(j)^W(j+4)
		i += 1
	return [W, W_W]

def SM3_CF(V, B):#压缩函数V(i+1) = CF(V(i), B(i))
	T_0_15 = 0x79cc4519
	T_16_63 = 0x7a879d8a
	T_0_15_b = bin(T_0_15).replace('0b', '').rjust(32, '0')
	T_16_63_b = bin(T_16_63).replace('0b', '').rjust(32, '0')
	[W, W_W] = SM3_W(B)
	A = V[0:32]
	B = V[32:64]
	C = V[64:96]
	D = V[96:128]
	E = V[128:160]
	F = V[160:192]
	G = V[192:224]
	H = V[224:256]#ABCDEFGH = V(i)
	SS1 = "00000000000000000000000000000000"
	SS2 = "00000000000000000000000000000000"
	TT1 = "00000000000000000000000000000000"
	TT2 = "00000000000000000000000000000000"
	j = 0
	while j < 64:#j = 0 to 63
		if 0 <= j <= 15:#T_j
			T_b = T_0_15_b
		else:
			T_b = T_16_63_b
		SS1 = SM3_ROL(SM3_PLUS(SM3_PLUS(SM3_ROL(A, 12), E), SM3_ROL(T_b, j)), 7)#SS1 = ((A<<<12)+E(T(j)<<<j))<<<7
		SS2 = SM3_NOR(SS1, SM3_ROL(A, 12))#SS2 = SS1^(A<<<12)
		TT1 = SM3_PLUS(SM3_PLUS(SM3_PLUS(SM3_FF(A, B, C, j), D), SS2), W_W[j])#TT1 = FF_j(A, b, C)+D+SS2+W'(j)
		TT2 = SM3_PLUS(SM3_PLUS(SM3_PLUS(SM3_GG(E, F, G, j), H), SS1), W[j])#TT2 = GG_j(E. F, G)+H+SS1+W(j)
		D = C
		C = SM3_ROL(B, 9)#C = B<<<9
		B = A
		A = TT1
		H = G
		G = SM3_ROL(F, 19)#G = F<<<19
		F = E
		E = SM3_P0(TT2)#E = P0(TT2)
		j += 1
	V = bin(int(A+B+C+D+E+F+G+H, 2) ^ int(V, 2)).replace('0b', '').rjust(256, '0')
	return V#V(i+1) = ABCDEFGH^V(i)

def SM3_FF(X, Y, Z, j):#FF_j(X, Y, Z)
	if 0 <= j <=15:
		R = SM3_NOR(SM3_NOR(X, Y), Z)
	else:
		R = SM3_OR(SM3_OR(SM3_AND(X, Y), SM3_AND(X, Z)), SM3_AND(Y, Z))
	return R

def SM3_GG(X, Y, Z, j):#GG_j(X, Y, Z)
	if 0 <= j <=15:
		R = SM3_NOR(SM3_NOR(X, Y), Z)
	else:
		R = SM3_OR(SM3_AND(X, Y), SM3_AND(SM3_NOT(X), Z))
	return R

def SM3_P0(X):#P0(X)
	return SM3_NOR(SM3_NOR(X, SM3_ROL(X, 9)), SM3_ROL(X, 17))

def SM3_P1(X):#P1(X)
	return SM3_NOR(SM3_NOR(X, SM3_ROL(X, 15)), SM3_ROL(X, 23))

def SM3_ROL(X, n):#<<<
	return (X+X[0:n%32])[n%32:32+n%32]

def SM3_PLUS(X, Y):#+
	return bin((int(X, 2)+int(Y, 2))%4294967296).replace('0b', '').rjust(32, '0')

def SM3_NOR(X, Y):#^
	return bin(int(X, 2) ^ int(Y, 2)).replace('0b', '').rjust(32, '0')

def SM3_AND(X, Y):#∧
	return bin(int(X, 2) & int(Y, 2)).replace('0b', '').rjust(32, '0')

def SM3_OR(X, Y):#∨
	return bin(int(X, 2) | int(Y, 2)).replace('0b', '').rjust(32, '0')

def SM3_NOT(X):#¬
	return bin(~int(X, 2) & 0xFFFFFFFF).replace('0b', '').rjust(32, '0')

def SM3_Decode(Y):#01串转换为16进制串
	return "".join(hex(i).replace('0x', '') for i in [int(Y[j:j+4], 2) for j in range(0, len(Y), 4)])
