"""
ALi 2017.12.24
for python3
"""

import random
import math

def SM2_Create(a, p, n, G):#SM2密钥对的生成
	d_A = random.randint(1, n-2)
	P_A = SM2_Mulyipoint(d_A, G, a, p)
	return [d_A, P_A]

def SM2_CA_Signature(a, b, p, n, G, d_A, P_A, ID_A, M):#数字签名生成
	entlen_A = len(ID_A)*8
	ENTL_A = bin(entlen_A).replace('0b', '').rjust(16, '0')
	ID_A_b = "".join([bin(ord(i)).replace('0b', '').rjust(8, '0') for i in ID_A])
	M_b = "".join([bin(ord(i)).replace('0b', '').rjust(8, '0') for i in M])
	a_b = bin(a).replace('0b', '').rjust(256, '0')
	b_b = bin(b).replace('0b', '').rjust(256, '0')
	Gx_b = bin(G[0]).replace('0b', '').rjust(256, '0')
	Gy_b = bin(G[1]).replace('0b', '').rjust(256, '0')
	x_A_b = bin(P_A[0]).replace('0b', '').rjust(256, '0')
	y_A_b = bin(P_A[1]).replace('0b', '').rjust(256, '0')
	Z_A = SM3(ENTL_A+ID_A_b+a_b+b_b+Gx_b+Gy_b+x_A_b+y_A_b)
	M_M = Z_A+M_b
	e = SM3(M_M)
	while True:
		k = random.randint(1, n-1)
		[x_1, y_1] = SM2_Mulyipoint(k, G, a, p)
		r = SM2_Mod(int(e, 2)+x_1, n)
		if r == 0 or r+k == n:
			continue
		else:
			s = SM2__Mod_Decimal(k-r*d_A, 1+d_A, n)
			if s == 0:
				continue
			else:
				break
	return [r, s, Z_A]

def SM2_CA_Check(a, b, p, n, G, Z_A, P_A, M, r, s):#数字签名认证
	M_b = "".join([bin(ord(i)).replace('0b', '').rjust(8, '0') for i in M])
	if 1 <= r <= n-1:
		if 1 <=s <= n-1:
			M_M = Z_A+M_b
			e = SM3(M_M)
			t = SM2_Mod(r+s, n)
			if t != 0:
				[x_1, y_1] = SM2_Pluspoint(SM2_Mulyipoint(s, G, a, p), SM2_Mulyipoint(t, P_A, a, p), a, p)
				R = SM2_Mod(int(e, 2)+x_1, n)
				if R == r:
					print("CHECKING SUCCEED")
				else:
					print("CHECKING FAILED")
			else:
				print("CHECKING FAILED")
		else:
			print("CHECKING FAILED")
	else:
		print("CHECKING FAILED")

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
	l = len(m)#m01串的长度
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


p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
G = [Gx, Gy]
SEsk=0
nounce=0
identification=0
CA=0
priv=0
pub=0
m = str(SEsk)+str(nounce)+str(identification)+hex(CA[0])[2:].rjust(64,'0')+hex(CA[1])[2:].rjust(64,'0')
sign = SM2_SA.SM2_CA_Signature(a, b, p, n, G, priv, pub, '0', m)

print(sign)