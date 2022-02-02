import random
import SM2_SA
import SM2
import SM4
import hmac
import math
import xlwt
import xlrd
import xlutils.copy

class Protocol:
    def __init__(self, bs=None):
        """
        如果bs为None则代表需要创建一个数据包
        否则代表需要解析一个数据包
        """
        if bs:
            self.bs = bytearray(bs)
        else:
            self.bs = bytearray(0)

#消息头
    def add_head(self,cookies_s=0,cookies_r=0,nex=0):
        #nex为下一载荷的type
        #cookies_s为发起方cookies
        #cookies_r为响应方cookies
        edition = 17  #版本号：0-3位主版本号，4-7位次版本号，协议约定主版本号、次版本号均为1
        exchange = 2  #交换类型
        flag = 0      #标志
        ID = 0        #消息ID
        if cookies_s == '0' or cookies_s == 0:
            cookies_s = "".join([random.choice("0123456789ABCDEF")for i in range(16)])
            cookies_s = int(cookies_s,16)
        if cookies_r == '0' or cookies_r == 0:
            cookies_r = "".join([random.choice("0123456789ABCDEF")for i in range(16)])
            cookies_r = int(cookies_r,16)
        bytes_val = bytearray(cookies_s.to_bytes(8, byteorder='big'))
        bytes_val += bytearray(cookies_r.to_bytes(8, byteorder='big'))
        bytes_val += bytearray(nex.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(edition.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(exchange.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(flag.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(ID.to_bytes(1, byteorder='big'))
        length = len(bytes_val)+len(self.bs)+2    #整个消息的长度
        bytes_val += bytearray(length.to_bytes(2, byteorder='big'))
        self.bs = bytes_val+self.bs   #消息头加在所有载荷之前

        global num

        if num=='1':
            f = xlrd.open_workbook('message.xls')
            new_f = xlutils.copy.copy(f)  # 将xlrd对象拷贝转化为xlwt对象
            new_worksheet = new_f.get_sheet(0)  # 获取转化后工作簿中的第一个表格
            new_worksheet.write(1,0,str(cookies_s))
            new_f.save('message.xls')
        if num=='2':
            f = xlrd.open_workbook('message.xls')
            new_f = xlutils.copy.copy(f)  # 将xlrd对象拷贝转化为xlwt对象
            new_worksheet = new_f.get_sheet(0)  # 获取转化后工作簿中的第一个表格
            new_worksheet.write(3,0,str(cookies_r))
            new_f.save('message.xls')


        return [cookies_s,cookies_r]

#SA载荷
    def sa_load(self,nex):
        #nex为下一载荷的type
        resevred = 0  #保留：1个字节。其值为0。
        DOI = 1       #解释域(DOI)：4个字节。值为1。
        sit = 1       #情形：4个字节。值为1。
        bytes_val = bytearray(nex.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(resevred.to_bytes(1, byteorder='big'))
        length = len(bytes_val)+len(self.bs)+10
        bytes_val += bytearray(length.to_bytes(2, byteorder='big'))
        bytes_val += bytearray(DOI.to_bytes(4, byteorder='big'))
        bytes_val += bytearray(sit.to_bytes(4, byteorder='big'))

        result = ''
        a = len(bytes_val)
        for i in range(a):
            ret = bytes_val[i]
            ret = str(hex(ret))[2:]
            if len(ret) == 1:
                result += '0'
            result += ret
        global num
        if num=='1':
            f = xlwt.Workbook()
            sheet = f.add_sheet('sheet')           
            SAi_b = result[-16:]
            row0 = ["cookie_i","SAi_b"]
            for i in range(2):
                sheet.write(0,i,row0[i])
            sheet.write(1,1,SAi_b)
            f.save('message.xls')
        if num=='2':
            f = xlrd.open_workbook('message.xls')
            new_f = xlutils.copy.copy(f)  # 将xlrd对象拷贝转化为xlwt对象
            new_worksheet = new_f.get_sheet(0)  # 获取转化后工作簿中的第一个表格
            SAr_b = result[-16:]
            row2 = ["cookie_r","SAr_b"]
            for i in range(2):
                new_worksheet.write(2,i,row2[i])
            new_worksheet.write(3,1,SAr_b)
            new_f.save('message.xls')

        self.bs = bytes_val+self.bs   #SA载荷加在建议载荷之前

#建议载荷
    def adv_load(self,nex = 0):
        #nex为下一载荷的type
        resevred = 0   #保留：1个字节。其值为0。
        adv = 1        #建议号：1个字节。设置为1，表示建议载荷的优先级，越小优先级越高。
        ID = 2         #协议ID：1个字节。设置为2，AH协议标识符。
        SPI = 0        #SPI长度：1个字节。设置为0。
        change_nu = 4  #变换数：1个字节。标志变换载荷的个数。
        bytes_val = bytearray(nex.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(resevred.to_bytes(1, byteorder='big'))
        length = len(bytes_val)+6     #载荷长度：2个字节.计算范围为建议载荷
        bytes_val += bytearray(length.to_bytes(2, byteorder='big'))
        bytes_val += bytearray(adv.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(ID.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(SPI.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(change_nu.to_bytes(1, byteorder='big'))
        self.bs = bytes_val+self.bs   #建议载荷加在变换载荷及SA属性载荷之前

#变换载荷及SA属性载荷
    def change_load(self,nex=0,sit_type=0,sit_val=0):
        #nex为下一载荷的type
        #sit_type为SA属性类型
        #sit_val为SA属性值
        change_no = 1   #变换号：1个字节。设置为1，表示变换载荷的优先级，越小优先级越高。
        ch_ID = 1       #变换ID：1个字节。值为1。
        resevred = 0    #保留：1个字节。值为0。
        resevred2 = 0   #保留2：2个字节。值为0。
        bytes_val = bytearray(nex.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(resevred.to_bytes(1, byteorder='big'))
        length = len(bytes_val)+10   #载荷长度：2个字节。单位为字节，计算范围为变换载荷和SA属性载荷
        bytes_val += bytearray(length.to_bytes(2, byteorder='big'))
        bytes_val += bytearray(change_no.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(ch_ID.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(resevred2.to_bytes(2, byteorder='big'))
        bytes_val += bytearray(sit_type.to_bytes(2, byteorder='big'))
        bytes_val += bytearray(sit_val.to_bytes(2, byteorder='big'))
        self.bs += bytes_val

    #加密算法：类型为1(定长)，属性值为129(SM4分组密码)。
    #哈希算法：类型为2(定长)，属性值为20(SM3哈希算法)
    #鉴别方式：类型为3(定长)，属性值为10(公钥数字信封鉴别方法)
    #非对称密码算法：类型为20(定长)，属性值为2 (SM2椭圆曲线密码)

#证书载荷
    def cer_load(self,nex=0,cer_no=5,cer_data=0):
        #nex下一载荷：1个字节。取决于数据包第一个载荷类型对应编号，如果没有下一载荷，其值为0。
        #证书编码：签名证书值为4，加密证书值为5。证书格式均为X.509。
        #证书数据：这里用通信本方非对称密码的公钥数据替代
        resevred = 0   #保留：1个字节。值为0。
        if cer_data == 0:
            return -1
        bytes_val = bytearray(nex.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(resevred.to_bytes(1, byteorder='big'))
        #载荷长度：单位为字节，计算范围为该证书载荷。
        length = len(bytes_val)+math.ceil(len(hex(cer_data[0])[2:].rjust(64,'0'))/2)+math.ceil(len(hex(cer_data[1])[2:].rjust(64,'0'))/2)+3
        bytes_val += bytearray(length.to_bytes(2, byteorder='big'))
        bytes_val = bytearray(cer_no.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(cer_data[0].to_bytes(math.ceil(len(hex(cer_data[0])[2:].rjust(64,'0'))/2), byteorder='big'))
        bytes_val += bytearray(cer_data[1].to_bytes(math.ceil(len(hex(cer_data[1])[2:].rjust(64,'0'))/2), byteorder='big'))
        self.bs += bytes_val

#对称密钥载荷
    def add_SEsk(self,nex=0,SEsk='0',pub=0):
        #SEsk是通信本方对称密码密钥
        #pub是通信对方非对称密码公钥
        #nex为下一载荷的type
        reserve = 0   #保留
        if pub == 0:
            return -1
        p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
        a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
        b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
        n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
        Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
        Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
        G = [Gx, Gy]
        SEkey1 = SM2.SM2_Encrypt(a, b, p, n, G, pub, SEsk[:16])
        SEkey = hex(int(SEkey1,2))[2:].rjust(256,'0')
        SEkey2 = SM2.SM2_Encrypt(a, b, p, n, G, pub, SEsk[16:])
        SEkey += hex(int(SEkey2,2))[2:].rjust(256,'0')
        length = 4+math.ceil(len(SEkey)/2)  #载荷长度:单位为字节，计算范围为该对称密钥载荷
        bytes_val = bytearray(nex.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(reserve.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(length.to_bytes(2, byteorder='big'))
        bytes_val += bytearray(int(SEkey,16).to_bytes(math.ceil(len(SEkey)/2), byteorder='big'))
        self.bs += bytes_val

#nounce载荷
    def add_nounce(self,nex=0,SEsk=0):
        #nex为下一载荷的type
        #SEsk为通信本方的对称密码密钥
        reserve = 0   #保留
        nounce = "".join([random.choice("0123456789ABCDEF")for i in range(128)])
        SEkey = bytearray(int(SEsk,16).to_bytes(len(SEsk), byteorder='big'))
        S = SM4.CryptSM4()
        S.set_key(SEkey,0)
        nounce_b = bytearray(int(nounce,16).to_bytes(len(nounce), byteorder='big'))
        nounce_c = S.crypt_ecb(nounce_b)

        result1 = ''
        a = len(nounce_c)
        for i in range(a):
            ret1 = nounce_c[i]
            ret1 = str(hex(ret1))[2:]
            if len(ret1) == 1:
                result1 += '0'
            result1 += ret1
        global num
        if num=='3':
            f = xlrd.open_workbook('message.xls')
            new_f = xlutils.copy.copy(f)  # 将xlrd对象拷贝转化为xlwt对象
            new_worksheet = new_f.get_sheet(0)  # 获取转化后工作簿中的第一个表格
            Ni_b = result1
            new_worksheet.write(8,0,"Ni_b")
            new_worksheet.write(9,0,Ni_b)
            new_f.save('message.xls')
        if num=='4':
            f = xlrd.open_workbook('message.xls')
            new_f = xlutils.copy.copy(f)  # 将xlrd对象拷贝转化为xlwt对象
            new_worksheet = new_f.get_sheet(0)  # 获取转化后工作簿中的第一个表格
            Nr_b = result1
            new_worksheet.write(10,0,"Nr_b")
            new_worksheet.write(11,0,Nr_b)
            new_f.save('message.xls')

        length = 4+len(nounce_c)      #载荷长度:单位为字节，计算范围为该Nounce载荷
        bytes_val = bytearray(nex.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(reserve.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(length.to_bytes(2, byteorder='big'))
        bytes_val += nounce_c
        self.bs += bytes_val
        return nounce

#标识载荷
    def add_identification(self,nex=0,identification='192.168.0.0',ID=0,pub=0):
        #nex为下一载荷的type
        #identification为标识数据，是一个IPv4地址
        #ID为协议ID，ID为6，则为TCP协议;ID为17，则为UDP协议
        #pub为通信对方非对称密码私钥
        reserve = 0   #保留
        port = 0      #端口
        if pub == 0:
            return -1
        identificate = 1   #标识类型设置为1，表示标识数据为IPv4地址
        p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
        a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
        b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
        n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
        Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
        Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
        G = [Gx, Gy]
        identification_c = SM2.SM2_Encrypt(a, b, p, n, G, pub, identification)
        identification_c = hex(int(identification_c,2))[2:].rjust(64,'0')
        length = math.ceil(len(identification_c)/2)+8   #载荷长度:单位为字节，计算范围为该标识载荷。
        bytes_val = bytearray(nex.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(reserve.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(length.to_bytes(2, byteorder='big'))
        bytes_val += bytearray(identificate.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(ID.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(port.to_bytes(2, byteorder='big'))
        bytes_val += bytearray(int(identification_c,16).to_bytes(length-8, byteorder='big'))

        result = ''
        a = len(bytes_val)
        for i in range(a):
            ret = bytes_val[i]
            ret = str(hex(ret))[2:]
            if len(ret) == 1:
                result += '0'
            result += ret
        global num
        if num=='3':
            f = xlrd.open_workbook('message.xls')
            new_f = xlutils.copy.copy(f)  # 将xlrd对象拷贝转化为xlwt对象
            new_worksheet = new_f.get_sheet(0)  # 获取转化后工作簿中的第一个表格
            IDi_b = result[17:]
            new_worksheet.write(4,0,"IDi_b")
            new_worksheet.write(5,0,IDi_b)
            new_f.save('message.xls')
        if num=='4':
            f = xlrd.open_workbook('message.xls')
            new_f = xlutils.copy.copy(f)  # 将xlrd对象拷贝转化为xlwt对象
            new_worksheet = new_f.get_sheet(0)  # 获取转化后工作簿中的第一个表格
            IDr_b = result[17:]
            new_worksheet.write(6,0,"IDr_b")
            new_worksheet.write(7,0,IDr_b)
            new_f.save('message.xls')

        self.bs += bytes_val

#签名载荷     
    def add_sign(self,SEsk=0,nounce=0,identification=0,CA=0,nex=0,priv=0,pub=0):
        #nex为下一载荷的type
        #pub为通信本方的非对称密码的公钥数据
        #priv为通信本方的非对称密码的私钥数据
        #identification为标识数据，是通信本方的IPv4地址
        #nounce为通信本方的nounce
        #SEsk为通信本方的非对称密码密钥
        reserve = 0    #保留
        if (priv and pub) == 0:
            return -1
        p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
        a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
        b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
        n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
        Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
        Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
        G = [Gx, Gy]
        m = str(SEsk)+str(nounce)+str(identification)+hex(CA[0])[2:].rjust(64,'0')+hex(CA[1])[2:].rjust(64,'0')
        sign = SM2_SA.SM2_CA_Signature(a, b, p, n, G, priv, pub, '0', m)
        #载荷长度:单位为字节，计算范围为该签名载荷。
        length = math.ceil(len(hex(sign[0])[2:].rjust(64,'0'))/2)+math.ceil(len(hex(sign[1])[2:].rjust(64,'0'))/2)+4
        bytes_val = bytearray(nex.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(reserve.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(length.to_bytes(2, byteorder='big'))
        bytes_val += bytearray(sign[0].to_bytes(math.ceil(len(hex(sign[0])[2:].rjust(64,'0'))/2), byteorder='big'))
        bytes_val += bytearray(sign[1].to_bytes(math.ceil(len(hex(sign[1])[2:].rjust(64,'0'))/2), byteorder='big'))
        self.bs += bytes_val

#杂凑载荷
    def add_hash(self,nounce=0,nex=0,pub=0,CAi=0,CAr=0):
        #nex为下一载荷的type
        #pub是通信对方非对称密码公钥
        #CAi：通信本方加密证书数据，这里用通信本方非对称密码的公钥数据替代
        #CAr：通信对方加密证书数据，这里用通信对方非对称密码的公钥数据替代
        #nounce是通信双方的nounce数据
        reserve = 0   #保留

        global num   
        data = xlrd.open_workbook('message.xls')
        table = data.sheets()[0]
        cookie_i = table.cell_value(1,0)
        cookie_r = table.cell_value(3,0)      
        if num=='5':
            SAi_b = table.cell_value(1,1)
            IDi_b = table.cell_value(5,0)
            h_seed =cookie_i+cookie_r+SAi_b+IDi_b
            h_message=bytearray(int(h_seed,16).to_bytes(math.ceil(len(h_seed)/2), byteorder='big'))
            temp1 = table.cell_value(9,0)
            nounce_in_message4=input("message 4")
            nounce=nounce_in_message4[606:862]
            nounce = temp1+nounce
        if num=='6':
            SAr_b = table.cell_value(3,1)
            IDr_b = table.cell_value(7,0)
            h_seed =cookie_r+cookie_i+SAr_b+IDr_b
            h_message=bytearray(int(h_seed,16).to_bytes(math.ceil(len(h_seed)/2), byteorder='big'))
            temp2 = table.cell_value(11,0)
            nounce_in_message3=input("message 3")
            nounce=nounce_in_message3[606:862]
            nounce = nounce+temp2

        h_nounce = SM2_SA.SM3(bin(int(nounce,16)))  #h_nounce为2进制
        h_nounce = bytearray(int(h_nounce,16).to_bytes(len(h_nounce), byteorder='big'))
        pub = hex(pub[0])[2:]+hex(pub[1])[2:]
        pub_b = bytearray(int(pub,16).to_bytes(math.ceil(len(pub)/2), byteorder='big'))
        skeyid = hmac.new(h_nounce,pub_b)   #h_nounce为种子，pub_b为message
        skeyid = skeyid.hexdigest()         #skeyid为16进制
        skeyid_b = bytearray(int(skeyid,16).to_bytes(len(skeyid), byteorder='big'))
        #h_message = hex(CAi[0])[2:]+hex(CAi[1])[2:]+hex(CAr[0])[2:]+hex(CAr[1])[2:]
        #h_message = bytearray(int(h_message,16).to_bytes(math.ceil(len(h_message)/2), byteorder='big'))
        h = hmac.new(skeyid_b,h_message)  #skeyid_b为种子，h_message为message
        h = h.hexdigest()
        length = math.ceil(len(h)/2)+4   #载荷长度:单位为字节，计算范围为该杂凑载荷。
        bytes_val = bytearray(nex.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(reserve.to_bytes(1, byteorder='big'))
        bytes_val += bytearray(length.to_bytes(2, byteorder='big'))
        bytes_val += bytearray(int(h,16).to_bytes(length-4, byteorder='big'))
        self.bs += bytes_val

#解密对称密码密钥
    def get_SEsk(self,message,d_B):
        p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
        a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
        b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
        n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
        Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
        Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
        G = [Gx, Gy]
        
        SEsk1 = message[:256]
        SEsk1 = bin(int(SEsk1,16))[2:]
        length1 = len(SEsk1)
        if length1%8:
            SEsk1 = SEsk1.rjust(length1+8-length1%8,'0')
        else:
            SEsk1 = SEsk1.rjust(length1,'0')
        SEsk = SM2.SM2_Decrypt(a, b, p, n, G, d_B, SEsk1)

        SEsk2 = message[256:]
        SEsk2 = bin(int(SEsk2,16))[2:]
        length2 = len(SEsk2)
        if length2%8:
            SEsk2 = SEsk2.rjust(length2+8-length2%8,'0')
        else:
            SEsk2 = SEsk2.rjust(length2,'0')
        SEsk += SM2.SM2_Decrypt(a, b, p, n, G, d_B, SEsk2)
        return SEsk

    def get_cer(self,cer):
        pubx = cer[:64]
        puby = cer[64:]
        return [int(pubx,16),int(puby,16)]
        
    def get_pck_not_head(self):
        return self.bs

    def get_pck_has_head(self):
        bytes_pck_length = bytearray(len(self.bs).to_bytes(4, byteorder='little'))
        return bytes_pck_length + self.bs

    def get_int32(self):
        try:
            result = ''
            a = len(self.bs)
            for i in range(a):
                ret = self.bs[i]
                ret = str(hex(ret))[2:]
                if len(ret) == 1:
                    result += '0'
                result += ret
            #self.bs = self.bs[a:]
            return result
        except:
            raise Exception("数据异常！")
  
if __name__ == '__main__':
    p = Protocol()
    result = 0

    num = input("第几次交互:")
    if num == '1' or num == '2':
        follow = 3
    elif num == '3' or num == '4':
        follow = 128
    else:
        follow = 8
#pub:通信对方的非对称密码公钥
#P_B:通信本方的非对称密码公钥
    while follow >= 0:
        if follow == 0:  #消息头
            follow = -1
            if num == '1':
                cookies_s=0
                cookies_r=0
                nex = 1
            else:
                cookies_s=input("cookies_s=")
                cookies_r=input("cookies_r=")
                cookies_s = int(cookies_s,10)
                cookies_r = int(cookies_r,10)
            if num == '2':
                nex = 1
            if num == '3' or num == '4':
                nex = 128
            if num == '5' or num == '6':
                nex = 8    
            [cookies_s,cookies_r] = p.add_head(cookies_s,cookies_r,nex)
                
        elif follow == 1:  #SA载荷
            follow = 0
            nex = 2
            if num == '2':
                follow = 6
            p.sa_load(nex)
            
        elif follow == 2:  #建议载荷
            follow = 1
            nex = 0
            p.adv_load(nex)

        elif follow == 3:  #变换载荷
            follow = 2
            p.change_load(3,1,129) #SM4分组密码
            p.change_load(3,2,20)  #SM3哈希算法
            p.change_load(3,3,10)  #公钥数字信封鉴别方法
            p.change_load(0,20,2)  #SM2椭圆曲线密码
            
        elif follow == 5:  #标识载荷
            follow = 6
            nex = 6
            if num == '4':
                follow = 9
                nex = 9
            flag = 1
            while flag:
                type_ID=input("the type of ip protocol(UDP or TCP):")
                if type_ID == 'UDP':
                    ID = 17  #表示UDP协议
                    flag = 0
                elif type_ID == 'TCP':
                    ID = 6   #表示TCP协议
                    flag = 0
                else:
                    print('please input UDP or TCP!')
            identification = input("the other side IP address:")
            result = p.add_identification(nex,identification,ID,pub)   #pub在对称密钥载荷已经输入

        elif follow == 6:  #证书载荷
            follow = 9
            nex = 9
            if num == '2':
                follow = 0
                nex = 0
            p1 = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
            a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
            n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123
            Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7
            Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0
            G = [Gx, Gy]
            [d_B,P_B] = SM2.SM2_Create(a, p1, n, G)
            p.cer_load(nex,5,P_B)
            
        elif follow == 8:   #杂凑载荷
            follow = 0
            nex = 0
            P_Bx = input("your public key of SM2(x-coordinate):")
            P_By = input("your public key of SM2(y-coordinate):")
            P_B = [int(P_Bx,10),int(P_By,10)]
            pubx = input("the other side public key of SM2(x-coordinate):")
            puby = input("the other side public key of SM2(y-coordinate):")
            pub = [int(pubx,10),int(puby,10)]
            #nounce = input("the other side nounce:")
            p.add_hash(0,nex,P_B,P_B,pub)
            
        elif follow == 9:   #签名载荷
            follow = 0
            nex = 0
            if num == '4':
                P_Bx = input("your public key of SM2(x-coordinate):")
                P_By = input("your public key of SM2(y-coordinate):")
                P_B = [int(P_Bx,10),int(P_By,10)]
            result = p.add_sign(SEsk,nounce,identification,P_B,nex,d_B,P_B)
            
        elif follow == 10:   #Nounce载荷
            follow = 5
            nex = 5
            nounce = p.add_nounce(nex,SEsk)
            
        elif follow == 128:  #对称密钥载荷
            follow = 10
            nex = 10
                          
            #pubx = input("the other side public key of SM2(x-coordinate):")
            #puby = input("the other side public key of SM2(y-coordinate):")
            #pub = [int(pubx,10),int(puby,10)]
            if num == '3':
                message2 = input("message 2:")
                SEsk = "".join([random.choice("0123456789ABCDEF")for i in range(32)])
                pub_hex = message2[-128:]
                pub = p.get_cer(pub_hex)
            else:
                message3 = input("message 3:")
                pub_hex = message3[-264:-136]
                pub = p.get_cer(pub_hex)
                d_B = input("your private key of SM2:")
                d_B = int(d_B,10)
                SEsk_c = message3[54:566]
                SEsk = p.get_SEsk(SEsk_c,d_B)
            p.add_SEsk(nex,SEsk,pub)
    if result != -1:
        r = Protocol(p.get_pck_not_head())
        print("\n")
        print(r.get_int32())
        print("\n")
        if num == '1':
            print("cookies_s："+str(cookies_s))
            print("cookies_r："+str(cookies_r))
        elif num == '2':
            print("非对称密码私钥："+str(d_B))
            print("非对称密码公钥："+str(P_B))
        elif num == '3' or num == '4':
            print("非对称密码私钥："+str(d_B))
            print("非对称密码公钥："+str(P_B))
            print("对称密码密钥："+str(SEsk))
            print("通信对方非对称密码公钥："+str(pub))
            print("nounce："+str(nounce))
            print("identification："+str(identification))


