
#Importamos los modulos necesarios para desempaquetar
import socket, sys
import struct

# Desempaquetamoss Ethernet 
def ethernet_frame(data):
    dest_mac, src_mac, proto = struct.unpack('! 6s 6s H', data[:14])
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]

    #Formato direccion MAC
def get_mac_addr(bytes_addr):
    bytes_str = map('{:02x}'.format, bytes_addr)
    mac_addr = '-'.join(bytes_str).upper()
    return mac_addr
#Opcional.Convertimos una cadena string de 6 caracteres de la direccion MAs en una cadena hexadecimal separado por guiones                      
def eth_addr (a) :
    a=str(a)
    b = "%.2x-%.2x-%.2x-%.2x-%.2x-%.2x" % (ord(a[0]) , ord(a[1]) , ord(a[2]), ord(a[3]), ord(a[4]) , ord(a[5]))
    return b
#Instanciamos el socket
try:
    s = socket.socket( socket.AF_PACKET , socket.SOCK_RAW , socket.ntohs(0x0003))
except:
    print ('Socket could not be created. Error Code : ' + str(msg[0]) + ' Message ' + msg[1])
    sys.exit()
#Recibimos el paquete
print('*********************************')
print('* RICHARD POMACOSI QUISPE       *')
print('* C-I. 9994735 LP  PARALELO: C  *')
print('*********************************')

while True:
    #Recibimos el paquete
    packet = s.recvfrom(65565)
    #Guardamos el paquete como una tupla
    packet = packet[0]
    dest_mac, src_mac, eth_proto, data = ethernet_frame(packet)
    eth_length=14
    
    #parseamos el tamaño de ethernet header
    eth_header = packet[0:14]
    #Desempaquetamos la informacion de acuerdo con el formato dado
    eth = struct.unpack('!6s6sH' , eth_header)
    
    eth_d=eth[0]
    eth_s=eth[1]
    eth_protocol = socket.ntohs(eth[2])
    
#Mostramos la cabecera de Ethernet
    print('Ethernet Header')
    print('\t|-Destination Address\t:',dest_mac)
    print('\t|-Destination Address\t:',src_mac)
    print('\t|-Protocol\t\t:',str(eth_protocol))
    #Version

    if eth_protocol==8:
        #tomamos los primeros 20 caracteres de la cabecera IP
        ip_header = packet[eth_length:20+eth_length]
        #Desempaquetamos la informacion de acuerdo con el formato dado
        iph = struct.unpack('!BBHHHBBH4s4s' , ip_header)
        #luego obtenemos los campos de la cabecera IP (consta de 10 campos)
        #La version y el ihl se encuentran en la posicion 0
        version_ihl = iph[0]
        #Obtenemos la version
        version = version_ihl >> 4
        #Obtenemos el ihl
        ihl = version_ihl & 0xF
        #Obtenemos el tipo de servicio
        ip_tos = iph[1] # char
        #Obtenemos la longitud total
        ip_len = iph[2] # short int
        #Obtenemos la identificacion
        ip_id = iph[3]  # short int
        #Obtenemos los flag
        ip_off = iph[4] # short int
        #Obtenemos el TTL
        ip_ttl = iph[5] #char
        #Obtenemos el tipo de protocolo
        ip_p = iph[6]   #char
        #Obtenemos el checksum
        ip_sum = iph[7] #shor int
        #Obtenemos la direccion origen
        s_addr = socket.inet_ntoa(iph[8])
        #Obtenemos la direccion destino
        d_addr = socket.inet_ntoa(iph[9])
        
        iph_length=ihl*4

        print("IP Header")
        print('\t|-IP Version\t\t:' ,str(version) )
        #De esta manera obtenemos lo bytes correspondiente al tamaño del IHL
        print('\t|-IP Header Length (IHL):' , ihl, ' DWORDS or ',str(ihl*32//8) ,' Bytes')
        print('\t|-Type of Service\t:',str(ip_tos))
        #De esta manera obtenemos los bytes correspondientes al tamaño total de la IP
        print('\t|-IP Total Length\t:',ip_len, ' DWORDS or 12',str(ip_len*32//8) ,'Bytes')
        print('\t|-Identification\t:',ip_id)
        print('\t|-TTL\t\t\t:' , str(ip_ttl))
        print('\t|-Protocol\t\t:' , str(ip_p) )
        print('\t|-Chksum\t\t:',ip_sum)
        print('\t|-Source IP\t\t: ' + str(s_addr) )
        print('\t|-Destination IP\t: ' + str(d_addr))
    
        if ip_p==6:
            t=iph_length+eth_length
        #****************************TCP***********************
            #tomamos la longitud de la cabecera TCP
            tcp_header = packet[t:t+20]

            #Desempaquetamos la informacion de acuerdo al dormato dado
            tcph = struct.unpack('!HHLLBBHHH' , tcp_header)
            #Obtenemos los valores del vector 
            source_port = tcph[0]   # uint16_t
            dest_port = tcph[1]     # uint16_t
            sequence = tcph[2]      # uint32_t
            acknowledgement = tcph[3]   # uint32_t
            doff_reserved = tcph[4]     # uint8_t
            tcph_length = doff_reserved >> 4
            tcph_flags = tcph[5]            #uint8_t
            tcph_window_size = tcph[6]      #uint16_t
            tcph_checksum = tcph[7]         #uint16_t
            tcph_urgent_pointer = tcph[8]   #uint16_t
            
            print("TCP Header")
            
            print("\t|-Source Port\t:",source_port)
            print("\t|-Destination Port\t:",dest_port)
            print("\t|-Sequence Number\t:",sequence)
            print("\t|-Acknowledge Number\t:",acknowledgement)
            print("\t|-Header Length\t:",tcph_length,'DWORDS or ',str(tcph_length*32//8) ,'bytes')
            #Ahora comprobaremos cada uno de los flags
            if(tcph_flags&(1<<5)):
                print("\t|-Urgent Flag\t: 1")
            else:
                print("\t|-Urgent Flag\t: 0")
            if(tcph_flags&(1<<4)):
                print("\t|-Acknowledgement Flag\t: 1")
            else:
                print("\t|-Acknowledgement Flag\t: 0")
            if(tcph_flags&(1<<3)):
                print("\t|-Push Flag\t: 1")
            else:
                print("\t|-Push Flag\t: 0")
            if(tcph_flags&(1<<2)):
                print("\t|-Reset Flag\t: 1")
            else:
                print("\t|-Reset Flag\t: 0")
            if(tcph_flags&(1<<1)):
                print("\t|-Synchronise Flag: 1")
            else:
                print("\t|-Synchronise Flag: 0")
            if(tcph_flags&(1)):
                print("\t|-Finish Flag: 1")
            else:
                print("\t|-Finish Flag: 0")

            print("\t|-Window Size\t:",tcph_window_size)
            print("\t|-Checksum\t:",tcph_checksum)
            print("\t|-Urgent Pointer\t:",tcph_urgent_pointer)
            print('*********************************')
            print('* RICHARD POMACOSI QUISPE       *')
            print('* C-I. 9994735 LP  PARALELO: C  *')
            print('*********************************')
#ICMP
        elif ip_p==1:
            u=iph_length+eth_length
            icmph_length = 4
            icmp_header = packet[u:u+4]

            #Ahora desempaquetamos
            icmph = struct.unpack('!BBH' , icmp_header)
            
            icmp_type = icmph[0]
            code = icmph[1]
            checksum = icmph[2]
            print('ICMP Header')
            print ('\t|-Type\t:' ,str(icmp_type))
            print('\t|-Code\t:' ,str(code))
            print('\t|-Checksum\t:',str(checksum))
            
            h_size = eth_length + iph_length + icmph_length
            data_size = len(packet) - h_size
            
            #get data from the packet
            data = packet[h_size:]
            
            print ('Data : ' , data)
            print('*********************************')
            print('* RICHARD POMACOSI QUISPE       *')
            print('* C-I. 9994735 LP  PARALELO: C  *')
            print('*********************************')
        #Packetes UDP
        elif ip_p==17:
            u = iph_length + eth_length
            udph_length = 8
            udp_header = packet[u:u+8]

            #Desempaquetamos
            udph = struct.unpack('!HHHH' , udp_header)
                
            source_port = udph[0]
            dest_port = udph[1]
            length = udph[2]
            checksum = udph[3]

            print('UDP Header') 
            print('\t|-Source Port\t:',str(source_port))
            print('\t|-Destination Port\t:',str(dest_port))
            print('\t|-Length\t:',str(length))
            print('\t|-Checksum\t:',str(checksum))
            h_size = eth_length + iph_length + udph_length
            data_size = len(packet) - h_size
                
            #get data from the packet
            data = packet[h_size:]
                
            print ('Data : ' +str(data))
            print('*********************************')
            print('* RICHARD POMACOSI QUISPE       *')
            print('* C-I. 9994735 LP  PARALELO: C  *')
            print('*********************************')
        #some other IP packet like IGMP
        else :
            print ('Protocol other than TCP/UDP/ICMP')


   