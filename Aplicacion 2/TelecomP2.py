from PyQt5 import QtCore, QtGui, QtWidgets
import socket
import binascii
import sys
from collections import OrderedDict

class Ui_Form(object):
    def setupUi(self, Form):
        Form.setObjectName("Form")
        Form.resize(516, 429)
        self.tabWidget = QtWidgets.QTabWidget(Form)
        self.tabWidget.setGeometry(QtCore.QRect(10, 10, 501, 411))
        self.tabWidget.setObjectName("tabWidget")
        self.tab = QtWidgets.QWidget()
        self.tab.setObjectName("tab")
        self.textEdit = QtWidgets.QTextEdit(self.tab)
        self.textEdit.setGeometry(QtCore.QRect(20, 80, 441, 281))
        self.textEdit.setObjectName("textEdit")
        self.lineEdit_2 = QtWidgets.QLineEdit(self.tab)
        self.lineEdit_2.setGeometry(QtCore.QRect(20, 40, 241, 20))
        self.lineEdit_2.setObjectName("lineEdit_2")
        self.label_2 = QtWidgets.QLabel(self.tab)
        self.label_2.setGeometry(QtCore.QRect(280, 40, 47, 13))
        self.label_2.setObjectName("label_2")
        self.pushButton = QtWidgets.QPushButton(self.tab)
        self.pushButton.setGeometry(QtCore.QRect(380, 40, 75, 23))
        self.pushButton.setObjectName("pushButton")
        self.tabWidget.addTab(self.tab, "")
        self.tab_2 = QtWidgets.QWidget()
        self.tab_2.setObjectName("tab_2")
        self.textEdit_2 = QtWidgets.QTextEdit(self.tab_2)
        self.textEdit_2.setGeometry(QtCore.QRect(30, 110, 401, 241))
        self.textEdit_2.setObjectName("textEdit_2")
        self.lineEdit = QtWidgets.QLineEdit(self.tab_2)
        self.lineEdit.setGeometry(QtCore.QRect(170, 10, 113, 20))
        self.lineEdit.setObjectName("lineEdit")
        self.lineEdit_3 = QtWidgets.QLineEdit(self.tab_2)
        self.lineEdit_3.setGeometry(QtCore.QRect(170, 40, 113, 20))
        self.lineEdit_3.setObjectName("lineEdit_3")
        self.lineEdit_4 = QtWidgets.QLineEdit(self.tab_2)
        self.lineEdit_4.setGeometry(QtCore.QRect(170, 70, 113, 20))
        self.lineEdit_4.setObjectName("lineEdit_4")
        self.label = QtWidgets.QLabel(self.tab_2)
        self.label.setGeometry(QtCore.QRect(310, 10, 47, 13))
        self.label.setObjectName("label")
        self.label_3 = QtWidgets.QLabel(self.tab_2)
        self.label_3.setGeometry(QtCore.QRect(310, 40, 47, 13))
        self.label_3.setObjectName("label_3")
        self.label_4 = QtWidgets.QLabel(self.tab_2)
        self.label_4.setGeometry(QtCore.QRect(310, 70, 47, 13))
        self.label_4.setObjectName("label_4")
        self.pushButton_2 = QtWidgets.QPushButton(self.tab_2)
        self.pushButton_2.setGeometry(QtCore.QRect(70, 40, 75, 23))
        self.pushButton_2.setObjectName("pushButton_2")
        self.tabWidget.addTab(self.tab_2, "")

        self.retranslateUi(Form)
        self.tabWidget.setCurrentIndex(1)
        QtCore.QMetaObject.connectSlotsByName(Form)
        self.pushButton.clicked.connect(self.search)
        self.pushButton_2.clicked.connect(self.run)

    def retranslateUi(self, Form):
        _translate = QtCore.QCoreApplication.translate
        Form.setWindowTitle(_translate("Form", "Form"))
        self.label_2.setText(_translate("Form", "URL"))
        self.pushButton.setText(_translate("Form", "Search"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab), _translate("Form", "HTTP"))
        self.label.setText(_translate("Form", "Dominio"))
        self.label_3.setText(_translate("Form", "Tipo"))
        self.label_4.setText(_translate("Form", "Dirección"))
        self.pushButton_2.setText(_translate("Form", "Run"))
        self.tabWidget.setTabText(self.tabWidget.indexOf(self.tab_2), _translate("Form", "DNS"))

    def search(self):
        URL = self.lineEdit_2.text()
        dom = URL.split('/')[2]
    
        mysock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        mysock.connect((dom, 80))
        cmd = ('GET ' + URL + ' HTTP/1.0\r\n\r\n').encode()
        mysock.send(cmd)

        x = ''

        while True:
            data = mysock.recv(4096)
            if len(data) < 1:
                break
            x += data.decode()


        html = x.split('\r\n\r\n')[1]
        #print (html)
        self.textEdit.setHtml(html)

        mysock.close()


    def run(self):
        #Conexion UDP mediante socket

        def Mensaje_UDP(mensaje, address, port):
            mensaje = mensaje.replace(" ", "").replace("\n", "") #Quita espacios para unit el mensaje
            server_address = (address, port)
            
            #se selecciono el AF_INET para utilizar protocolo 4 (Ipv4) para configurar el socket
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #define la puerta
            try:
                sock.sendto(binascii.unhexlify(mensaje), server_address)
                data, _ = sock.recvfrom(4096)
            finally:
                sock.close()
            return binascii.hexlify(data).decode("utf-8")

        #inicio de generacion de mensaje

        def Generar_mensaje(type="A", address=""):
            ID = 43690
            
            QR = 0      # Query: 0, Respuesta: 1     1bit
            OPCODE = 0  # Query estandar           4bit
            AA = 0      # Autoritativo Resp. Servidor                       1bit
            TC = 0      # +512 los supera esta truncado    1bit
            RD = 1      # Recursivo                1bit
            RA = 0      # Confirma si es recur                   1bit
            Z = 0       # Reservado siempre 000                      3bit
            RCODE = 0   # define si es exitosa la respuesta              4bit
                    
            #Parametors query unir
            paramsQ = str(QR)
            paramsQ += str(OPCODE).zfill(4)
            paramsQ += str(AA) + str(TC) + str(RD) + str(RA)
            paramsQ += str(Z).zfill(3)
            paramsQ += str(RCODE).zfill(4)
            paramsQ = "{:04x}".format(int(paramsQ, 2))
            
            QDCOUNT = 1 # Numero de preguntas            4bit
            ANCOUNT = 0 # Numero de respuestas           4bit
            NSCOUNT = 0 # Numero de records de autoridad 4bit
            ARCOUNT = 0 # Numero de records adicionales  4bit
            #fin del diseño del header del DNS
            
            #Creamos el mensaje del request que se realiza, unimos el header
            mensaje = ""
            mensaje  += "{:04x}".format(ID)
            mensaje  += paramsQ
            mensaje  += "{:04x}".format(QDCOUNT)
            mensaje  += "{:04x}".format(ANCOUNT)
            mensaje  += "{:04x}".format(NSCOUNT)
            mensaje  += "{:04x}".format(ARCOUNT)
            
            #El QNAME osea el url es dividido por "."
            addr_parts = address.split(".")
            for part in addr_parts:
                addr_len = "{:02x}".format(len(part))
                addr_part = binascii.hexlify(part.encode())
                mensaje += addr_len
                mensaje += addr_part.decode()
            
            mensaje += "00" #Bit de terminacion del QNAME
            
            #Tipo de request
            QTYPE = get_type(type)
            mensaje += QTYPE
            
            #La classe del Lookup, 1 es Internet
            QCLASS = 1
            mensaje += "{:04x}".format(QCLASS)
            
            return mensaje
            
        #Decodificacion del mensaje + la respuesta del mismo
        def Mensaje_decod(mensaje):
            res = []
            
            ID          = mensaje[0:4]
            paramsQ     = mensaje[4:8]
            QDCOUNT     = mensaje[8:12]
            ANCOUNT     = mensaje[12:16]  
            NSCOUNT     = mensaje[16:20]  
            ARCOUNT     = mensaje[20:24]      
            
            parametros = "{:b}".format(int(paramsQ, 16)).zfill(16)
            QPARAMS = OrderedDict([
                ("QR", parametros[0:1]),
                ("OPCODE", parametros[1:5]),
                ("AA", parametros[5:6]),
                ("TC", parametros[6:7]),
                ("RD", parametros[7:8]),
                ("RA", parametros[8:9]),
                ("Z", parametros[9:12]),
                ("RCODE", parametros[12:16])
            ])
            
            #Seccion de pregunta
            QUESTION_SECTION_STARTS = 24
            partes_pregunta = parse_parts(mensaje, QUESTION_SECTION_STARTS, [])
            
            QNAME = ".".join(map(lambda p: binascii.unhexlify(p).decode(), partes_pregunta))    

            QTYPE_STARTS = QUESTION_SECTION_STARTS + (len("".join(partes_pregunta))) + (len(partes_pregunta) * 2) + 2
            QCLASS_STARTS = QTYPE_STARTS + 4 #Se salta la seccion de pregunta

            QTYPE = mensaje[QTYPE_STARTS:QCLASS_STARTS]
            QCLASS = mensaje[QCLASS_STARTS:QCLASS_STARTS + 4]   
            
            #seccion de respuesta
            ANSWER_SECTION_STARTS = QCLASS_STARTS + 4 #Donde empieza la sec de respuesta 
            
            NUM_ANSWERS = max([int(ANCOUNT, 16), int(NSCOUNT, 16), int(ARCOUNT, 16)]) #Contadores de tipo de respuesta que manda de regreso
            #AN Autoritativa
            #NS 
            #AR Respuestas Extras
            if NUM_ANSWERS > 0:
                res.append("\n# Seccion de Respuesta")
                
                for ANSWER_COUNT in range(NUM_ANSWERS): 
                    if (ANSWER_SECTION_STARTS < len(mensaje)):
                        ANAME = mensaje[ANSWER_SECTION_STARTS:ANSWER_SECTION_STARTS + 4] # Referencia a la pregunta
                        ATYPE = mensaje[ANSWER_SECTION_STARTS + 4:ANSWER_SECTION_STARTS + 8]
                        ACLASS = mensaje[ANSWER_SECTION_STARTS + 8:ANSWER_SECTION_STARTS + 12]
                        TTL = int(mensaje[ANSWER_SECTION_STARTS + 12:ANSWER_SECTION_STARTS + 20], 16)
                        RDLENGTH = int(mensaje[ANSWER_SECTION_STARTS + 20:ANSWER_SECTION_STARTS + 24], 16)  #mismo tamaño
                        RDDATA = mensaje[ANSWER_SECTION_STARTS + 24:ANSWER_SECTION_STARTS + 24 + (RDLENGTH * 2)] #si cambia (Observar)
                    
                    #Decodificar tipo A, el resto no se decodifica
                        if ATYPE == get_type("A"):
                            octetos = [RDDATA[i:i+2] for i in range(0, len(RDDATA), 2)]
                            RDATA_Decodificada = ".".join(list(map(lambda x: str(int(x, 16)), octetos)))
                        else:
                            RDATA_Decodificada = RDDATA
                            
                        ANSWER_SECTION_STARTS = ANSWER_SECTION_STARTS + 24 + (RDLENGTH * 2)  #lo genera con el desfase que se hizo
                    try: ATYPE
                    except NameError: None
                    else:
                        res.append("# Respuesta " + str(ANSWER_COUNT + 1)) 
                        res.append("ATYPE: " + ATYPE + " (\"" + get_type(int(ATYPE, 16)) + "\")")    
                        res.append("TTL: " + str(TTL))
                        res.append("RDLENGTH: " + str(RDLENGTH))
                        res.append("RDDATA: " + RDDATA)
                        res.append("RDDATA (Resultado): " + RDATA_Decodificada + "\n")
            
            return "\n".join(res)
            
        #Tipo de Registros/Consultas
        def get_type(type):
            types = [
                "ERROR", # type 0 does not exist
                "A",
                "NS",
                "MD",
                "MF",
                "CNAME",
                "SOA",
                "MB",
                "MG",
                "MR",
                "NULL",
                "WKS",
                "PTS",
                "HINFO",
                "MINFO",
                "MX",
                "TXT",
                "RP",
                "AFSDB",
                "X25",
                "ISDN",
                "RT",
                "NSAP",
                "NSAP-PTR",
                "SIG",
                "KEY",
                "PX",
                "GPOS",
                "AAAA"
            ]

            return "{:04x}".format(types.index(type)) if isinstance(type, str) else types[type]
        
        #Seccion que sirve como parte de la decodificacion
        def parse_parts(mensaje, start, parts):
            part_start = start + 2
            part_len = mensaje[start:part_start]
        
            if len(part_len) == 0:
                return parts
            
            part_end = part_start + (int(part_len, 16) * 2)
            parts.append(mensaje[part_start:part_end])

            if mensaje[part_end:part_end + 2] == "00" or part_end > len(mensaje):
                return parts
            else:
                return parse_parts(mensaje, part_end, parts)


            
        #Datos que se van a ingresar
        #Primero el URL
        if len(sys.argv) > 1:
            url = sys.argv[1]
        else:
            url = self.lineEdit.text()
            
        #El tipo de mensaje a consultar
        mensaje = Generar_mensaje(self.lineEdit_3.text(), url)
        print("Request:\n" + mensaje)
        dp1 = ("Request:\n" + mensaje)

        #Dirección a la que se hace la consulta
        Respuesta = Mensaje_UDP(mensaje, self.lineEdit_4.text(), 53)
        print("\nResponse:\n" + Respuesta)
        print("\nRespuesta (decodificada):" + Mensaje_decod(Respuesta))
        dp2 = ("\nRespuesta:\n" + Respuesta)
        dp3 = ("\nRespuesta (decodificada):" + Mensaje_decod(Respuesta))
        
       
        self.textEdit_2.setPlainText(dp1 + '\n' + dp2 + '\n' + dp3)       
        
        


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Form = QtWidgets.QWidget()
    ui = Ui_Form()
    ui.setupUi(Form)
    Form.show()
    sys.exit(app.exec_())
