# -*- coding: utf-8 -*-

# Form implementation generated from reading ui file 'pruebainterfaz.ui'
#
# Created by: PyQt5 UI code generator 5.15.7
#
# WARNING: Any manual changes made to this file will be lost when pyuic5 is
# run again.  Do not edit this file unless you know what you are doing.

#Rodrigo Garcia, 19085

from sre_parse import ASCIILETTERS
from bokeh.plotting import figure, output_file, show, save
from bokeh.resources import CDN
import pandas as pd
import sys
from PyQt5 import QtCore, QtGui, uic, QtWidgets
from bokeh import plotting, embed, resources
from PyQt5 import QtCore, QtWidgets, QtWebEngineWidgets, QtWebEngine
from PyQt5.QtWidgets import *
import requests
import networkx as nx
import matplotlib.pyplot as plt
from pyvis.network import Network
from PyQt5 import QtCore, QtGui, QtWidgets

#IP = "181.174.107.0/24"
#ST = "2022-08-14T07:00"
#ET = "2022-08-14T12:00"
#SEspecifico = "3257"


class Ui_Dialog(object):
    def setupUi(self, Dialog):
        Dialog.setObjectName("Dialog")
        Dialog.resize(872, 529)
        #Botones
        #Graficar Consulta General
        self.ConslGeneral = QtWidgets.QPushButton(Dialog)
        self.ConslGeneral.setGeometry(QtCore.QRect(10, 370, 121, 31))
        self.ConslGeneral.setObjectName("ConslGeneral")
        
        self.ConslGeneral.clicked.connect(self.PAGE1GENERAL)
        self.ConslGeneral.clicked.connect(self.PAGE2EVENTOS)
        
        #Graficar Eventos
        #self.GenGrafica = QtWidgets.QPushButton(Dialog)
        #self.GenGrafica.setGeometry(QtCore.QRect(20, 430, 111, 31))
        #self.GenGrafica.setObjectName("GenGrafica")
        #self.ConslGeneral.clicked.connect(self.PAGE2EVENTOS)
        
        #Inputs de texto
        #Start Time
        self.STinput = QtWidgets.QLineEdit(Dialog)
        self.STinput.setGeometry(QtCore.QRect(20, 190, 113, 20))
        self.STinput.setObjectName("STinput")
        self.STinput.setText("X-X-XT00:00")
        
        #End Time
        self.ETinput = QtWidgets.QLineEdit(Dialog)
        self.ETinput.setGeometry(QtCore.QRect(20, 250, 113, 20))
        self.ETinput.setObjectName("ETinput")
        self.ETinput.setText("X-X-XT00:00")
        
        #IP
        self.IPinput = QtWidgets.QLineEdit(Dialog)
        self.IPinput.setGeometry(QtCore.QRect(20, 50, 113, 22))
        self.IPinput.setObjectName("IPinput")
        self.IPinput.setText("181.174.107.0/24")
        #self.IPinput = QPlainTextEdit(self)
            
       #ASN
        self.ASNinput = QtWidgets.QLineEdit(Dialog)
        self.ASNinput.setGeometry(QtCore.QRect(20, 310, 113, 20))
        self.ASNinput.setObjectName("ASNinput")
        self.ASNinput.setText("ASN")
        
        #Titulos
        self.label = QtWidgets.QLabel(Dialog)
        self.label.setGeometry(QtCore.QRect(20, 170, 121, 16))
        self.label.setObjectName("label")
        self.label_2 = QtWidgets.QLabel(Dialog)
        self.label_2.setGeometry(QtCore.QRect(30, 230, 91, 16))
        self.label_2.setObjectName("label_2")
        self.label_3 = QtWidgets.QLabel(Dialog)
        self.label_3.setGeometry(QtCore.QRect(20, 30, 121, 16))
        self.label_3.setObjectName("label_3")
        self.plainTextEdit = QtWidgets.QPlainTextEdit(Dialog)
        self.plainTextEdit.setGeometry(QtCore.QRect(20, 80, 121, 81))
        self.plainTextEdit.setObjectName("plainTextEdit")
        
        #Widget pagina 1
        self.tabWidgetTREE = QtWidgets.QTabWidget(Dialog)
        self.tabWidgetTREE.setGeometry(QtCore.QRect(190, 10, 621, 471))
        self.tabWidgetTREE.setObjectName("tabWidgetTREE")
        self.tabWidgetTREEPage1 = QtWidgets.QWidget()
        self.tabWidgetTREEPage1.setObjectName("tabWidgetTREEPage1")
        self.tabWidgetTREEPage1 = QtWebEngineWidgets.QWebEngineView()
        
        
        #Widget pagina 2
        self.tabWidgetTREE.addTab(self.tabWidgetTREEPage1, "")
        self.tabWidgetTREEPage2 = QtWidgets.QWidget()
        self.tabWidgetTREEPage2.setObjectName("tabWidgetTREEPage2")
        self.tabWidgetTREEPage2 = QtWebEngineWidgets.QWebEngineView()
        self.tabWidgetTREE.addTab(self.tabWidgetTREEPage2, "")
        
        
        #self.label_4 = QtWidgets.QLabel(Dialog)
        #self.label_4.setGeometry(QtCore.QRect(50, 410, 47, 13))
        #self.label_4.setObjectName("label_4")
        self.label_5 = QtWidgets.QLabel(Dialog)
        self.label_5.setGeometry(QtCore.QRect(20, 290, 91, 16))
        self.label_5.setObjectName("label_5")

        self.retranslateUi(Dialog)
        self.tabWidgetTREE.setCurrentIndex(0)
        QtCore.QMetaObject.connectSlotsByName(Dialog)

        
    def PAGE1GENERAL(self):
        g = Network('1000px', '1000px', notebook = True)
        IP = self.IPinput.text()
        ASEspecifico = self.ASNinput.text()
        resp2 = requests.get('https://stat.ripe.net/data/ris-peerings/data.json?resource={}'.format(IP))
        R1 = resp2.json()
        data = R1["data"]

        for i in data["peerings"]:
            for j in i["peers"]:
                if len(j["routes"])!=0:
                    M = []
                    for L in j['routes'][0]['as_path']:
                            if L == 52362:
                                    g.add_node(L, label = '52362', color= 'green')  
                            if L == int(ASEspecifico):
                                    g.add_node(L, label = str(ASEspecifico), color= 'red')
                                    
                    for N in j['routes'][0]['as_path']:
                        M.append(str(N))
                    g.add_nodes(j['routes'][0]['as_path'], label = M)
                    for n in range(1, len(j['routes'][0]['as_path'])):
                            if(j['routes'][0]['as_path'][n]!=j['routes'][0]['as_path'][n-1]):
                                    g.add_edge(j['routes'][0]['as_path'][n], j['routes'][0]['as_path'][n-1])
        g.toggle_physics(True)
        #g.show_buttons(filter_=['nodes'])
        g.show('prueba.html')
        archtml = open("prueba.html", "r")
        html = ""
        for i in archtml.readlines():
            html = html + i
        self.tabWidgetTREEPage1.setHtml(html)

    def PAGE2EVENTOS(self):
        IP = self.IPinput.text()
        ST = self.STinput.text()
        ET = self.ETinput.text()
        ASEspecifico = self.ASNinput.text()
        G2 = Network('1000px', '1000px', notebook = True)
        resp = 'https://stat.ripe.net/data/bgplay/data.json?resource={}&starttime={}&endtime{}'.format(IP,ST,ET)
        response = requests.get(resp)
        R = response.json()
        data = R["data"]
        #print(data['query_starttime'])
        #print(data['query_endtime'])

        for i in data["events"]:
            if len(i["attrs"])>2:
                for J in i["attrs"]["path"]:
                    T2 = []
            
                    if J == int(ASEspecifico):
                        T = data['events'].index(i)
                
                        Cblue = ['blue']*len(data["events"][T]["attrs"]["path"])
                
                        for H in data["events"][T]["attrs"]["path"]:
                            T2.append(str(H))
                        if H == 52362:
                            G2.add_node(H, label = '52362', color= 'green') 
                        if J == int(ASEspecifico):
                            G2.add_node(J, label = str(ASEspecifico), color= 'red')
                            
                        G2.add_nodes(data["events"][T]["attrs"]["path"], label = T2, color= Cblue)  
                        for n in range(1, len(data["events"][T]["attrs"]["path"])):
                            if(data["events"][T]["attrs"]["path"][n]!=data["events"][T]["attrs"]["path"][n-1]):
                                G2.add_edge(data["events"][T]["attrs"]["path"][n], data["events"][T]["attrs"]["path"][n-1], color = 'black')
        
        G2.show('prueba2.html')
        archtml = open("prueba2.html", "r")
        html = ""
        for i in archtml.readlines():
            html = html + i
        self.tabWidgetTREEPage2.setHtml(html)
        
    def retranslateUi(self, Dialog):
        _translate = QtCore.QCoreApplication.translate
        Dialog.setWindowTitle(_translate("Dialog", "Dialog"))
        self.ConslGeneral.setText(_translate("Dialog", "Consultar"))
        self.label.setText(_translate("Dialog", "Tiempo de Inicio"))
        self.label_2.setText(_translate("Dialog", "Tiempo Final"))
        self.label_3.setText(_translate("Dialog", "Ingresar IP/Prefijo"))
        self.plainTextEdit.setPlainText(_translate("Dialog", "Usar el siguiente formato para el Tiempo:\n"
"AA-MM-DDT00:00"))
        self.tabWidgetTREE.setTabText(self.tabWidgetTREE.indexOf(self.tabWidgetTREEPage1), _translate("Dialog", "General"))
        self.tabWidgetTREE.setTabText(self.tabWidgetTREE.indexOf(self.tabWidgetTREEPage2), _translate("Dialog", "Eventos"))
        self.label_5.setText(_translate("Dialog", "ASN Especifico"))


if __name__ == "__main__":
    import sys
    app = QtWidgets.QApplication(sys.argv)
    Dialog = QtWidgets.QDialog()
    ui = Ui_Dialog()
    ui.setupUi(Dialog)
    Dialog.show()
    sys.exit(app.exec_())
