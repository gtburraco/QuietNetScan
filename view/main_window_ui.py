# -*- coding: utf-8 -*-

################################################################################
## Form generated from reading UI file 'main_window.ui'
##
## Created by: Qt User Interface Compiler version 6.10.1
##
## WARNING! All changes made in this file will be lost when recompiling UI file!
################################################################################

from PySide6.QtCore import (QCoreApplication, QMetaObject, QRect)
from PySide6.QtWidgets import (QAbstractItemView, QHBoxLayout, QLineEdit, QMenuBar, QProgressBar,
                               QPushButton, QSizePolicy, QSpacerItem, QStatusBar,
                               QTableView, QVBoxLayout, QWidget)


class Ui_MainWindow(object):
    def setupUi(self, MainWindow):
        if not MainWindow.objectName():
            MainWindow.setObjectName(u"MainWindow")
        MainWindow.resize(940, 451)
        self.centralwidget = QWidget(MainWindow)
        self.centralwidget.setObjectName(u"centralwidget")
        self.verticalLayout = QVBoxLayout(self.centralwidget)
        self.verticalLayout.setObjectName(u"verticalLayout")
        self.horizontalLayout_2 = QHBoxLayout()
        self.horizontalLayout_2.setObjectName(u"horizontalLayout_2")
        self.from_ip_lineedit = QLineEdit(self.centralwidget)
        self.from_ip_lineedit.setObjectName(u"from_ip_lineedit")
        self.from_ip_lineedit.setMaxLength(15)

        self.horizontalLayout_2.addWidget(self.from_ip_lineedit)

        self.to_ip_lineedit = QLineEdit(self.centralwidget)
        self.to_ip_lineedit.setObjectName(u"to_ip_lineedit")
        self.to_ip_lineedit.setMaxLength(15)

        self.horizontalLayout_2.addWidget(self.to_ip_lineedit)

        self.horizontalSpacer = QSpacerItem(40, 20, QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Minimum)

        self.horizontalLayout_2.addItem(self.horizontalSpacer)

        self.verticalLayout.addLayout(self.horizontalLayout_2)

        self.horizontalLayout = QHBoxLayout()
        self.horizontalLayout.setObjectName(u"horizontalLayout")
        self.start_scan_button = QPushButton(self.centralwidget)
        self.start_scan_button.setObjectName(u"start_scan_button")

        self.horizontalLayout.addWidget(self.start_scan_button)

        self.stop_scan_button = QPushButton(self.centralwidget)
        self.stop_scan_button.setObjectName(u"stop_scan_button")

        self.horizontalLayout.addWidget(self.stop_scan_button)

        self.scan_progress_bar = QProgressBar(self.centralwidget)
        self.scan_progress_bar.setObjectName(u"scan_progress_bar")
        self.scan_progress_bar.setValue(24)

        self.horizontalLayout.addWidget(self.scan_progress_bar)

        self.verticalLayout.addLayout(self.horizontalLayout)

        self.network_table_view = QTableView(self.centralwidget)
        self.network_table_view.setObjectName(u"network_table_view")
        self.network_table_view.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.network_table_view.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.network_table_view.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.network_table_view.setSortingEnabled(True)

        self.verticalLayout.addWidget(self.network_table_view)

        MainWindow.setCentralWidget(self.centralwidget)
        self.menubar = QMenuBar(MainWindow)
        self.menubar.setObjectName(u"menubar")
        self.menubar.setGeometry(QRect(0, 0, 940, 22))
        MainWindow.setMenuBar(self.menubar)
        self.statusbar = QStatusBar(MainWindow)
        self.statusbar.setObjectName(u"statusbar")
        MainWindow.setStatusBar(self.statusbar)

        self.retranslateUi(MainWindow)

        QMetaObject.connectSlotsByName(MainWindow)

    # setupUi

    def retranslateUi(self, MainWindow):
        MainWindow.setWindowTitle(QCoreApplication.translate("MainWindow", u"MainWindow", None))
        self.start_scan_button.setText(QCoreApplication.translate("MainWindow", u"Start", None))
        self.stop_scan_button.setText(QCoreApplication.translate("MainWindow", u"Stop", None))
    # retranslateUi
