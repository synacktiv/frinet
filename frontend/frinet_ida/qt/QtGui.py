from . import QT6

if QT6:
    from PySide6.QtGui import *
else:
    from PyQt5.QtGui import *
    from PyQt5.QtWidgets import QAction, QActionGroup, QShortcut
