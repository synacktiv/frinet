from . import QT6

if QT6:
    from PySide6.QtWidgets import *
else:
    from PyQt5.QtWidgets import *
