from . import QT6

if QT6:
    from PySide6.QtCore import *
    from PySide6.QtCore import Signal, Slot
else:
    from PyQt5.QtCore import *
    from PyQt5.QtCore import pyqtSignal as Signal, pyqtSlot as Slot
