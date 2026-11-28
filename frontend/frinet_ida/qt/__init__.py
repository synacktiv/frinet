"""
Generic QT bindings starting from IDA 9.0
"""

import ctypes

import ida_kernwin
import ida_pro

QT6 = ida_pro.IDA_SDK_VERSION >= 920


def mouse_position(event):
    if QT6:
        return event.position()
    else:
        return event.localPos()


def wheel_position(event):
    if QT6:
        return event.position()
    else:
        return event.posF()


_capsule_pointer = ctypes.PYFUNCTYPE(ctypes.c_void_p, ctypes.py_object, ctypes.c_char_p)(
    ("PyCapsule_GetPointer", ctypes.pythonapi)
)


def twidget_to_qwidget(twidget):
    """
    QWidget of an IDA TWidget, or of the form given to PluginForm.OnCreate.
    Not PluginForm.TWidgetToPyQtWidget: from IDA 9.1, it wraps the widget with
    PySide6 whenever PySide6 can be imported, even in the Qt 5 IDA 9.1.
    """
    if type(twidget).__name__ == "SwigPyObject":
        address = int(twidget)
    else:
        # a PyCapsule
        address = _capsule_pointer(twidget, ida_kernwin.PluginForm.VALID_CAPSULE_NAME)
    if not address:
        raise ValueError("null TWidget")

    from .QtWidgets import QWidget

    if QT6:
        from shiboken6 import wrapInstance
    else:
        from PyQt5.sip import wrapinstance as wrapInstance
    return wrapInstance(address, QWidget)
