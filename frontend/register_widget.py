import functools

from PySide6.QtGui import QFont, QFontMetrics
from PySide6.QtWidgets import (
    QLineEdit,
    QHBoxLayout,
    QVBoxLayout,
    QWidget,
    QGridLayout,
    QLabel,
    QPushButton,
    QMenu,
    QApplication,
)
from PySide6 import QtGui, QtWidgets
from PySide6.QtCore import Qt, QPoint, QEvent, QSize

from core import Ctx

TextSelectableByMouse = Qt.TextInteractionFlag.TextSelectableByMouse


class RegistersWidget(QtWidgets.QWidget):
    ctx: Ctx
    names: list[str]
    value_labels: list[QLabel]

    def __init__(self, ctx: Ctx):
        super().__init__()

        self.ctx = ctx
        self.ctx.register_time_observer(self)

        self.names = []

        db_names = self.ctx.db.register_names()
        for name in ctx.arch.all_register_names():
            if name not in db_names:
                print(f"[Warning] register '{name}' not in the trace data")
                continue
            db_names.remove(name)
            self.names.append(name)

        self.names.extend(db_names)  # add unknown registers

        self.value_labels = []

        self.setup_ui()
        # compact: take only the width the register list needs
        self.setSizePolicy(QtWidgets.QSizePolicy.Policy.Maximum, QtWidgets.QSizePolicy.Policy.Preferred)
        self.on_time_update()

    def sizeHint(self) -> QSize:
        hint = super().sizeHint()
        return QSize(self._grid.sizeHint().width() + 12, max(hint.height(), 300))

    def close(self) -> bool:
        is_closed = super().close()
        if is_closed:
            self.ctx.unregister_time_observer(self)
        return is_closed

    def setup_ui(self) -> None:
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        self.setLayout(main_layout)

        time_layout = QHBoxLayout()
        time_layout.setContentsMargins(0, 0, 0, 0)

        self.time_edit = QLineEdit()
        self.time_edit.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.time_edit.setMaximumWidth(120)
        self.time_edit.returnPressed.connect(self.on_time_edit)

        time_layout.addStretch()
        time_layout.addWidget(self.time_edit)
        time_layout.addStretch()

        main_layout.addLayout(time_layout)

        h_layout = QHBoxLayout()
        h_layout.setContentsMargins(0, 0, 0, 0)
        grid_widget = QWidget()
        layout = QGridLayout(grid_widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setHorizontalSpacing(2)
        layout.setVerticalSpacing(1)
        self._grid = grid_widget

        font_name = QFont("monospace")
        font_name.setStyleHint(QtGui.QFont.StyleHint.Monospace)
        font_name.setBold(True)

        font_value = QFont("monospace")
        font_value.setStyleHint(QtGui.QFont.StyleHint.Monospace)

        metrics = QFontMetrics(font_value)
        max_val_width = metrics.horizontalAdvance("0x0000000000000000") + 4

        for idx, reg_name in enumerate(self.names):
            btn_prev = QPushButton("<")
            btn_prev.setFixedSize(12, 16)
            btn_prev.setStyleSheet("border: none; margin: 0px; padding: 0px;")
            btn_prev.setCursor(Qt.CursorShape.PointingHandCursor)
            btn_prev.clicked.connect(functools.partial(self.nav_prev, reg_name))

            label_name = QLabel(reg_name + ":")
            label_name.setFont(font_name)
            label_name.setAlignment(
                Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter
            )

            label_value = QLabel()
            label_value.setFont(font_value)
            label_value.setFixedWidth(max_val_width)
            label_value.setAlignment(Qt.AlignmentFlag.AlignCenter)
            label_value.setTextInteractionFlags(TextSelectableByMouse)
            label_value.setToolTip("Double-click: show this address in the Memory window")
            label_value.installEventFilter(self)

            label_value.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)

            label_value.customContextMenuRequested.connect(
                functools.partial(self.show_context_menu, label_value)
            )

            self.value_labels.append(label_value)

            btn_next = QPushButton(">")
            btn_next.setFixedSize(12, 16)
            btn_next.setStyleSheet("border: none; margin: 0px; padding: 0px;")
            btn_next.setCursor(Qt.CursorShape.PointingHandCursor)
            btn_next.clicked.connect(functools.partial(self.nav_next, reg_name))

            layout.addWidget(btn_prev, idx, 0)
            layout.addWidget(label_name, idx, 1)
            layout.addWidget(label_value, idx, 2)
            layout.addWidget(btn_next, idx, 3)

        h_layout.addStretch()
        h_layout.addWidget(grid_widget)
        h_layout.addStretch()

        main_layout.addLayout(h_layout)
        main_layout.addStretch()

    def show_context_menu(self, value_label: QLabel, pos: QPoint) -> None:
        menu = QMenu(self)
        copy_action = menu.addAction("Copy Value")
        mem_action = menu.addAction("Show in Memory window")
        mem_action.setEnabled(self._label_value(value_label) is not None)

        global_pos = value_label.mapToGlobal(pos)
        action = menu.exec(global_pos)

        if action == copy_action:
            clipboard = QApplication.clipboard()
            clipboard.setText(value_label.text())
        elif action == mem_action:
            self._show_in_memory(value_label)

    @staticmethod
    def _label_value(value_label: QLabel):
        try:
            return int(value_label.text(), 16)
        except ValueError:
            return None  # "<undefined>"

    def _show_in_memory(self, value_label: QLabel) -> None:
        value = self._label_value(value_label)
        if value is not None:
            self.ctx.goto_memory(value)

    def eventFilter(self, obj, event) -> bool:
        if event.type() == QEvent.Type.MouseButtonDblClick and obj in self.value_labels:
            self._show_in_memory(obj)
            return True
        return super().eventFilter(obj, event)

    def on_time_edit(self) -> None:
        try:
            new_time = int(self.time_edit.text(), 0)
        except ValueError:
            self.time_edit.setText(str(self.ctx.db.time))
        self.ctx.set_time(new_time)

    def nav_prev(self, reg_name: str) -> None:
        snapshot = self.ctx.db.registers_snapshot()
        reg = snapshot.reg(reg_name)
        if reg is not None and reg.prev_time is not None:
            self.ctx.set_time(reg.prev_time)

    def nav_next(self, reg_name: str) -> None:
        snapshot = self.ctx.db.registers_snapshot()
        reg = snapshot.reg(reg_name)
        if reg is not None and reg.next_time is not None:
            self.ctx.set_time(reg.next_time)

    def on_time_update(self) -> None:
        time = self.ctx.db.time
        self.time_edit.setText(str(time))

        snapshot = self.ctx.db.registers_snapshot()

        for reg_name, value_label in zip(self.names, self.value_labels):
            reg = snapshot.reg(reg_name)
            if reg is None:
                continue  # should never happen

            if reg.value is None:
                val_str = "<undefined>"
            else:
                val_str = hex(reg.value)

            value_label.setText(val_str)

            if reg.value is None:
                value_label.setStyleSheet("color: gray;")
            elif reg.has_just_changed:
                value_label.setStyleSheet("color: red;")
            else:
                value_label.setStyleSheet("")
