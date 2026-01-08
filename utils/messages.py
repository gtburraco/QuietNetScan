from PySide6.QtWidgets import QWidget, QMessageBox


def show_error(parent: QWidget, e: Exception, text: str):
    msg = QMessageBox(
        QMessageBox.Icon.Critical,
        parent.tr("Error"),
        text,
        QMessageBox.StandardButton.Ok,
        parent
    )
    if e is not None:
        msg.setDetailedText(str(e))
    msg.exec()


def show_warning(parent: QWidget, text: str, details: str = None):
    msg = QMessageBox(
        QMessageBox.Icon.Warning,
        parent.tr("Warning"),
        text,
        QMessageBox.StandardButton.Ok,
        parent
    )
    if details:
        msg.setDetailedText(details)
    msg.exec()


def show_info(parent: QWidget, text: str, details: str = None):
    msg = QMessageBox(
        QMessageBox.Icon.Information,
        parent.tr("Information"),
        text,
        QMessageBox.StandardButton.Ok,
        parent
    )
    if details:
        msg.setDetailedText(details)
    msg.exec()


def show_question(parent: QWidget, text: str, details: str = None) -> bool:
    return QMessageBox.question(parent, parent.tr("Question"), text,
                                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                                QMessageBox.StandardButton.No) == QMessageBox.StandardButton.Yes
