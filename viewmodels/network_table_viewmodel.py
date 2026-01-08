import ipaddress

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt

from models.network_object import NetworkObject


class NetworkTableViewModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._items: list[NetworkObject] = []
        self.headers = ["Address", "TTL", "RTT", "MAC", "VENDOR", "OPEN_TCP", "OPEN_UDP", "OS", "FIND_METHOD"]

    # --- Qt overrides ---

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._items)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 9

    def data(self, index: QModelIndex, role=Qt.ItemDataRole.DisplayRole):
        if not index.isValid() or role != Qt.ItemDataRole.DisplayRole:
            return None

        network_object = self._items[index.row()]

        if index.column() == 0:
            return network_object.address
        elif index.column() == 1:
            # Mostra TTL o "-" se None
            return str(network_object.ttl) if network_object.ttl is not None else "-"
        elif index.column() == 2:
            # Mostra TTL o "-" se None
            return f"{network_object.rtt:.2f}" if network_object.rtt is not None else "-"
        elif index.column() == 3:
            return network_object.mac if network_object.mac is not None else "-"
        elif index.column() == 4:
            return network_object.vendor if network_object.vendor is not None else "-"
        elif index.column() == 5:
            return network_object.open_tcp_ports
        elif index.column() == 6:
            return network_object.open_udp_ports
        elif index.column() == 7:
            return network_object.os
        elif index.column() == 8:
            return network_object.discovery_method if network_object.discovery_method is not None else "-"
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None

        if orientation == Qt.Orientation.Horizontal:

            if 0 <= section < len(self.headers):
                return self.headers[section]
            return None

        return str(section + 1)

    # --- API ViewModel ---

    def add_network_object(self, network_object: NetworkObject):
        row = len(self._items)
        self.beginInsertRows(QModelIndex(), row, row)
        self._items.append(network_object)
        self.endInsertRows()

    def sort(self, column: int, order: Qt.SortOrder = Qt.SortOrder.AscendingOrder) -> None:
        if column == 0:  # colonna IP
            self._items.sort(
                key=lambda o: ipaddress.ip_address(o.address),
                reverse=(order == Qt.SortOrder.DescendingOrder)
            )
        else:
            self._items.sort(
                key=lambda o: getattr(o, self.headers[column].lower(), ""),
                reverse=(order == Qt.SortOrder.DescendingOrder)
            )
        self.layoutChanged.emit()

    def clear(self):
        self.beginResetModel()
        self._items.clear()
        self.endResetModel()
