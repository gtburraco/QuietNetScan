from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from models.network_object import NetworkObject


class NetworkTableViewModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._items: list[NetworkObject] = []

    # --- Qt overrides ---

    def rowCount(self, parent=QModelIndex()) -> int:
        return len(self._items)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 8

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
            return network_object.mac_address if network_object.mac_address is not None else "-"
        elif index.column() == 4:
            return network_object.vendor if network_object.vendor is not None else "-"
        elif index.column() == 5:
            return network_object.open_tcp_ports
        elif index.column() == 6:
            return network_object.open_udp_ports
        elif index.column() == 7:
            return network_object.discovery_method if network_object.discovery_method is not None else "-"
        return None

    def headerData(self, section: int, orientation: Qt.Orientation, role=Qt.ItemDataRole.DisplayRole):
        if role != Qt.ItemDataRole.DisplayRole:
            return None

        if orientation == Qt.Orientation.Horizontal:
            headers = ["Address", "TTL", "RTT", "MAC","VENDOR","OPEN_TCP","OPEN_UDP","FIND_METHOD"]
            if 0 <= section < len(headers):
                return headers[section]
            return None

        return str(section + 1)

    # --- API ViewModel ---

    def add_network_object(self, network_object: NetworkObject):
        row = len(self._items)
        self.beginInsertRows(QModelIndex(), row, row)
        self._items.append(network_object)
        self.endInsertRows()

    def clear(self):
        self.beginResetModel()
        self._items.clear()
        self.endResetModel()
