import json
import markdown
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel,
    QPushButton, QLineEdit, QScrollArea, QSizePolicy
)
from PyQt6.QtCore import QThread, pyqtSignal, Qt, QTimer

from src.core.intelligence_manager import IntelligenceManager

class AdvisorWorker(QThread):
    new_message = pyqtSignal(str)
    finished_successfully = pyqtSignal()

    def __init__(self, manager, user_query):
        super().__init__()
        self.manager = manager
        self.user_query = user_query

    def run(self):
        try:
            response = self.manager.get_response(self.user_query)
            self.new_message.emit(response)
        finally:
            self.finished_successfully.emit()

class AIAdvisorView(QWidget):
    # ▼▼▼ 新しいメッセージが追加されたことを通知するシグナル ▼▼▼
    message_added = pyqtSignal(dict) 

    def __init__(self, parent=None):
        super().__init__(parent)
        self.manager = IntelligenceManager()
        self.worker = None
        self.messages = []
        self.init_ui()

    def load_conversation(self, messages):
        """指定されたメッセージリストで、チャットビューを再構築する"""
        # 現在のチャット内容を全て削除
        while self.chat_layout.count() > 1:
            item = self.chat_layout.takeAt(0)
            widget = item.widget()
            if widget is not None:
                widget.deleteLater()
        self.messages.clear()
        
        # 新しいメッセージリストを元にUIを構築
        if not messages:
            self.add_message("こんにちは。私はあなた専属のAIセキュリティアドバイザーです。", is_user=False, save=False)
        else:
            for msg in messages:
                self.add_message(msg["text"], msg["is_user"], save=False)
        
        self.user_input.setEnabled(True)
        self.send_button.setEnabled(True)
        self.user_input.setFocus()


    def _calc_limits(self):
        chat_width = self.scroll_area.viewport().width()
        outer_max = int(chat_width * 0.85) 
        inner_max = max(1, outer_max - 20)
        return outer_max, inner_max

    def init_ui(self):
        # (init_uiの大部分は変更なし)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0) 
        self.scroll_area = QScrollArea()
        self.scroll_area.setWidgetResizable(True)
        self.scroll_area.setStyleSheet("QScrollArea { border: none; background-color: #1e1e1e; }")
        self.chat_container = QWidget()
        self.chat_layout = QVBoxLayout(self.chat_container)
        self.chat_layout.setContentsMargins(10, 10, 10, 10)
        self.chat_layout.setSpacing(15)
        self.chat_layout.addStretch()
        self.scroll_area.setWidget(self.chat_container)
        input_layout = QHBoxLayout()
        self.user_input = QLineEdit()
        self.user_input.setPlaceholderText("AIに質問や調査依頼をしてください...")
        self.send_button = QPushButton("送信")
        input_layout.addWidget(self.user_input)
        input_layout.addWidget(self.send_button)
        main_layout.addWidget(self.scroll_area)
        main_layout.addLayout(input_layout)
        self.send_button.clicked.connect(self.send_message)
        self.user_input.returnPressed.connect(self.send_message)
        # 起動時のメッセージ追加はMainWindow側で行うため、ここは削除

    def send_message(self):
        user_text = self.user_input.text().strip()
        if not user_text or (self.worker and self.worker.isRunning()):
            return

        self.add_message(user_text, is_user=True)
        self.user_input.clear()

        self.user_input.setEnabled(False)
        self.send_button.setEnabled(False)

        self.worker = AdvisorWorker(self.manager, user_text)
        self.worker.new_message.connect(lambda response: self.add_message(response, is_user=False))
        self.worker.finished_successfully.connect(
            lambda: (self.user_input.setEnabled(True), self.send_button.setEnabled(True), self.user_input.setFocus())
        )
        self.worker.start()

    def add_message(self, text, is_user, save=True):
        """メッセージを画面に追加し、必要なら保存シグナルを送信する"""
        # (UI構築部分は変更なし)
        outer_max, inner_max = self._calc_limits()
        label = QLabel()
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)
        label.setOpenExternalLinks(True)
        label.setMaximumWidth(inner_max)
        label.setSizePolicy(QSizePolicy.Policy.Preferred, QSizePolicy.Policy.Preferred)
        if is_user:
            label.setText(text)
        else:
            html_style = "<style>a { color: #a9d1ff; text-decoration: none; } p {margin:0;}</style>"
            html_text = markdown.markdown(text)
            label.setText(html_style + html_text)
        label.setStyleSheet("background-color: transparent; color: #f0f0f0; padding: 0px;")
        container = QWidget()
        container_layout = QHBoxLayout(container)
        container_layout.setContentsMargins(10, 10, 10, 10)
        container_layout.addWidget(label)
        container.setMaximumWidth(outer_max)
        container.setSizePolicy(QSizePolicy.Policy.Maximum, QSizePolicy.Policy.Preferred)
        if is_user:
            container.setStyleSheet("background-color: #2c3e50; border-radius: 10px;")
        else:
            container.setStyleSheet("background-color: #34495e; border-radius: 10px;")
        outer_layout = QHBoxLayout()
        outer_layout.setContentsMargins(0, 0, 0, 0)
        if is_user:
            outer_layout.addStretch(1)
            outer_layout.addWidget(container)
        else:
            outer_layout.addWidget(container)
            outer_layout.addStretch(1)
        row_widget = QWidget()
        row_widget.setLayout(outer_layout)
        self.chat_layout.insertWidget(self.chat_layout.count() - 1, row_widget)
        self.messages.append({"container": container, "label": label})
        
        # ▼▼▼ `save=True` の場合のみ、MainWindowに通知 ▼▼▼
        if save:
            self.message_added.emit({"text": text, "is_user": is_user})

        QTimer.singleShot(0, self._update_all_bubble_widths)
        QTimer.singleShot(50, lambda: self.scroll_area.verticalScrollBar().setValue(
            self.scroll_area.verticalScrollBar().maximum()
        ))

    def _update_all_bubble_widths(self):
        # (変更なし)
        if not self.messages: return
        outer_max, inner_max = self._calc_limits()
        for m in self.messages:
            m["label"].setMaximumWidth(inner_max)
            m["container"].setMaximumWidth(outer_max)
            m["label"].updateGeometry()
            m["container"].updateGeometry()

    def resizeEvent(self, event):
        # (変更なし)
        super().resizeEvent(event)
        QTimer.singleShot(0, self._update_all_bubble_widths)

    def shutdown(self):
        # (変更なし)
        if self.worker and self.worker.isRunning():
            self.worker.quit()
            self.worker.wait(2000)