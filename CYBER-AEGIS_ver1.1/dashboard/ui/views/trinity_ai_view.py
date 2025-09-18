# dashboard/ui/views/trinity_ai_view.py
import json
import re
import markdown
import datetime # ★ 変更点: sim_id生成のためにdatetimeをインポート
from PyQt6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QTextEdit, QLabel, QSplitter,
    QListWidget, QListWidgetItem, QHBoxLayout, QMessageBox, QGroupBox,
    QCheckBox
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QSyntaxHighlighter, QTextCharFormat, QColor, QFont
from src.core_ai.white_team_ai import WhiteTeamAI
from src.database.db_manager import DBManager

class PythonHighlighter(QSyntaxHighlighter):
    def __init__(self, parent):
        super().__init__(parent)
        self.highlighting_rules = []

        keyword_format = QTextCharFormat()
        keyword_format.setForeground(QColor("#569CD6"))
        keywords = ["def", "class", "import", "from", "return", "if", "else", "elif", "for", "while", "in", "and", "or", "not", "True", "False", "None"]
        self.highlighting_rules.extend([(f"\\b{word}\\b", keyword_format) for word in keywords])

        string_format = QTextCharFormat()
        string_format.setForeground(QColor("#CE9178"))
        self.highlighting_rules.append(("'[^']*'", string_format))
        self.highlighting_rules.append(('"[^"]*"', string_format))
        
        comment_format = QTextCharFormat()
        comment_format.setForeground(QColor("#6A9955"))
        self.highlighting_rules.append(("#[^\n]*", comment_format))

    def highlightBlock(self, text):
        for pattern, format in self.highlighting_rules:
            for match in re.finditer(pattern, text):
                self.setFormat(match.start(), match.end() - match.start(), format)

class SimulationWorker(QThread):
    simulation_complete = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)

    def __init__(self, fast_mode=False):
        super().__init__()
        self.fast_mode = fast_mode

    def run(self):
        try:
            white_team = WhiteTeamAI(fast_mode=self.fast_mode)
            
            # ★ 変更点: white_team.pyのrun_full_simulationに合わせてsim_idを生成して渡す
            sim_id = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
            result = white_team.run_full_simulation(sim_id)
            
            self.simulation_complete.emit(result)
        except Exception as e:
            import traceback
            self.error_occurred.emit(f"シミュレーション中にエラーが発生しました: {e}\n{traceback.format_exc()}")

class TrinityAIView(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.db_manager = DBManager()
        self.simulation_worker = None
        
        main_layout = QHBoxLayout(self)
        left_panel = QWidget()
        left_layout = QVBoxLayout(left_panel)
        left_panel.setFixedWidth(250)
        
        self.fast_mode_checkbox = QCheckBox("超高速開発モード (AI思考スキップ)")
        self.fast_mode_checkbox.setToolTip("チェックを入れると、AIの応答を待たずに固定の応答を返し、システム全体の動作を高速にテストできます。")
        left_layout.addWidget(self.fast_mode_checkbox)
        
        history_label = QLabel("シミュレーション履歴 (ダブルクリックで削除)")
        history_label.setStyleSheet("font-weight: bold;")
        self.history_list = QListWidget()
        self.history_list.currentItemChanged.connect(self.display_simulation_result)
        self.history_list.itemDoubleClicked.connect(self.on_history_item_double_clicked)
        
        left_layout.addWidget(history_label)
        left_layout.addWidget(self.history_list)

        right_panel = QWidget()
        right_layout = QVBoxLayout(right_panel)
        
        self.run_button = QPushButton("🚀 AI攻防演習を開始")
        self.run_button.setStyleSheet("font-size: 14px; padding: 10px;")
        self.run_button.clicked.connect(self.run_simulation)
        right_layout.addWidget(self.run_button)
        
        self.results_splitter = QSplitter(Qt.Orientation.Horizontal)
        
        left_splitter = QSplitter(Qt.Orientation.Vertical)
        self.red_team_output = self._create_output_area("🔴 Red Team AI (全戦闘ログ)")
        self.blue_team_output = self._create_output_area("🔵 Blue Team AI (最終イベントログ)")
        left_splitter.addWidget(self.red_team_output)
        left_splitter.addWidget(self.blue_team_output)

        right_splitter = QSplitter(Qt.Orientation.Vertical)
        self.white_team_report = self._create_output_area("⚪ White Team AI (総合演習レポート)")
        self.generated_code_area = self._create_code_area("💡 自己生成アップグレードモジュール (Python)")
        right_splitter.addWidget(self.white_team_report)
        right_splitter.addWidget(self.generated_code_area)
        right_splitter.setSizes([250, 450])

        self.results_splitter.addWidget(left_splitter)
        self.results_splitter.addWidget(right_splitter)
        right_layout.addWidget(self.results_splitter)
        main_layout.addWidget(left_panel)
        main_layout.addWidget(right_panel, 1)
        self.load_history()

    def _create_output_area(self, title):
        group_box = QGroupBox(title)
        layout = QVBoxLayout(group_box)
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        layout.addWidget(text_edit)
        group_box.text_edit = text_edit
        return group_box

    def _create_code_area(self, title):
        group_box = QGroupBox(title)
        layout = QVBoxLayout(group_box)
        text_edit = QTextEdit()
        text_edit.setReadOnly(True)
        font = QFont("Courier New")
        font.setPointSize(10)
        text_edit.setFont(font)
        self.highlighter = PythonHighlighter(text_edit.document())
        layout.addWidget(text_edit)
        group_box.text_edit = text_edit
        return group_box

    def run_simulation(self):
        self.run_button.setText("🧠 AI演習を実行中...")
        self.run_button.setEnabled(False)
        self.clear_displays()
        
        use_fast_mode = self.fast_mode_checkbox.isChecked()
        
        self.simulation_worker = SimulationWorker(fast_mode=use_fast_mode)
        self.simulation_worker.simulation_complete.connect(self.on_simulation_finished)
        self.simulation_worker.error_occurred.connect(self.on_simulation_error)
        self.simulation_worker.start()

    def on_simulation_finished(self, result):
        self.run_button.setText("🚀 AI攻防演習を開始")
        self.run_button.setEnabled(True)
        QMessageBox.information(self, "完了", "AI攻防演習が完了しました。")
        self.display_full_result(result)
        self.load_history()

    def on_simulation_error(self, error_message):
        self.run_button.setText("🚀 AI攻防演習を開始")
        self.run_button.setEnabled(True)
        QMessageBox.critical(self, "エラー", error_message)

    def load_history(self):
        self.history_list.clear()
        simulations = self.db_manager.get_all_trinity_simulations()
        for sim in simulations:
            item = QListWidgetItem(f"ID:{sim['id']}: {sim['simulation_time']}")
            item.setData(Qt.ItemDataRole.UserRole, sim['id'])
            self.history_list.addItem(item)
        if self.history_list.count() > 0:
            self.history_list.setCurrentRow(0)

    def display_simulation_result(self, current_item, _):
        if not current_item: return
        sim_id = current_item.data(Qt.ItemDataRole.UserRole)
        simulations = self.db_manager.get_trinity_simulation_by_id(sim_id)
        if simulations:
            display_data = {
                "red_team_output": simulations.get('red_team_output'),
                "blue_team_output": simulations.get('blue_team_output'),
                "white_team_report": simulations.get('white_team_report'),
                "generated_code": self.db_manager.get_system_learning_by_sim_id(sim_id)
            }
            self.display_full_result(display_data)

    def display_full_result(self, result_dict):
        self.red_team_output.text_edit.setText(result_dict.get('red_team_output', ''))
        self.blue_team_output.text_edit.setText(result_dict.get('blue_team_output', ''))
        
        report_md = result_dict.get('white_team_report', '')
        report_html = markdown.markdown(report_md, extensions=['fenced_code', 'tables'])
        self.white_team_report.text_edit.setHtml(report_html)
        
        self.generated_code_area.text_edit.setText(result_dict.get('generated_code', "# この演習ではコードは生成されませんでした。"))
        
    def clear_displays(self):
        self.red_team_output.text_edit.clear()
        self.blue_team_output.text_edit.clear()
        self.white_team_report.text_edit.clear()
        self.generated_code_area.text_edit.clear()

    def on_history_item_double_clicked(self, item):
        if not item: return
        
        sim_id = item.data(Qt.ItemDataRole.UserRole)
        sim_text_parts = item.text().split(': ')
        sim_time = f"{sim_text_parts[1]}:{sim_text_parts[2]}:{sim_text_parts[3]}" if len(sim_text_parts) > 3 else "時刻不明"

        reply = QMessageBox.question(
            self,
            '削除の確認',
            f"本当にシミュレーション履歴を削除しますか？\n\nID: {sim_id}\n時刻: {sim_time}\n\nこの操作は元に戻せません。",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
            QMessageBox.StandardButton.No
        )

        if reply == QMessageBox.StandardButton.Yes:
            success = self.db_manager.delete_trinity_simulation(sim_id)
            if success:
                row = self.history_list.row(item)
                self.history_list.takeItem(row)
                QMessageBox.information(self, "完了", f"履歴 (ID: {sim_id}) を削除しました。")
                if self.history_list.count() == 0:
                    self.clear_displays()
            else:
                QMessageBox.critical(self, "エラー", "データベースからの履歴削除に失敗しました。")