# CYBER-AEGIS/src/reporting/pdf_generator.py

import os
from PyQt6.QtWidgets import QFileDialog
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.lib import colors
from html.parser import HTMLParser

class PDFTextExtractor(HTMLParser):
    """HTMLから本文のテキストとタグ情報を抽出する、状態管理付きパーサー"""
    def __init__(self):
        super().__init__()
        self.reset()
        self.fed = []
        self.current_style_tags = []
        self.in_body = False # --- bodyタグ内にいるかどうかのフラグ ---

    def handle_starttag(self, tag, attrs):
        if tag == 'body':
            self.in_body = True
            return
        if self.in_body:
            self.current_style_tags.append(tag)

    def handle_endtag(self, tag):
        if tag == 'body':
            self.in_body = False
            return
        if self.in_body and self.current_style_tags and self.current_style_tags[-1] == tag:
            self.current_style_tags.pop()

    def handle_data(self, d):
        # bodyタグ内にいる場合のみデータを処理
        if self.in_body:
            text = d.strip()
            if text:
                self.fed.append(('/'.join(self.current_style_tags), text))

    def get_data(self):
        return self.fed

class PDFGenerator:
    def __init__(self):
        self.default_font = 'Times-Roman'
        self.setup_fonts()
        self.styles = self.get_pdf_styles()
        
    def setup_fonts(self):
        local_font_path = "ipaexg.ttf"
        if os.path.exists(local_font_path):
            pdfmetrics.registerFont(TTFont('Japanese-Gothic', local_font_path))
            self.default_font = 'Japanese-Gothic'
            return
        try:
            win_font_path = "C:/Windows/Fonts/YuGothR.ttc"
            if os.path.exists(win_font_path):
                pdfmetrics.registerFont(TTFont('Japanese-Gothic', win_font_path))
                self.default_font = 'Japanese-Gothic'
            else:
                print("警告: 日本語フォントが見つかりませんでした。")
        except Exception as e:
            print(f"フォント登録エラー: {e}")

    def get_pdf_styles(self):
        styles = getSampleStyleSheet()
        styles['Normal'].fontName = self.default_font
        styles['h1'].fontName = self.default_font
        styles['h2'].fontName = self.default_font
        styles['h3'].fontName = self.default_font
        styles.add(ParagraphStyle(name='p', parent=styles['Normal'], fontName=self.default_font))
        styles['h1'].fontSize = 24; styles['h1'].leading = 28; styles['h1'].spaceAfter = 20
        styles['h2'].fontSize = 18; styles['h2'].leading = 22; styles['h2'].spaceAfter = 15; styles['h2'].textColor = colors.HexColor("#575fcf")
        styles['h3'].fontSize = 14; styles['h3'].leading = 18; styles['h3'].spaceAfter = 10; styles['h3'].textColor = colors.HexColor("#aab0b8")
        return styles

    def html_to_flowables(self, html_content):
        parser = PDFTextExtractor()
        parser.feed(html_content)
        data = parser.get_data()
        
        flowables = []
        for tags, text in data:
            style = self.styles['p']
            if 'h2' in tags:
                style = self.styles['h2']
            elif 'h3' in tags:
                style = self.styles['h3']
            
            if 'strong' in tags:
                text = f"<b>{text}</b>"

            flowables.append(Paragraph(text, style))
        
        return flowables

    def generate_pdf_from_html(self, html_content, parent_widget=None):
        default_filename = "CYBER-AEGIS-Report.pdf"
        save_path, _ = QFileDialog.getSaveFileName(parent_widget, "PDFレポートを保存", default_filename, "PDF Files (*.pdf)")

        if not save_path:
            return False, "保存がキャンセルされました。"

        doc = SimpleDocTemplate(save_path)
        story = [Paragraph("CYBER-AEGIS 分析レポート", self.styles['h1']), Spacer(1, 24)]

        # --- 全文をパーサーに渡すように修正 ---
        story.extend(self.html_to_flowables(html_content))
        
        try:
            doc.build(story)
            return True, save_path
        except Exception as e:
            print(f"PDF生成エラー: {e}")
            return False, str(e)