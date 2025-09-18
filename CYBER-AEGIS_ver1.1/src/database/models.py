from sqlalchemy import Column, Integer, String, DateTime, Text
from sqlalchemy.orm import declarative_base
import datetime

# すべてのSQLAlchemyモデルクラスが継承するための「Base」クラスを定義
Base = declarative_base()

#
# --- 将来的には、既存のテーブルもこのファイルでクラスとして定義し、 ---
# --- db_manager.py の CREATE TABLE文を削除していくと、より管理しやすくなります ---
#

class SigmaMatch(Base):
    """SIGMAルールのマッチング結果を保存するためのテーブルモデル"""
    __tablename__ = 'sigma_matches'
    
    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=datetime.datetime.now)
    rule_title = Column(String)
    rule_level = Column(String)
    
    # --- ▼ここから修正 (最終ロジック) ---
    # String型からText型へ変更し、長いJSON文字列を保存できるようにする
    log_source = Column(Text)
    # --- ▲ここまで修正 ---
    
    detection_details = Column(Text)
    log_entry = Column(Text)