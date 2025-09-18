import os
import sys
import json
import datetime

# プロジェクトのルートディレクトリをPythonのパスに追加
project_root = os.path.abspath(os.path.dirname(__file__))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from src.database.db_manager import get_session, init_db_schema
from src.database.models import SigmaMatch

def run_test():
    """
    データベースのsigma_matchesテーブルへの書き込みをテストする関数
    """
    print("--- データベース書き込み単体テストを開始します ---")

    # 1. データベーススキーマを初期化
    #    これにより、db_managerが初期化され、テーブルが確実に作成されます
    try:
        print("[ステップ1] データベーススキーマを初期化しています...")
        init_db_schema()
        print(" -> 完了")
    except Exception as e:
        print(f" !!! エラー: データベーススキーマの初期化に失敗しました: {e}")
        import traceback
        traceback.print_exc()
        return

    # 2. データベースセッションを取得
    try:
        print("[ステップ2] データベースセッションを取得しています...")
        session = get_session()
        print(" -> 完了")
    except Exception as e:
        print(f" !!! エラー: データベースセッションの取得に失敗しました: {e}")
        import traceback
        traceback.print_exc()
        return

    # 3. テスト用のデータを作成してデータベースに追加
    try:
        print("[ステップ3] テストデータをデータベースに追加しています...")
        test_match = SigmaMatch(
            rule_title="単体テスト用ルール",
            rule_level="high",
            log_source=json.dumps({"test_source": "local"}),
            detection_details=json.dumps({"condition": "test"}),
            log_entry=json.dumps({"message": "これは単体テストのログエントリです。"}),
            timestamp=datetime.datetime.now()
        )
        session.add(test_match)
        print(" -> session.add() 成功")
    except Exception as e:
        print(f" !!! エラー: SigmaMatchオブジェクトの作成またはセッションへの追加に失敗しました: {e}")
        import traceback
        traceback.print_exc()
        session.rollback()
        return

    # 4. 変更をコミット
    try:
        print("[ステップ4] データベースに変更をコミットしています...")
        session.commit()
        print(" -> session.commit() 成功！")
        print("\n[成功] テストデータが正常にデータベースに書き込まれました。")
    except Exception as e:
        print(f" !!! エラー: データベースへのコミットに失敗しました: {e}")
        import traceback
        traceback.print_exc()
        session.rollback()
    finally:
        session.close()
        print("\n--- データベース書き込み単体テストを終了します ---")


if __name__ == "__main__":
    # aegis.dbがもしあれば、クリーンな状態でテストするために削除
    if os.path.exists("aegis.db"):
        print("古いaegis.dbファイルを削除します。")
        os.remove("aegis.db")
    run_test()