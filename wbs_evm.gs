// スクリプトプロパティや固定のメールアドレスの代わりに、ここに担当者とメールアドレスのマッピングを定義します。
const TARGET_ASSIGNEES_MAP = {
  "メンバー１": "example1@com",
  "メンバー２": "example2@com",
  "メンバー３": "example3@com",
  "メンバー４": "example4@com",
  "メンバー５": "example5@com",
  "メンバー６": "example6@com"
  // 必要に応じて他の担当者も追加
};

// 優先度の背景色定義
const PRIORITY_COLORS = {
  "高": "#f4cccc", // 薄い赤 (Google Sheets Light red 3)
  "中": "#fff2cc", // 薄い黄 (Google Sheets Light yellow 3)
  "低": null       // 無色
};

const SEARCH_PLACEHOLDER_TEXT = "ここにIDまたは作業名を入力";
const SEARCH_PLACEHOLDER_COLOR = "#999999"; // 薄いグレー
const SEARCH_INPUT_COLOR = "#000000"; // 通常の黒
const SEARCH_INPUT_BACKGROUND = "#f0f0f0"; // グレー背景
const WBS_DATA_COLUMN_COUNT = 19; // WBS_Dataシートの主要データ列の数 (IDからコメントまで)

/**
 * WBSとガントチャート、EVM表示の初期シート構成を作成します。
 */
function createInitialSheets() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();

  // --- WBS_Data シート ---
  let wbsSheet = ss.getSheetByName("WBS_Data");
  if (!wbsSheet) {
    wbsSheet = ss.insertSheet("WBS_Data");
  } else {
    wbsSheet.clear();
    wbsSheet.clearFormats();
    let rangeProtections = wbsSheet.getProtections(SpreadsheetApp.ProtectionType.RANGE);
    rangeProtections.forEach(p => p.remove());
    wbsSheet.clearConditionalFormatRules();
  }

  const headers = [
    "ID", "作業名", "親タスクID", "階層レベル", "タスクタイプ", "開始日", "終了日",
    "予定作業時間", "実績作業時間", "担当者", "進捗度 (%)", "優先度", "ステータス",
    "依存関係", "成果物", "リスクレベル", "リスク内容",
    "詳細内容", "備考", "コメント"
  ];
  const headerRange = wbsSheet.getRange(1, 1, 1, headers.length);
  headerRange.setValues([headers])
    .setFontWeight("bold")
    .setWrap(true)
    .setVerticalAlignment("middle")
    .setBackground("#c8e6c9");
  wbsSheet.setFrozenRows(1);

  const inputHints = [
    "自動ID(編集禁止)", "タスクの名称", "上位タスクのID", "例: 大機能,中機能,小機能", "例: 設計,開発,テスト", "例: 2025/5/22", "例: 2025/5/25",
    "予定時間(例:10)", "実績時間(例:12)", "担当者(カンマ区切り)", "0-100%", "高/中/低", "例:未着手,進行中,完了",
    "依存タスクID(例:1,2)", "タスクの成果物", "高/中/低", "リスク詳細",
    "補足事項", "その他特記事項", "作業履歴や連絡事項"
  ];
  const hintRowRange = wbsSheet.getRange(2, 1, 1, headers.length);
  hintRowRange.setValues([inputHints])
    .setFontStyle("italic")
    .setBackground("#fff9c4")
    .setWrap(true)
    .setVerticalAlignment("middle");

  // 検索機能用ラベルと入力セルの設定 (V2, W2)
  const searchLabelCell = wbsSheet.getRange("V2");
  searchLabelCell.setValue("検索(ID/作業名):")
      .setFontStyle("italic")
      .setBackground("#e0e0e0")
      .setHorizontalAlignment("right")
      .setVerticalAlignment("middle");

  const searchInputCell = wbsSheet.getRange("W2");
  searchInputCell.setValue(SEARCH_PLACEHOLDER_TEXT)
      .setFontColor(SEARCH_PLACEHOLDER_COLOR)
      .setBackground(SEARCH_INPUT_BACKGROUND)
      .setBorder(true, true, true, true, true, true, "#888888", SpreadsheetApp.BorderStyle.SOLID_THIN) // 罫線
      .setVerticalAlignment("middle");

  wbsSheet.setColumnWidth(22, 120); // V列の幅
  wbsSheet.setColumnWidth(23, 200); // W列の幅


  const today = new Date();
  const threeDaysLater = new Date(today.getTime() + 3 * 24 * 60 * 60 * 1000);
  const exampleRow = [ // IDを0に変更
    "0", "【サンプルタスク】プロジェクト計画作成", "", "大機能", "計画", today, threeDaysLater,
    20, 0, "山田太郎", 0, "高", "未着手",
    "", "プロジェクト計画書v1", "中", "スコープ変更の可能性",
    "初期計画の策定", "", ""
  ];
  wbsSheet.getRange(3, 1, 1, exampleRow.length).setValues([exampleRow]).setBackground("#f0f0f0");
  applyWbsDataRowFormatting(wbsSheet, 3); // サンプル行にもフォーマット適用

  const wbsColWidths = [
     60, 250,  80, 120, 100, 100, 100,
    100, 100, 150,  80,  70, 100,
    100, 150,  80, 200,
    200, 200, 200
  ];
  for (let i = 0; i < headers.length; i++) { // headers.length は WBS_DATA_COLUMN_COUNT と同じはず
    wbsSheet.getRange(1, i + 1, wbsSheet.getMaxRows(), 1).setWrap(true);
    if (i < wbsColWidths.length) {
      wbsSheet.setColumnWidth(i + 1, wbsColWidths[i]);
    }
  }

  if (wbsSheet.getMaxRows() >= 3) {
    wbsSheet.getRange(3, 1, wbsSheet.getMaxRows() - 2, headers.length).setVerticalAlignment("top");
  }

  const borderLastRow = 305;
  const borderLastCol = headers.length; // WBS_DATA_COLUMN_COUNT
  wbsSheet.getRange(1, 1, borderLastRow, borderLastCol).setBorder(true, true, true, true, true, true, "#d9d9d9", SpreadsheetApp.BorderStyle.SOLID_MEDIUM);
  wbsSheet.getRange(1, 1, 1, borderLastCol).setBorder(null, null, true, null, null, null, "#000000", SpreadsheetApp.BorderStyle.SOLID_THICK);
  wbsSheet.getRange(2, 1, 1, borderLastCol).setBorder(null, null, true, null, null, null, "#000000", SpreadsheetApp.BorderStyle.SOLID_THICK);
  wbsSheet.getRange("V2:W2").setBorder(null, null, true, null, null, null, "#000000", SpreadsheetApp.BorderStyle.SOLID_THICK); //検索セルの下罫線太く

  protectIDColumn(wbsSheet);

  // --- Gantt_Chart シート ---
  let ganttSheet = ss.getSheetByName("Gantt_Chart");
  if (!ganttSheet) ganttSheet = ss.insertSheet("Gantt_Chart");
  else { ganttSheet.clear(); ganttSheet.clearFormats(); }
  ganttSheet.getRange(1, 1).setValue("ガントチャートはWBS_Dataシートの編集後に自動更新されます。");

  // --- EVM_Display シート ---
  let evmSheet = ss.getSheetByName("EVM_Display");
  if (!evmSheet) evmSheet = ss.insertSheet("EVM_Display");
  else { evmSheet.clear(); evmSheet.clearFormats(); }
  evmSheet.getRange(1,1).setValue("EVMデータとグラフはWBS_Dataシートの編集後に自動更新されます。\nEVM計算には「予定作業時間」「実績作業時間」「進捗度」が使用されます。").setFontWeight("normal").setWrap(true);

  // --- How_To_Use シート ---
  let howToUseSheet = ss.getSheetByName("How_To_Use");
  if (!howToUseSheet) howToUseSheet = ss.insertSheet("How_To_Use");
  else { howToUseSheet.clear(); howToUseSheet.clearFormats(); }
  const explanation = [
    ["このスプレッドシートの使い方"],
    [""],
    ["1. WBS_Data シートに作業情報を入力してください。"],
    ["  - ID列は自動で割り振られます。直接入力しないでください。ID '0' はサンプルタスク専用です。"],
    ["  - 主要項目 (作業名, 親タスクID, 階層レベル, タスクタイプ, 開始日, 終了日, 予定/実績作業時間, 担当者, 進捗度, 優先度, ステータスなど) を入力します。"],
    ["  - 「階層レベル」列には、「大機能」「中機能」「小機能」などを入力してタスクの階層を示します。"],
    ["  - 「優先度」列は「高」「中」「低」で入力すると、セルに色がつきます。"],
    ["  - 詳細内容、備考、コメントは、指定された列幅で自動改行されます。"],
    [""],
    ["2. 作業IDは必須項目（作業名, 開始日, 終了日, 予定作業時間, 担当者）が全て入力されたら自動で割り振られます（ID '0' は除く）。"],
    ["3. WBS_DataシートのV2セルに「検索(ID/作業名):」ラベルがあり、その右隣のW2セルにIDまたは作業名の一部を入力してEnterを押すと、該当する最初のタスクにジャンプします。"],
    ["4. 作業の追加・編集はWBS_Dataの行単位で行ってください。"],
    ["5. 作業を削除したい場合は、該当行のID列以外の必須項目を空欄にするとIDがクリアされます。その後行を削除できます。"],
    ["6. Gantt_ChartシートはWBS_Dataの内容から自動でガントチャートを描画します（ID '0' のサンプルタスクは除く）。"],
    ["   WBS_Dataシート編集時に自動更新されます。手動更新はメニュー「WBS管理」>「ガントチャート更新」からも可能です。"],
    ["7. EVM_DisplayシートはWBS_Dataの内容からEVM関連指標 (PV, EV, AC, SPI, CPI) を自動で計算し表示します（ID '0' のサンプルタスクは除く）。また、PV, EV, ACの推移を示す折れ線グラフも表示されます。"],
    ["   WBS_Dataシート編集時に自動更新されます。手動更新はメニュー「WBS管理」>「EVM表示更新」からも可能です。"],
    ["   PV = 予定作業時間, EV = 予定作業時間 × (進捗度 / 100), AC = 実績作業時間 で計算されます。"],
    ["8. 作業の進捗度が100%になると、WBS_Dataシートの該当行全体が緑色で表示されます。"],
    ["9. 特定の担当者の作業が変更された場合 (作業内容、担当者、進捗度、期日、優先度、ステータスなど)、該当担当者へメールで通知が送られます（要メール送信許可）。"],
    ["10. 不明点はスクリプトの作者にお問い合わせください。"]
  ];
  const newExplanationLength = explanation.length;
  howToUseSheet.getRange(1, 1, newExplanationLength, 1).setValues(explanation);
  howToUseSheet.setColumnWidth(1, 700);
  howToUseSheet.getRange(1, 1, newExplanationLength, 1).setWrap(true).setVerticalAlignment("top");
  howToUseSheet.getRange(1, 1).setFontWeight("bold").setFontSize(14).setBackground("#4CAF50").setFontColor("white").setHorizontalAlignment("center").setVerticalAlignment("middle");
  howToUseSheet.setFrozenRows(1);
  howToUseSheet.getRange(3, 1, 6, 1).setBackground("#e8f5e9");
  howToUseSheet.getRange(11, 1, 1, 1).setBackground("#fff9c4");
  howToUseSheet.getRange(14, 1, 2, 1).setBackground("#e6e6fa");
  howToUseSheet.getRange(18, 1, 2, 1).setBackground("#fff3e0");
  howToUseSheet.getRange(1, 1, newExplanationLength, 1).setBorder(true, true, true, true, true, true);

  Logger.log("初期シート構成と説明文（サンプルID 0対応、検索UI V2/W2対応）作成完了");
  SpreadsheetApp.getUi().alert("初期設定が完了しました。WBS_Dataシートに情報を入力してください。\n\nEVMの計算には「WBS_Data」シートの「予定作業時間」「実績作業時間」「進捗度」が使用されます。\nPV = 予定作業時間\nEV = 予定作業時間 × (進捗度 / 100)\nAC = 実績作業時間\n\nWBS_DataシートのW2セルからタスク検索ができます。");
}

function protectIDColumn(sheet) {
  let protections = sheet.getProtections(SpreadsheetApp.ProtectionType.RANGE);
  protections.forEach(p => { if (p.getDescription() === 'ID列保護') p.remove(); });
  let lastRowForProtection = Math.max(sheet.getMaxRows(), 3);
  let rangeToProtect = sheet.getRange("A3:A" + lastRowForProtection);
  let protection = rangeToProtect.protect().setDescription('ID列保護');
  protection.removeEditors(protection.getEditors());
  if (protection.canDomainEdit()) protection.setDomainEdit(false);
}

function applyWbsDataRowFormatting(sheet, row) {
  if (row < 3) return;
  const progressCell = sheet.getRange(row, 11); // K列: 進捗度
  let progressValue = progressCell.getValue();
  let is100Percent = (typeof progressValue === 'string' && progressValue.trim() === "100%") ||
                    (typeof progressValue === 'number' && progressValue === 100) ||
                    (typeof progressValue === 'string' && parseFloat(progressValue.replace('%', '')) === 100);

  // 行全体の背景色変更は、定義されたデータ列の範囲内(WBS_DATA_COLUMN_COUNT)に限定
  const targetRowRange = sheet.getRange(row, 1, 1, WBS_DATA_COLUMN_COUNT);
  const idValue = String(sheet.getRange(row, 1).getValue()).trim();

  if (is100Percent) {
    targetRowRange.setBackground("#d9ead3");
  } else if (idValue === "0") { // ID 0 (サンプル行)
    targetRowRange.setBackground("#f0f0f0");
  } else {
    targetRowRange.setBackground(null);
  }

  const priorityCell = sheet.getRange(row, 12); // L列: 優先度
  const priorityValue = priorityCell.getValue();
  let priorityBgColor = PRIORITY_COLORS[priorityValue] ||
                      PRIORITY_COLORS[String(priorityValue).toLowerCase()] ||
                      null;

  if (PRIORITY_COLORS[priorityValue] !== undefined) {
    priorityCell.setBackground(PRIORITY_COLORS[priorityValue]);
  } else {
    // 優先度指定がない場合、セルの背景色は行全体の背景色に従う
    // (ただし、100%完了行なら緑、サンプル行なら薄灰色、それ以外は無色)
    // is100Percent や idValue の条件は targetRowRange で既に適用済みなので、
    // targetRowRange.getBackground() を使えば、その行の基本色になる。
    // ただし、priorityCellがtargetRowRangeの範囲外だとエラーになるため、
    // targetRowRangeの背景色を直接参照するのではなく、上記の条件分岐を再利用する。
    if (is100Percent) {
        priorityCell.setBackground("#d9ead3");
    } else if (idValue === "0") {
        priorityCell.setBackground("#f0f0f0");
    } else {
        priorityCell.setBackground(null);
    }
  }
}

function getNotificationEmails(assigneesStr, targetMap) {
  if (!assigneesStr || typeof assigneesStr !== 'string') return [];
  const assignees = assigneesStr.split(',').map(name => name.trim()).filter(name => name !== '');
  return [...new Set(assignees.map(name => targetMap[name]).filter(Boolean))];
}

function onEdit(e) {
  Logger.log("--- onEdit関数開始 ---");
  if (!e || !e.range) { Logger.log("onEdit: イベントオブジェクトeまたはe.rangeが不正。終了。"); return; }

  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const sheet = e.range.getSheet();
  const sheetName = sheet.getName();
  const editedRow = e.range.getRow();
  const editedCol = e.range.getColumn(); // 1-based
  const editedValue = e.value;
  const oldValue = e.oldValue;

  Logger.log(`onEdit: シート: ${sheetName}, 行: ${editedRow}, 列: ${editedCol}, 新値: "${editedValue}", 旧値: "${oldValue}"`);

  if (sheetName !== "WBS_Data") { Logger.log(`onEdit: 対象外シート (${sheetName})。スキップ。`); return; }

  // 検索機能の処理 (W2セル: row 2, col 23)
  if (editedRow === 2 && editedCol === 23) { // W列 (23番目の列)
    const searchCell = e.range;
    const searchTermRaw = editedValue;

    if (searchTermRaw === undefined || String(searchTermRaw).trim() === "") { // 空になった場合
      searchCell.setValue(SEARCH_PLACEHOLDER_TEXT).setFontColor(SEARCH_PLACEHOLDER_COLOR);
      Logger.log("onEdit: 検索セルが空になったためプレースホルダーを再表示。");
      return;
    } else if (oldValue === SEARCH_PLACEHOLDER_TEXT && searchTermRaw !== SEARCH_PLACEHOLDER_TEXT) { // プレースホルダーから実際の入力に変わった
      searchCell.setFontColor(SEARCH_INPUT_COLOR);
      Logger.log("onEdit: 検索セルに入力が開始されたためフォントカラーを変更。");
    }
    
    if (searchTermRaw !== SEARCH_PLACEHOLDER_TEXT && String(searchTermRaw).trim() !== "") {
        const searchTerm = String(searchTermRaw).trim().toLowerCase();
        const wbsSheet = sheet;
        const lastDataRow = wbsSheet.getLastRow();
        if (lastDataRow >= 3) {
            const searchRangeValues = wbsSheet.getRange(3, 1, lastDataRow - 2, 2).getValues(); // ID(A列)と作業名(B列)
            let found = false;
            for (let i = 0; i < searchRangeValues.length; i++) {
                const currentId = String(searchRangeValues[i][0] || "").trim().toLowerCase();
                const currentTaskName = String(searchRangeValues[i][1] || "").trim().toLowerCase();
                if (currentId.includes(searchTerm) || currentTaskName.includes(searchTerm)) {
                    const targetRowFound = i + 3;
                    wbsSheet.setActiveSelection(wbsSheet.getRange(targetRowFound, 1));
                    // SpreadsheetApp.getUi().alert(`検索結果: ID「${searchRangeValues[i][0]}」作業名「${searchRangeValues[i][1]}」 (行 ${targetRowFound}) にジャンプしました。`);
                    Logger.log(`検索ヒット: 行 ${targetRowFound}`);
                    found = true;
                    break;
                }
            }
            if (!found) {
                SpreadsheetApp.getUi().alert(`「${searchTermRaw}」に一致するタスクは見つかりませんでした。`);
                Logger.log(`検索ミスヒット: ${searchTermRaw}`);
            }
        }
    }
    Logger.log(`onEdit: 検索機能処理終了。`);
    return;
  }


  if (editedRow < 3) { Logger.log(`onEdit: ヘッダー/ヒント行編集 (${editedRow})。スキップ。`); return; }

  const wbsSheet = sheet;
  const currentEditedId = String(wbsSheet.getRange(editedRow, 1).getValue()).trim();

  if (editedCol === 1 && currentEditedId !== "0") { // ID列 (A列) で、ID 0でない場合
    SpreadsheetApp.getUi().alert("ID列は自動割当のため編集禁止です (ID '0' を除く)。元に戻します。");
    e.range.setValue(oldValue !== undefined ? oldValue : null);
    Logger.log(`onEdit: ID列編集禁止。元の値に戻しました。終了。`);
    return;
  }

  // ID自動割り当て/クリアロジック (ID 0 の行は対象外)
  if (currentEditedId !== "0") {
    const idCell = wbsSheet.getRange(editedRow, 1);
    const taskNameVal     = wbsSheet.getRange(editedRow, 2).getValue();  // B列 作業名
    const startDateVal    = wbsSheet.getRange(editedRow, 6).getValue();  // F列 開始日
    const endDateVal      = wbsSheet.getRange(editedRow, 7).getValue();  // G列 終了日
    const plannedHoursVal = wbsSheet.getRange(editedRow, 8).getValue();  // H列 予定作業時間
    const assigneesVal    = wbsSheet.getRange(editedRow, 10).getValue(); // J列 担当者

    const requiredValues = [taskNameVal, startDateVal, endDateVal, plannedHoursVal, assigneesVal];
    let allRequiredFilled = requiredValues.every(cell => (cell instanceof Date ? !isNaN(cell.getTime()) : cell !== "" && cell !== null && cell !== undefined));

    if (allRequiredFilled && (idCell.getValue() === "" || idCell.getValue() === null || idCell.getValue() === undefined)) {
        let maxId = 0;
        const idColumnValues = wbsSheet.getRange(3, 1, wbsSheet.getLastRow() - 2, 1).getValues();
        const allIds = idColumnValues.flat().map(String).filter(v => v !== "" && v !== null && v !== "0" && !isNaN(Number(v))).map(Number); // ID 0 を最大値計算から除外
        if (allIds.length > 0) maxId = Math.max(...allIds);
        idCell.setValue(maxId + 1);
        Logger.log(`onEdit: 必須項目入力完了、ID割り当て: ${maxId + 1}`);
    } else if (!allRequiredFilled && (idCell.getValue() !== "" && idCell.getValue() !== null && idCell.getValue() !== undefined)) {
        const oldId = idCell.getValue();
        idCell.clearContent();
        Logger.log(`onEdit: 必須項目未入力、IDクリア: ${oldId}`);
    }
  }

  protectIDColumn(wbsSheet);
  applyWbsDataRowFormatting(wbsSheet, editedRow);

  // メール通知ロジック (ID 0 の行は対象外)
  if (currentEditedId === "0" || !currentEditedId) {
      Logger.log("onEdit: ID 0 または IDなしタスクのためメール通知スキップ。");
      // ID 0 のタスクが編集された場合でもガントチャート等は更新する
      Utilities.sleep(500); // 短い待機
      updateGanttChart();
      updateEvmDisplay();
      Logger.log("--- onEdit関数終了 (ID 0 タスク編集) ---");
      return;
  }

  const taskRowData = wbsSheet.getRange(editedRow, 1, 1, WBS_DATA_COLUMN_COUNT).getValues()[0]; // 20 -> WBS_DATA_COLUMN_COUNT
  const finalId = taskRowData[0];
  const finalTaskName = taskRowData[1];
  const finalAssigneesString = taskRowData[9]; // J列(インデックス9): 担当者
  const sheetLink = ss.getUrl() + "#gid=" + wbsSheet.getSheetId() + "&range=A" + editedRow;
  let emailSubject = "", emailBody = "", notifyEmails = [], sendMail = false;
  const headerName = wbsSheet.getRange(1, editedCol).getValue();

  if (editedCol === 11) { /* 進捗度 K列 */
    let oldP = String(oldValue || "0").replace('%',''), newP = String(editedValue || "0").replace('%','');
    if (parseFloat(newP) === 100 && parseFloat(oldP) !== 100) {
        sendMail = true; emailSubject = `[WBS通知] タスク「${finalTaskName}」(ID:${finalId})完了`;
        emailBody = `タスク「${finalTaskName}」(ID:${finalId})が進捗100%になりました。\n${sheetLink}`;
    } else if (oldP !== newP) {
        sendMail = true; emailSubject = `[WBS通知] タスク「${finalTaskName}」(ID:${finalId})進捗更新`;
        emailBody = `タスク「${finalTaskName}」(ID:${finalId})進捗更新: ${oldP}%→${newP}%\n${sheetLink}`;
    }
    if(sendMail) notifyEmails = getNotificationEmails(finalAssigneesString, TARGET_ASSIGNEES_MAP);
  } else if (editedCol === 10) { /* 担当者 J列 */
    if (String(oldValue || "") !== String(editedValue || "")) {
      sendMail = true; emailSubject = `[WBS通知] タスク「${finalTaskName}」(ID:${finalId})担当者変更`;
      emailBody = `タスク「${finalTaskName}」(ID:${finalId})担当者変更: ${oldValue||"なし"}→${editedValue||"なし"}\n${sheetLink}`;
      notifyEmails = getNotificationEmails(`${oldValue||""},${editedValue||""}`, TARGET_ASSIGNEES_MAP);
    }
  } else if (editedCol === 9) { /* 実績作業時間 I列 */
    if (String(oldValue || "") !== String(editedValue || "")) {
      sendMail = true; emailSubject = `[WBS通知] タスク「${finalTaskName}」(ID:${finalId}) ${headerName} 更新`;
      emailBody = `タスク「${finalTaskName}」(ID:${finalId}) ${headerName} 更新: "${oldValue||"未"}"→"${editedValue||"未"}"\n${sheetLink}`;
      notifyEmails = getNotificationEmails(finalAssigneesString, TARGET_ASSIGNEES_MAP);
    }
  } else if ([2,3,4,5,6,7,8,12,13,14,15,16,17,18,19].includes(editedCol)) { // 20を削除し、19（コメント列）までを対象
    if (String(oldValue || "") !== String(editedValue || "")) {
      sendMail = true; emailSubject = `[WBS通知] タスク「${finalTaskName}」(ID:${finalId}) ${headerName} 更新`;
      let oldD = oldValue, newD = editedValue;
      if (editedCol === 6 || editedCol === 7) { // 日付列
        const tz = ss.getSpreadsheetTimeZone();
        if (oldValue instanceof Date) oldD = Utilities.formatDate(oldValue, tz, "yyyy/MM/dd");
        if (editedValue instanceof Date) newD = Utilities.formatDate(editedValue, tz, "yyyy/MM/dd");
      }
      emailBody = `タスク「${finalTaskName}」(ID:${finalId}) ${headerName} 更新: "${oldD||"未"}"→"${newD||"未"}"\n${sheetLink}`;
      notifyEmails = getNotificationEmails(finalAssigneesString, TARGET_ASSIGNEES_MAP);
    }
  }

  if (sendMail && emailSubject && notifyEmails.length > 0 && finalId) {
    Logger.log(`onEdit: メール送信実行。宛先: ${notifyEmails.join(", ")}, 件名: "${emailSubject}"`);
    notifyEmails.forEach(email => { try { MailApp.sendEmail(email, emailSubject, emailBody); Logger.log(`Mail送成功:${email}`);} catch (f) { Logger.log(`Mail送失敗:${email}. Error:${f.message}`);}});
  } else { Logger.log(`onEdit: Mail送信条件未達。sendMail:${sendMail}, subject:"${emailSubject}", recipients:${notifyEmails.length}, ID:${finalId}`);}

  Utilities.sleep(500);
  updateGanttChart();
  updateEvmDisplay();
  Logger.log("--- onEdit関数終了 ---");
}


function updateGanttChart() {
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const wbsSheet = ss.getSheetByName("WBS_Data");
  const ganttSheet = ss.getSheetByName("Gantt_Chart");
  if (!wbsSheet || !ganttSheet) { Logger.log("updateGanttChart: 必要シートなし。"); return; }
  ganttSheet.clear(); ganttSheet.clearFormats();

  const firstDataRowWBS = 3;
  const wbsLastRow = wbsSheet.getLastRow();
  if (wbsLastRow < firstDataRowWBS) { ganttSheet.getRange(1,1).setValue("WBS_Dataにデータなし。"); return; }

  const allWbsData = wbsSheet.getRange(firstDataRowWBS, 1, wbsLastRow - firstDataRowWBS + 1, 11).getValues();
  const validData = allWbsData.filter(row => {
    const id = String(row[0]).trim(); // ID
    const start = row[5]; // 開始日(F列)
    const end = row[6];   // 終了日(G列)
    return id && id !== "0" && start instanceof Date && !isNaN(start.getTime()) && end instanceof Date && !isNaN(end.getTime()) && end.getTime() >= start.getTime();
  });

  if (validData.length === 0) { ganttSheet.getRange(1,1).setValue("有効なWBSデータなし (ID 0除く)。"); return; }

  let minDate = null, maxDate = null;
  validData.forEach(row => {
    const startDate = new Date(row[5]);
    const endDate = new Date(row[6]);
    if (!minDate || startDate < minDate) minDate = startDate;
    if (!maxDate || endDate > maxDate) maxDate = endDate;
  });

  if (!minDate || !maxDate) { ganttSheet.getRange(1,1).setValue("有効な日付範囲特定不可。"); return; }

  let currentMinDate = new Date(minDate.getFullYear(), minDate.getMonth(), minDate.getDate());
  const dayOfWeek = currentMinDate.getDay();
  currentMinDate.setDate(currentMinDate.getDate() - (dayOfWeek === 0 ? 6 : dayOfWeek -1)); // 週の月曜始まり

  const msPerDay = 86400000;
  let adjustedMaxDate = new Date(maxDate.getFullYear(), maxDate.getMonth(), maxDate.getDate());
  const totalDays = Math.max(1, Math.ceil((adjustedMaxDate - currentMinDate) / msPerDay) +1); // 最小1日

  if (totalDays > 730) { ganttSheet.getRange(1,1).setValue("日付範囲広すぎ(2年以上)。"); return; }

  const headerRowGantt = ["ID", "作業名", "担当者", "進捗度 (%)"];
  const dateHeaders = Array.from({length: totalDays}, (_, i) => Utilities.formatDate(new Date(currentMinDate.getTime() + i * msPerDay), ss.getSpreadsheetTimeZone(), "M/d E"));
  const dateHeaderFullDates = Array.from({length: totalDays}, (_, i) => new Date(currentMinDate.getTime() + i * msPerDay));

  ganttSheet.getRange(1, 1, 1, headerRowGantt.length).setValues([headerRowGantt]).setBackground("#c8e6c9");
  if (dateHeaders.length > 0) ganttSheet.getRange(1, headerRowGantt.length + 1, 1, dateHeaders.length).setValues([dateHeaders]);
  ganttSheet.setFrozenRows(1); ganttSheet.setFrozenColumns(4);
  ganttSheet.getRange(1, 1, 1, headerRowGantt.length + dateHeaders.length).setFontWeight("bold").setBackground("#90caf9").setHorizontalAlignment("center").setVerticalAlignment("top").setWrap(true);
  ganttSheet.getRange("A1:D1").setBackground("#c8e6c9"); // 強調
  ganttSheet.setRowHeight(1, 40);
  ganttSheet.setColumnWidth(1, 80); ganttSheet.setColumnWidth(2, 300); ganttSheet.setColumnWidth(3, 200); ganttSheet.setColumnWidth(4, 100);
  for (let i=0; i<totalDays; i++) ganttSheet.setColumnWidth(headerRowGantt.length + 1 + i, 40);

  const outputRows = validData.map(dataRow => {
    let ganttRowOutput = [dataRow[0], dataRow[1], dataRow[9], dataRow[10]]; // ID, 作業名, 担当者, 進捗
    const taskStartDay = new Date(dataRow[5].getFullYear(), dataRow[5].getMonth(), dataRow[5].getDate());
    const taskEndDay = new Date(dataRow[6].getFullYear(), dataRow[6].getMonth(), dataRow[6].getDate());
    let ganttBarCells = dateHeaderFullDates.map(currentDayStart => (taskStartDay <= currentDayStart && currentDayStart <= taskEndDay) ? "■" : "");
    return ganttRowOutput.concat(ganttBarCells);
  });

  if (outputRows.length === 0) { ganttSheet.getRange(2,1).setValue("描画対象データなし。"); return; }
  ganttSheet.getRange(2, 1, outputRows.length, outputRows[0].length).setValues(outputRows).setVerticalAlignment("top");
  ganttSheet.setRowHeights(2, outputRows.length, 25);

  const taskColors = ["#4285F4","#DB4437","#F4B400","#0F9D58","#AB47BC","#FF7043","#26A69A","#7E57C2","#EC407A","#66BB6A","#FFA726","#5C6BC0"];
  validData.forEach((dataRow, i) => {
    let progressVal = dataRow[10]; // 進捗度
    if ((typeof progressVal === 'string' && parseFloat(progressVal.replace('%','')) === 100) || (typeof progressVal === 'number' && progressVal === 100)) {
        ganttSheet.getRange(i + 2, 1, 1, headerRowGantt.length).setBackground("#d9ead3");
    }
    const taskColor = taskColors[i % taskColors.length];
    for (let c = 0; c < dateHeaders.length; c++) {
        if (outputRows[i][headerRowGantt.length + c] === "■") {
            ganttSheet.getRange(i + 2, headerRowGantt.length + 1 + c).setBackground(taskColor).setFontColor(taskColor);
        }
    }
  });

  dateHeaderFullDates.forEach((date, d) => {
    const day = date.getDay();
    const colToFormat = headerRowGantt.length + 1 + d;
    if (day === 0 || day === 6) { // 土日
        // ganttSheet.getRange(2, colToFormat, outputRows.length, 1).setBackground("#f0f0f0"); // データ行の背景色設定を削除
        ganttSheet.getRange(1, colToFormat, 1, 1).setBackground("#e0e0e0"); // ヘッダー行のみ背景色を設定
    }
  });
  if (ganttSheet.getLastRow() > 1) ganttSheet.getRange(2,1,ganttSheet.getLastRow()-1, ganttSheet.getLastColumn()).setBorder(true,true,true,true,true,true,"#d9d9d9",SpreadsheetApp.BorderStyle.SOLID);
  Logger.log("ガントチャート更新完了");
}


function updateEvmDisplay() {
  Logger.log("--- updateEvmDisplay関数開始 ---");
  const ss = SpreadsheetApp.getActiveSpreadsheet();
  const wbsSheet = ss.getSheetByName("WBS_Data");
  let evmSheet = ss.getSheetByName("EVM_Display");

  if (!wbsSheet) { 
    if(evmSheet){ evmSheet.clear(); evmSheet.getRange(1,1).setValue("WBS_Dataシートが見つかりません。");} 
    Logger.log("EVM: WBS_Dataなし。"); 
    return; 
  }
  
  evmSheet.clear(); 
  evmSheet.getCharts().forEach(chart => evmSheet.removeChart(chart));

  // --- 1. タスク毎のEVMテーブルを作成 ---
  const firstDataRowWBS = 3;
  const wbsLastRow = wbsSheet.getLastRow();
  if (wbsLastRow < firstDataRowWBS) { 
    evmSheet.getRange(1,1).setValue("WBS_Dataにデータがありません。"); 
    return; 
  }
  const wbsValues = wbsSheet.getRange(firstDataRowWBS, 1, wbsLastRow - firstDataRowWBS + 1, 11).getValues()
    .filter(row => String(row[0]).trim() && String(row[0]).trim() !== "0");

  if (wbsValues.length === 0) {
    evmSheet.getRange(1,1).setValue("有効なEVM計算対象データがありません (ID '0'を除く)。");
    return;
  }
  const evmHeaders = ["ID","作業名","PV(予定時間)","EV(出来高時間)","AC(実績時間)","SPI(進捗効率)","CPI(コスト効率)"];
  evmSheet.getRange(1, 1, 1, evmHeaders.length).setValues([evmHeaders])
    .setFontWeight("bold").setBackground("#c8e6c9").setHorizontalAlignment("center").setWrap(true).setVerticalAlignment("middle");

  let totalPv = 0, totalEv = 0, totalAc = 0;
  const evmDataRows = wbsValues.map(row => {
    const id = row[0], taskName = row[1];
    const plannedHours = parseFloat(row[7]) || 0;
    const actualHours = parseFloat(row[8]) || 0;
    let progress = row[10];
    if (typeof progress === 'string') progress = parseFloat(progress.replace('%','')) || 0;
    else if (typeof progress !== 'number' || isNaN(progress)) progress = 0;
    const pv = plannedHours, ev = plannedHours * (progress / 100), ac = actualHours;
    totalPv += pv; totalEv += ev; totalAc += ac;
    const spi = pv > 0 ? (ev / pv) : (ev === 0 && pv === 0 ? 1 : "-");
    const cpi = ac > 0 ? (ev / ac) : (ev === 0 && ac === 0 ? 1 : "-");
    return [id, taskName, pv, ev, ac, spi, cpi];
  });

  evmSheet.getRange(2, 1, evmDataRows.length, evmHeaders.length).setValues(evmDataRows).setVerticalAlignment("top").setNumberFormat("@");
  evmSheet.getRange(2, 3, evmDataRows.length, 3).setNumberFormat("0.0");
  evmSheet.getRange(2, 6, evmDataRows.length, 2).setNumberFormat("0.00");
  
  const summaryRowIndex = evmDataRows.length + 2;
  const totalSpi = totalPv > 0 ? (totalEv / totalPv) : (totalEv === 0 && totalPv === 0 ? 1 : "-");
  const totalCpi = totalAc > 0 ? (totalEv / totalAc) : (totalEv === 0 && totalAc === 0 ? 1 : "-");
  const summaryRange = evmSheet.getRange(summaryRowIndex, 1, 1, evmHeaders.length);
  summaryRange.setValues([["プロジェクト合計", "", totalPv, totalEv, totalAc, totalSpi, totalCpi]])
    .setFontWeight("bold").setBackground("#f3f3f3").setBorder(true,true,true,true,true,true);
  evmSheet.getRange(summaryRowIndex, 3, 1, 3).setNumberFormat("0.0");
  evmSheet.getRange(summaryRowIndex, 6, 1, 2).setNumberFormat("0.00");
  evmSheet.setColumnWidths(1, 7, 120).setColumnWidth(1, 60).setColumnWidth(2, 250);
  evmSheet.getRange(1, 1, summaryRowIndex, evmHeaders.length).setBorder(true, true, true, true, true, true, "#d9d9d9", SpreadsheetApp.BorderStyle.SOLID);
  evmSheet.setFrozenRows(1);

  // --- 2. 時間軸ベースの累積EVMグラフ（Sカーブ）を作成 ---
  const tasks = wbsValues.map(row => {
    const startDate = row[5]; // F列
    const endDate = row[6];   // G列
    if (!(startDate instanceof Date) || !(endDate instanceof Date) || endDate < startDate) return null;
    const pv = parseFloat(row[7]) || 0;
    const progress = (parseFloat(String(row[10]).replace('%', '')) || 0) / 100;
    return {
      startDate: new Date(startDate.setHours(0,0,0,0)),
      endDate: new Date(endDate.setHours(0,0,0,0)),
      pv: pv,
      ev: pv * progress,
      ac: parseFloat(row[8]) || 0,
    };
  }).filter(Boolean);

  if (tasks.length === 0) {
    Logger.log("グラフ描画対象の有効な日付を持つタスクがありません。");
    return;
  }

  const allDates = tasks.flatMap(t => [t.startDate, t.endDate]);
  const projectStartDate = new Date(Math.min.apply(null, allDates));
  const projectEndDate = new Date(Math.max.apply(null, allDates));
  const today = new Date();
  today.setHours(0,0,0,0);
  
  const dailyDeltas = new Map();
  const msPerDay = 86400000;

  tasks.forEach(task => {
    const duration = (task.endDate.getTime() - task.startDate.getTime()) / msPerDay + 1;
    if (duration <= 0) return;

    const dailyPv = task.pv / duration;
    const dailyEv = task.ev / duration;
    const dailyAc = task.ac / duration;

    for (let d = new Date(task.startDate); d <= task.endDate; d.setDate(d.getDate() + 1)) {
      const dateKey = d.toISOString().slice(0, 10);
      const currentDeltas = dailyDeltas.get(dateKey) || { pv: 0, ev: 0, ac: 0 };
      currentDeltas.pv += dailyPv;
      currentDeltas.ev += dailyEv;
      currentDeltas.ac += dailyAc;
      dailyDeltas.set(dateKey, currentDeltas);
    }
  });

  const chartData = [];
  let cumulativePv = 0, cumulativeEv = 0, cumulativeAc = 0;

  for (let d = new Date(projectStartDate); d <= projectEndDate; d.setDate(d.getDate() + 1)) {
    const dateKey = d.toISOString().slice(0, 10);
    const deltas = dailyDeltas.get(dateKey) || { pv: 0, ev: 0, ac: 0 };
    
    cumulativePv += deltas.pv;
    
    let evForChart = null, acForChart = null;
    if (d <= today) {
      cumulativeEv += deltas.ev;
      cumulativeAc += deltas.ac;
      evForChart = cumulativeEv;
      acForChart = cumulativeAc;
    }
    chartData.push([new Date(d), cumulativePv, evForChart, acForChart]);
  }
  
  if (chartData.length > 0) {
    const chartDataWithHeader = [["日付", "累積PV", "累積EV", "累積AC"], ...chartData];
    const chartDataStartColumn = evmHeaders.length + 2;
    const chartDataSourceRange = evmSheet.getRange(1, chartDataStartColumn, chartDataWithHeader.length, chartDataWithHeader[0].length);
    chartDataSourceRange.setValues(chartDataWithHeader);

    const sCurveChart = evmSheet.newChart()
        .setChartType(Charts.ChartType.LINE)
        .addRange(chartDataSourceRange)
        .setMergeStrategy(Charts.ChartMergeStrategy.MERGE_COLUMNS)
        .setTransposeRowsAndColumns(false)
        .setNumHeaders(1)
        .setOption('useFirstColumnAsDomain', true)
        .setOption('title', 'EVM累積グラフ（Sカーブ）')
        .setOption('titleTextStyle', { color: '#333', fontSize: 16 })
        .setOption('legend', { position: 'top', alignment: 'center' })
        .setOption('hAxis', { title: '日付', titleTextStyle: { color: '#555' }, gridlines: { count: -1 } })
        .setOption('vAxis', { title: '累積時間 (Hours)', titleTextStyle: { color: '#555' }, viewWindow: { min: 0 } })
        .setOption('series', {
            0: { color: '#4285F4', lineWidth: 2 },
            1: { color: '#0F9D58', lineWidth: 2 },
            2: { color: '#DB4437', lineWidth: 2 }
        })
        .setPosition(2, evmHeaders.length + 2, 0, 0)
        .build();
    evmSheet.insertChart(sCurveChart);

    // グラフのデータソース列を非表示にする
    evmSheet.hideColumns(chartDataStartColumn, chartDataWithHeader[0].length);
  }

  Logger.log("EVM表示更新完了");
}


function onOpen() {
  SpreadsheetApp.getUi().createMenu("WBS管理")
    .addItem("初期シート作成/リセット", "createInitialSheets")
    .addSeparator()
    .addItem("ガントチャート手動更新", "updateGanttChart")
    .addItem("EVM表示手動更新", "updateEvmDisplay")
    .addToUi();
}

