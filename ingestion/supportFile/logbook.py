import openpyxl, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from modules import dbMongo
from openpyxl.styles import Font, Fill, Border, Side, PatternFill, Alignment
from datetime import datetime, timedelta
from deep_translator import GoogleTranslator
print(datetime.now())
border_style_left = Border(
    top=Side(style='thin'),
    right=Side(style='thin'),
    left=Side(style='medium'),
    bottom=Side(style="thin")
)

border_style_left_only = Border(
    left=Side(style='medium'),
)

border_style_right_only = Border(
    right=Side(style='medium'),
)

border_style_bot_only = Border(
    bottom=Side(style="medium")
)

border_style_right = Border(
    # top=Side(style='thin'),
    right=Side(style='medium'),
    # left=Side(style="thin"),
    # bottom=Side(style="medium")
)

border_style_thin = Border(
    top=Side(style='thin'),
    right=Side(style="thin"),
    left=Side(style="thin"),
    bottom=Side(style="thin")
)

border_style_thin_lr = Border(
    right=Side(style="thin"),
    left=Side(style="thin")
)

fill_status = False
hex_color = "D6E1F4"
fill = PatternFill(start_color=hex_color, end_color=hex_color, fill_type="solid")

def _insertData(cell_num, border_style, value, fill_color_status):
    cell = wb[cell_num]
    cell.border = border_style

    if str(cell_num).startswith("E") or str(cell_num).startswith("G"):
        cell.alignment = Alignment(horizontal='left', vertical='center')
    else:
        cell.alignment = Alignment(horizontal='center', vertical='center')

    try:
        if str(value).startswith("http"):
            cell.hyperlink = value
            cell.value = "Link to Article"
        else:
            cell.value = value
    except AttributeError:
        pass

    if fill_color_status == True:
        cell.fill = fill
    else:
        pass

def _insertSignature(cell_num, border_style, value, status):
    custom_font_underline = Font(name='Calibri', size=12, bold=True, underline='single')
    custom_font = Font(name='Calibri', size=12, bold=True)

    cell = wb[cell_num]
    cell.border = border_style

    if str(cell_num).startswith("E") or str(cell_num).startswith("G"):
        cell.alignment = Alignment(horizontal='center', vertical='center')
    else:
        cell.alignment = Alignment(horizontal='center', vertical='center')

    cell.value = value
    if status == True:
        cell.font = custom_font_underline
    else:
        cell.font = custom_font


two_weeks_prior = (datetime.now() - timedelta(days=14))
now_date = (datetime.now())
article_data = []

last_date_str = dbMongo.get_logbook_last_date()

if last_date_str is None:
    dbMongo.set_logbook_last_date(now_date.strftime("%d-%b-%Y"))
    last_date_str = now_date.strftime("%d-%b-%Y")

if (datetime.now() - datetime.strptime(last_date_str.strip(), "%d-%b-%Y")).days < 14:
    exit()

news_type = [
    "GLOBAL",
    "APAC",
]

for entry in dbMongo.get_all_article_entries_in_period(two_weeks_prior, now_date):
    if entry['news_type'].upper() in news_type:
        if "threat_actors" in entry and entry['news_type'].upper() not in news_type:
            article_data.append(f"APT || {entry['title']} || {entry['url']} || {entry['posted_on']}")
        else:
            article_data.append(f"{entry['news_type'].upper()} || {entry['title']} || {entry['url']} || {entry['posted_on']}")

wb_file = openpyxl.load_workbook(filename = 'supportFile/templateLogbook.xlsx')
wb = wb_file[wb_file.sheetnames[0]]

max_row = 13
counter = 1

# Editing the Header
wb.cell(row=3, column=7).value = f"Tanggal: {GoogleTranslator(source='auto', target='id').translate(datetime.now().strftime('%d %B %Y'))}"
wb.cell(row=3, column=7).border = border_style_right_only

wb.cell(row=4, column=5).value = f"Logbook Threat Information Periode\n{GoogleTranslator(source='auto', target='id').translate(two_weeks_prior.strftime('%d %B %Y').upper())} - {GoogleTranslator(source='auto', target='id').translate(now_date.strftime('%d %B %Y').upper())}"

wb.cell(row=11, column=5).value = f"Laporan ini diberikan setiap dua minggu sekali di mana dalam laporan ini berisi informasi ancaman siber yang terjadi dalam periode {GoogleTranslator(source='auto', target='id').translate(two_weeks_prior.strftime('%d %B %Y').title())} – {GoogleTranslator(source='auto', target='id').translate(now_date.strftime('%d %B %Y').title())}. Informasi dikategorikan berdasarkan cakupan geografis dan jenis ancamannya."

for num in range(1, 5):
    wb.cell(row=num, column=10).border = border_style_left_only

while True:
    num_value = wb.cell(row=max_row, column=2).value

    if num_value is not None:
        max_row += 1
        continue
    else:
        num_value = max_row
        break

wb.insert_rows(idx=max_row, amount=len(article_data))
for article in article_data:
    wb.merge_cells(f'E{max_row}:F{max_row}', start_row=max_row)
    # B = Nomor align center align middle
    # C = Date align center align middle
    # D = Cat align center align middle
    # E = Subject align left align middle
    # G = Source align left align middle
    try:
        article_date = GoogleTranslator(source='auto', target='id').translate(datetime.strptime(str(article).split(" || ")[3], "%Y-%m-%d").strftime("%d %B %Y"))
        
        if article_date.startswith("0"):
            article_date = article_date[1:]
    except IndexError:
        continue    
    
    _insertData(f"B{max_row}", border_style_left, counter, fill_status) # insert "No"
    _insertData(f"C{max_row}", border_style_thin, article_date, fill_status) # insert "Date"
    _insertData(f"D{max_row}", border_style_thin, str(article).split(" || ")[0], fill_status) # insert "Category"
    _insertData(f"E{max_row}", border_style_thin, str(article).split(" || ")[1], fill_status) # insert "Subject"
    _insertData(f"F{max_row}", border_style_thin, "", "") # just for borderline
    _insertData(f"G{max_row}", border_style_thin, str(article).split(" || ")[2], fill_status) # insert "Source Link"
    _insertData(f"H{max_row}", border_style_thin, "-", fill_status) # just for borderline
    _insertData(f"I{max_row}", border_style_right, "", "") # just for borderline
    if fill_status == True:
        fill_status = False
    else:
        fill_status = True

    counter += 1
    max_row += 1

wb.insert_rows(idx=max_row, amount=15)
counter = 1
for i in range(max_row, max_row + 14):
    _insertSignature(f"B{i}", border_style_left_only, "", False)
    _insertSignature(f"I{i}", border_style_right, "", False)

    if counter == 6:
        _insertSignature(f"E{i}", border_style_thin, "Disusun Oleh:", False) # insert "Disusun Oleh"
        _insertSignature(f"F{i}", border_style_thin, "Disetujui Oleh:", False) # insert "Disetujui Oleh"

    if counter >= 7 and counter < 13:
        _insertSignature(f"E{i}", border_style_thin_lr, "", False) 
        _insertSignature(f"F{i}", border_style_thin_lr, "", False)

    if counter == 13:
        _insertSignature(f"E{i}", border_style_thin, "Dyah Retno Palupi", True)
        _insertSignature(f"F{i}", border_style_thin, "Michael Dragon Muliawidjaja", True)
    
    if counter == 14:
        _insertSignature(f"E{i}", border_style_thin, "Threat Intel", False)
        _insertSignature(f"F{i}", border_style_thin, "SOC Lead", False)

        _insertSignature(f"B{i + 1}", border_style_left_only, "", False)
        _insertSignature(f"I{i + 1}", border_style_right, "", False)
    
    # if counter >= 15:

    #     _insertSignature(f"B{i + 1}", border_style_left_only, "hueheh", False)
    #     _insertSignature(f"I{i + 1}", border_style_right, "", False)

    #     _insertSignature(f"B{i}", border_style_left_only, "hueheh", False)
    #     _insertSignature(f"C{i}", border_style_right, "", False)
    #     _insertSignature(f"D{i}", border_style_right, "", False)
    #     _insertSignature(f"E{i}", border_style_right, "", False)
    #     _insertSignature(f"F{i}", border_style_right, "", False)
    #     _insertSignature(f"G{i}", border_style_right, "", False)
    #     _insertSignature(f"H{i}", border_style_right, "", False)

    counter += 1

filename = f'supportFile/ThreatInformation_Logbook_{two_weeks_prior.strftime("%d-%b-%Y")}_to_{now_date.strftime("%d-%b-%Y")}.xlsx'
wb_file.save(filename)

print(f"Logbook saved: {filename}")
dbMongo.mark_logbook_entries_reported()
dbMongo.set_logbook_last_date(now_date.strftime("%d-%b-%Y"))
print(datetime.now())