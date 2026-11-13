# To archive the daily counter files into logFile

from supportFile.countAllNewsDB import count_all_news
from datetime import datetime, timedelta
import os, shutil

now_date = datetime.now().strftime('%d_%m_%Y')
# now_date = (datetime.now() - timedelta(days=1)).strftime('%d_%m_%Y')

counts = count_all_news(now_date)
raw_all_counter = counts["total"]
raw_related_counter = counts["completed"]
raw_unrelated_counter = counts["filtered"]

all_news_msg = f"""
    === SCRAPED NEWS ALERT ===
Total news scraped on {datetime.now().strftime("%d %m %Y")}: {raw_all_counter}
Total unrelated cti news: {raw_unrelated_counter}
Total related cti news: {raw_related_counter}
"""
print(all_news_msg)

shutil.move(f"supportFile/UNRELATED_{now_date}.txt", f"supportFile/logFile/UNRELATED_{now_date}.txt")
shutil.move(f"supportFile/RELATED_{now_date}.txt", f"supportFile/logFile/RELATED_{now_date}.txt")
# os.remove(f"supportFile/UNRELATED_{now_date}.txt")
# os.remove(f"supportFile/RELATED_{now_date}.txt")