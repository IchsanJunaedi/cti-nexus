import asyncio
import os
import sys

# Ensure platform is in path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
PLATFORM_DIR = os.path.abspath(os.path.join(CURRENT_DIR, ".."))
WORKSPACE_DIR = os.path.abspath(os.path.join(PLATFORM_DIR, ".."))

if PLATFORM_DIR not in sys.path:
    sys.path.insert(0, PLATFORM_DIR)

from app.services.auth_service import create_token
from playwright.async_api import async_playwright

SCREENSHOTS_DIR = os.path.join(WORKSPACE_DIR, "docs", "screenshots")
os.makedirs(SCREENSHOTS_DIR, exist_ok=True)

async def capture_all():
    token = create_token("admin", "superadmin", ["default"])
    print(f"Generated JWT token for admin (superadmin).")
    
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        context = await browser.new_context(
            viewport={"width": 1600, "height": 950},
            device_scale_factor=2,  # High DPI Retina quality
            ignore_https_errors=True
        )

        # 1. Set cti_auth cookie for FastAPI authentication
        await context.add_cookies([{
            "name": "cti_auth",
            "value": token,
            "domain": "localhost",
            "path": "/",
            "httpOnly": False,
            "secure": True,
            "sameSite": "Lax",
        }])

        # 2. Inject localStorage credentials before any script runs
        await context.add_init_script(f"""
            localStorage.setItem('cti_jwt', '{token}');
            localStorage.setItem('active_client_id', 'default');
        """)

        page = await context.new_page()
        print("Navigating to https://localhost:5443/ ...")
        await page.goto("https://localhost:5443/", wait_until="networkidle")
        await asyncio.sleep(2)
        print("Current URL:", page.url)

        # Target 1: Executive Dashboard
        print("1. Capturing Executive Dashboard...")
        await page.evaluate("""() => {
            const btn = document.querySelector('.tab[title="Executive Dashboard"]');
            switchTab('exec', btn);
        }""")
        # Wait for executive dashboard data to load
        await asyncio.sleep(4)
        out1 = os.path.join(SCREENSHOTS_DIR, "01_Executive_Dashboard.png")
        await page.screenshot(path=out1, full_page=False)
        print(f"   Saved -> {out1}")

        # Target 2: Threat Newsroom
        print("2. Capturing Threat Newsroom...")
        await page.evaluate("""() => {
            const btn = document.querySelector('.tab[title="News Room"]');
            switchTab('newsroom', btn);
        }""")
        await asyncio.sleep(3)
        out2 = os.path.join(SCREENSHOTS_DIR, "02_Threat_Newsroom.png")
        await page.screenshot(path=out2, full_page=False)
        print(f"   Saved -> {out2}")

        # Target 3: CVE Tracker & Prioritization
        print("3. Capturing CVE Tracker & Prioritization...")
        await page.evaluate("""() => {
            const btn = document.querySelector('.tab[title="CVE Tracker"]');
            switchTab('cvetracker', btn);
        }""")
        await asyncio.sleep(3)
        out3 = os.path.join(SCREENSHOTS_DIR, "03_CVE_Tracker_Prioritization.png")
        await page.screenshot(path=out3, full_page=False)
        print(f"   Saved -> {out3}")

        # Target 4: Intelligence & Defensive Operations
        print("4. Capturing Intelligence & Defensive Operations...")
        await page.evaluate("""() => {
            const btn = document.querySelector('.tab[title="Intelligence"]');
            switchTab('intelligence', btn);
            intelSwitchGroup('landscape');
            intelSwitchViewAndLoad('campaigns');
            const daysSelect = document.getElementById('campaigns-days');
            if (daysSelect) {
                daysSelect.value = '30';
                loadCampaigns();
            }
        }""")
        # Wait for campaign cluster data and table rows to load
        try:
            await page.wait_for_selector('.campaign-row, .ta-table-wrap table, #campaigns-body tr', timeout=15000)
        except Exception:
            pass
        await asyncio.sleep(2)
        out4 = os.path.join(SCREENSHOTS_DIR, "04_Intelligence_Defensive_Operations.png")
        await page.screenshot(path=out4, full_page=False)
        print(f"   Saved -> {out4}")

        # Target 5: X Intel / OSINT Stream
        print("5. Capturing X Intel / OSINT Stream...")
        await page.evaluate("""() => {
            const btn = document.querySelector('.tab[title="X Intel"]');
            switchTab('xintel', btn);
        }""")
        await asyncio.sleep(3)
        out5 = os.path.join(SCREENSHOTS_DIR, "05_X_Intel_OSINT_Stream.png")
        await page.screenshot(path=out5, full_page=False)
        print(f"   Saved -> {out5}")

        await browser.close()
        print("All 5 screenshots captured successfully!")

if __name__ == "__main__":
    asyncio.run(capture_all())
