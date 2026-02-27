from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(headless=False)  # headless=False shows browser
    page = browser.new_page()
    page.goto("https://www.google.com")
    print("✅ Playwright is working!")
    browser.close()