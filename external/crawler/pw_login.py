from playwright.sync_api import sync_playwright

def playwright_login(domain, journal, username, password, save_path="auth.json"):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        login_url = f"{domain}/{journal}/login"
        page.goto(login_url)

        page.fill("input[name='username']", username)
        page.fill("input[name='password']", password)
        page.click("button[type='submit']")

        page.wait_for_load_state("networkidle")

        print("LOGIN SUCCESS:", page.url)

        # 🔥 SIMPAN FULL SESSION
        context.storage_state(path=save_path)

        browser.close()
    return save_path
