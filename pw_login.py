from playwright.sync_api import sync_playwright

def playwright_login(domain, journal, username, password):
    cookies_dict = {}

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)  # ubah False kalau mau lihat
        context = browser.new_context()
        page = context.new_page()

        login_url = f"{domain}/{journal}/login"
        page.goto(login_url)

        # cek page

        print("CURRENT URL:", page.url)
        print(page.content)

        # isi form login
        page.fill("input[name='username']", username)
        page.fill("input[name='password']", password)

        # submit
        page.click("button[type='submit']")

        page.wait_for_timeout(2000)

        print("AFTER LOGIN URL:", page.url)
        print(page.inner_text("body"))

        # tunggu redirect selesai
        page.wait_for_load_state("networkidle")

        # 🔥 ambil semua cookies
        cookies = context.cookies()

        for c in cookies:
            cookies_dict[c["name"]] = c["value"]

        print("PLAYWRIGHT COOKIES:", cookies_dict)

        browser.close()

    return cookies_dict