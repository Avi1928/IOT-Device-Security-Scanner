from playwright.sync_api import sync_playwright, expect
import time

def verify_frontend():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page()
        
        # Go to dashboard
        try:
            page.goto("http://localhost:5000")
        except Exception as e:
            print(f"Failed to load page: {e}")
            return

        # Wait for title
        expect(page).to_have_title("IoT Security Dashboard")
        print("Dashboard loaded.")
        
        # Take screenshot of Dashboard
        page.screenshot(path="/home/jules/verification/dashboard.png")
        
        # Click 'Scan History' in sidebar
        # Sidebar link: Scan History
        page.get_by_role("link", name="Scan History").click()
        
        # Wait for modal to appear
        # Modal id is 'savedScansModal'
        modal = page.locator("#savedScansModal")
        expect(modal).to_be_visible()
        print("Scan History modal visible.")
        
        # Wait for content to load (spinner to disappear or content to appear)
        # The fetch might be fast or slow.
        # If empty, it shows "No saved scans found".
        # If error, it shows "Error loading scans".
        
        # Wait a bit for fetch
        page.wait_for_timeout(2000)
        
        # Take screenshot of Modal
        page.screenshot(path="/home/jules/verification/history_modal.png")
        
        browser.close()

if __name__ == "__main__":
    verify_frontend()
