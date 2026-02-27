import asyncio
from playwright.async_api import async_playwright

async def scan_website_runtime(url: str):
    findings = []
    
    async with async_playwright() as p:
        # Launch headless browser
        browser = await p.chromium.launch(headless=True)
        page = await browser.new_page()
        
        try:
            # Navigate to the URL
            response = await page.goto(url, timeout=60000)
            
            # 1. Check Security Headers
            headers = response.headers
            security_headers = ["x-frame-options", "content-security-policy", "strict-transport-security"]
            for header in security_headers:
                if header not in headers:
                    findings.append({
                        "tool": "crawler",
                        "file_path": url,
                        "line": 0,
                        "message": f"Missing Security Header: {header}",
                        "severity": "MEDIUM"
                    })

            # 2. Detect Insecure Scripts (Mixed Content)
            scripts = await page.locator("script").all()
            for script in scripts:
                src = await script.get_attribute("src")
                if src and src.startswith("http://"):
                    findings.append({
                        "tool": "crawler",
                        "file_path": src,
                        "line": 0,
                        "message": "Insecure Script (Mixed Content) detected",
                        "severity": "HIGH"
                    })

            # 3. Extract Images for Copyright/Compliance (Feature 2 & 4)
            images = await page.locator("img").all()
            image_urls = []
            for img in images:
                src = await img.get_attribute("src")
                if src: image_urls.append(src)
            
            if len(image_urls) > 0:
                findings.append({
                    "tool": "crawler",
                    "file_path": url,
                    "line": 0,
                    "message": f"Extracted {len(image_urls)} images for compliance scanning",
                    "severity": "INFO"
                })

        except Exception as e:
            print(f"Crawl Error: {e}")
        finally:
            await browser.close()
            
    return findings