from playwright.async_api import async_playwright
import logging

logger = logging.getLogger(__name__)


async def capture_screenshot(url: str) -> bytes:
    """
    Capture a screenshot of a website using Playwright (headless browser).
    
    Args:
        url (str): The URL to capture
        
    Returns:
        bytes: PNG screenshot data
    """
    # Ensure URL has a protocol
    if not url.startswith(("http://", "https://")):
        url = "http://" + url
    
    try:
        async with async_playwright() as p:
            # Launch browser in headless mode
            browser = await p.chromium.launch(headless=True)
            page = await browser.new_page()
            
            # Set viewport size
            await page.set_viewport_size({"width": 1280, "height": 720})
            
            try:
                # Navigate to the URL with a timeout
                await page.goto(url, timeout=10000, wait_until="domcontentloaded")
                
                # Wait a bit for content to load
                await page.wait_for_timeout(1000)
                
                # Take screenshot
                screenshot_bytes = await page.screenshot(type="png")
                
                # Close browser
                await browser.close()
                
                return screenshot_bytes
                
            except Exception as e:
                # Close browser even if there was an error
                await browser.close()
                logger.error(f"Error capturing screenshot for {url}: {str(e)}")
                raise e
                
    except Exception as e:
        logger.error(f"Error initializing Playwright for {url}: {str(e)}")
        raise e