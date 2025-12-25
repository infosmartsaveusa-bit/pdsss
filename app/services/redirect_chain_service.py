import httpx
import time
from typing import List, Dict


async def get_redirect_chain(url: str) -> Dict:
    """
    Follow redirects using httpx and record every hop with URL, status code, and duration.
    
    Args:
        url (str): The URL to analyze
        
    Returns:
        dict: Structured JSON with redirect chain information
    """
    chain = []
    max_redirects = 10
    current_url = url
    
    # Ensure URL has a protocol
    if not current_url.startswith(("http://", "https://")):
        current_url = "http://" + current_url
    
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=10.0) as client:
            for i in range(max_redirects):
                start_time = time.time()
                try:
                    response = await client.get(current_url)
                    duration_ms = round((time.time() - start_time) * 1000)
                    
                    chain.append({
                        "url": str(response.url),
                        "status": response.status_code,
                        "duration_ms": duration_ms
                    })
                    
                    # Check if there's a redirect
                    if response.status_code in [301, 302, 303, 307, 308]:
                        location = response.headers.get("location")
                        if location:
                            # Handle relative redirects
                            if location.startswith("/"):
                                parsed_url = httpx.URL(current_url)
                                current_url = f"{parsed_url.scheme}://{parsed_url.host}{location}"
                            elif not location.startswith(("http://", "https://")):
                                # Relative path
                                current_url = location
                            else:
                                current_url = location
                        else:
                            break
                    else:
                        # No more redirects
                        break
                        
                except httpx.TimeoutException:
                    duration_ms = round((time.time() - start_time) * 1000)
                    chain.append({
                        "url": current_url,
                        "status": 408,
                        "duration_ms": duration_ms,
                        "error": "Timeout"
                    })
                    break
                except Exception as e:
                    duration_ms = round((time.time() - start_time) * 1000)
                    chain.append({
                        "url": current_url,
                        "status": 0,
                        "duration_ms": duration_ms,
                        "error": str(e)
                    })
                    break
                    
    except Exception as e:
        return {
            "chain": [{
                "url": url,
                "status": 0,
                "duration_ms": 0,
                "error": f"Error initializing redirect chain analysis: {str(e)}"
            }]
        }
        
    return {"chain": chain}