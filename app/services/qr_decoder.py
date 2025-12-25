import numpy as np
import cv2
from pyzbar.pyzbar import decode as pyzbar_decode


def decode_qr_image(image_bytes: bytes) -> str | None:
    """
    Takes raw image bytes and returns decoded QR string or None.
    """
    try:
        # Convert bytes → numpy array → CV2 image
        nparr = np.frombuffer(image_bytes, np.uint8)
        img = cv2.imdecode(nparr, cv2.IMREAD_COLOR)

        if img is None:
            return None

        decoded_objects = pyzbar_decode(img)
        if not decoded_objects:
            return None

        return decoded_objects[0].data.decode("utf-8")
    except Exception:
        return None


