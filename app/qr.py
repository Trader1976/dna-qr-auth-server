import qrcode
import qrcode.image.svg

def make_auth_qr_svg(payload_json: str) -> str:
    img = qrcode.make(payload_json, image_factory=qrcode.image.svg.SvgImage)
    return img.to_string(encoding="unicode")
