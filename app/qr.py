import qrcode
import qrcode.image.svg


def make_auth_qr_svg_bytes(payload: str) -> bytes:
    img = qrcode.make(payload, image_factory=qrcode.image.svg.SvgImage)
    return img.to_string()  # bytes, no args

def make_auth_qr_svg(payload: str) -> str:
    return make_auth_qr_svg_bytes(payload).decode("utf-8")

#def make_auth_qr_svg(payload_json: str) -> str:
#    img = qrcode.make(payload_json, image_factory=qrcode.image.svg.SvgImage)
#    return img.to_string(encoding="unicode")


#def make_auth_qr_svg_bytes(payload_json: str) -> bytes:
#    img = qrcode.make(payload_json, image_factory=qrcode.image.svg.SvgImage)
#    return img.to_string(encoding="utf-8")

