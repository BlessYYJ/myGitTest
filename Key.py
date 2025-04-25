from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

import base64
# 1. 生成 Ed25519 密钥对
def generate_keys():
    private_key = ed25519.Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    # 保存私钥
    with open("ed25519_private_key.pem", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        ))

    # 保存公钥
    with open("ed25519_public_key.pem", "wb") as f:
        f.write(public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))
    
    print("✅ 密钥对生成完成并保存到当前目录。")

# 2. 使用私钥签名数据
def sign_message(message: str, private_key_path="ed25519_private_key.pem") -> bytes:
    with open(private_key_path, "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    signature = private_key.sign(message.encode('utf-8'))
    print("🖋️ 签名完成。")
    return signature

# 3. 使用公钥验证签名
def verify_signature(message: str, signature: bytes, public_key_path="ed25519_public_key.pem") -> bool:
    with open(public_key_path, "rb") as f:
        public_key = serialization.load_pem_public_key(f.read())

    try:
        public_key.verify(signature, message.encode('utf-8'))
        print("✅ 签名验证成功。")
        return True
    except InvalidSignature:
        print("❌ 签名验证失败。")
        return False

# 示例用法
if __name__ == "__main__":
    # 第一次运行建议生成密钥
    # generate_keys()

    # 待签名数据（比如和风天气的请求参数串）
    data = "eyJhbGciOiJFZERTQSIsImtpZCI6IlRCR1hFWThERkoifQ.eyJzdWIiOiIzN1RQOVhWSERNIiwiaWF0IjoxNzEzNjgzMzEwLCJleHAiOjE3MTM3NjMzMTB9"
    
    # 签名
    signature = sign_message(data)
    # 使用 Base64 URL 安全编码并去掉末尾的 '='
    encoded_signature = base64.urlsafe_b64encode(signature).decode('utf-8').rstrip('=')
    print("✍️ Base64 URL 签名结果:", encoded_signature)

    # 验证签名
    verify_signature(data, signature)
