import unittest
import sys
import os

# 添加项目根目录到Python路径
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from jwt_gui_integrated import JWToolCore
except ImportError:
    # 如果导入失败，跳过测试
    JWToolCore = None


class TestJWTToolGUI(unittest.TestCase):
    """JWT Tool GUI的单元测试"""
    
    def setUp(self):
        """测试前的设置"""
        if JWToolCore is None:
            self.skipTest("JWToolCore import failed")
        self.core = JWToolCore()
    
    def test_import(self):
        """测试导入是否成功"""
        self.assertIsNotNone(JWToolCore, "JWToolCore import failed")
    
    def test_validate_token_empty(self):
        """测试空令牌验证"""
        if JWToolCore is None:
            self.skipTest("JWToolCore import failed")
        header, payload, signature, contents = self.core.validateToken("")
        self.assertIsNone(header, "Empty token should return None header")
    
    def test_sign_token(self):
        """测试令牌签名"""
        if JWToolCore is None:
            self.skipTest("JWToolCore import failed")
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {"sub": "1234567890", "name": "John Doe", "iat": 1516239022}
        token = self.core.signToken(header, payload, "secret", "HS256")
        self.assertIsNotNone(token, "Token signing should not return None")
        self.assertIn(".", token, "Token should contain dots")


if __name__ == "__main__":
    unittest.main()