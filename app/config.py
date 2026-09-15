import os
import secrets

BASE_DIR = os.path.abspath(os.path.dirname(os.path.dirname(__file__)))


def _load_or_create_secret_key(base_dir):
    """取 SECRET_KEY:环境变量优先,否则用 instance/secret.key 持久化的随机值。

    持久化这一步是必须的。若每次启动都现场随机生成,已登录用户的会话会全部失效,
    且 CSRF token 校验必然失败(签发与校验用的是同一把 key)。

    原实现是硬编码的 'dev-secret-key' —— 公开且固定,等于没有密钥。
    """
    env_key = os.environ.get('SECRET_KEY')
    if env_key:
        return env_key

    key_path = os.path.join(base_dir, 'instance', 'secret.key')
    if os.path.isfile(key_path):
        with open(key_path, 'r', encoding='utf-8') as handle:
            saved = handle.read().strip()
            if saved:
                return saved

    key = secrets.token_hex(32)
    os.makedirs(os.path.dirname(key_path), exist_ok=True)
    with open(key_path, 'w', encoding='utf-8') as handle:
        handle.write(key)
    return key


class Config:
    SECRET_KEY = _load_or_create_secret_key(BASE_DIR)

    # 获取项目根目录的绝对路径
    BASE_DIR = BASE_DIR
    # 漏洞截图的上传目录。挂在 Config 上是为了让测试能指向临时目录 ——
    # 否则跑一次测试就会往仓库的 instance/uploads/vulns 里写一堆图片。
    UPLOAD_DIR = os.path.join(BASE_DIR, 'instance', 'uploads', 'vulns')
    # 数据库文件路径。可用 SDL_DB 环境变量切库（例如演示前用种子脚本生成的库）:
    #   set SDL_DB=instance/sdl_demo.db && python run.py
    DB_PATH = os.path.abspath(
        os.environ.get('SDL_DB') or os.path.join(BASE_DIR, 'instance', 'sdl.db')
    )
    # 确保路径使用正确格式（Windows 用反斜杠会被 SQLite 正确处理）
    SQLALCHEMY_DATABASE_URI = f'sqlite:///{DB_PATH.replace(os.sep, "/")}'

    SQLALCHEMY_TRACK_MODIFICATIONS = False

    # 开发期关掉静态文件缓存。Flask 默认给静态文件 12 小时 max_age,
    # 迭代样式时会反复出现"改了没生效"的错觉。
    SEND_FILE_MAX_AGE_DEFAULT = 0

    # 上传体积上限（截图等）。挂在 Config 类上而不是模块级变量,
    # 否则测试里用 monkeypatch 覆盖类属性的做法够不到它。
    MAX_CONTENT_LENGTH = 8 * 1024 * 1024

    # 全站 CSRF 防护
    WTF_CSRF_ENABLED = True
    # 默认是 3600 秒。答辩时页面开着超过一小时再提交就会"令牌过期",
    # 这是很常见的现场翻车点,这里直接关掉时限。
    WTF_CSRF_TIME_LIMIT = None
