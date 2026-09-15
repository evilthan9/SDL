"""回收 instance/uploads/vulns 下的孤儿图片文件。

为什么需要它
------------
``upload_image`` 是在用户**还在编辑时**就被调用的（粘贴即上传），那一刻漏洞可能
还不存在、或者用户最后取消了保存。这些文件会永久留在磁盘上。不能在保存时同步
删盘（用户可能撤销），所以在保存时只更新引用缓存，盘上的垃圾交给这个脚本回收。

判定规则
--------
一个文件被删除，当且仅当同时满足：

1. 它的文件名**没有被任何漏洞的 screenshots 列引用**；
2. 它的修改时间已经超过 ``--days`` 天（默认 7）。

第 2 条是关键的安全垫：刚上传、还没保存的图片不能被误删。

用法
----
    python scripts/cleanup_orphan_uploads.py              # 只看不删（默认）
    python scripts/cleanup_orphan_uploads.py --apply      # 真的删除
    SDL_DB=instance/sdl_demo.db python scripts/... --apply

默认是 dry-run。这个脚本不挂路由，只手工运行。
"""
import argparse
import json
import os
import sys
import time
from datetime import datetime, timedelta

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

DEFAULT_DAYS = 7


def _referenced_filenames():
    """所有漏洞的 screenshots 列里出现过的文件名集合。"""
    from app import create_app, db
    from app.models import Vulnerability

    app = create_app()
    referenced = set()
    with app.app_context():
        for (raw,) in db.session.query(Vulnerability.screenshots).all():
            if not raw:
                continue
            try:
                names = json.loads(raw)
            except (TypeError, ValueError):
                continue  # 脏数据不该让清理脚本整个挂掉
            if isinstance(names, list):
                referenced.update(n for n in names if isinstance(n, str))
    return referenced, app.config['BASE_DIR']


def main():
    parser = argparse.ArgumentParser(description='回收未被引用的上传图片')
    parser.add_argument('--apply', action='store_true',
                        help='真的删除。不加这个参数只做演练（默认）')
    parser.add_argument('--days', type=int, default=DEFAULT_DAYS,
                        help=f'只清理超过 N 天的文件（默认 {DEFAULT_DAYS}）')
    args = parser.parse_args()

    referenced, base_dir = _referenced_filenames()
    upload_dir = os.path.join(base_dir, 'instance', 'uploads', 'vulns')

    if not os.path.isdir(upload_dir):
        print(f'上传目录不存在，无需清理：{upload_dir}')
        return

    cutoff = time.time() - args.days * 86400
    orphans, kept, recent = [], 0, 0

    for name in sorted(os.listdir(upload_dir)):
        path = os.path.join(upload_dir, name)
        if not os.path.isfile(path):
            continue
        if name in referenced:
            kept += 1
            continue
        if os.path.getmtime(path) >= cutoff:
            recent += 1   # 刚上传、可能还没保存，不动
            continue
        orphans.append((name, os.path.getsize(path)))

    print(f'上传目录：{upload_dir}')
    print(f'  被引用（保留）      : {kept}')
    print(f'  未引用但很新（保留）: {recent}   （{args.days} 天内，可能还没保存）')
    print(f'  判定为孤儿          : {len(orphans)}')

    if not orphans:
        print('\n没有需要回收的文件。')
        return

    total = sum(size for _name, size in orphans)
    print(f'  可回收空间          : {total / 1024:.1f} KB')
    for name, size in orphans[:20]:
        stamp = datetime.fromtimestamp(
            os.path.getmtime(os.path.join(upload_dir, name))
        ).strftime('%Y-%m-%d %H:%M')
        print(f'    {name}  {size / 1024:>7.1f} KB  {stamp}')
    if len(orphans) > 20:
        print(f'    …… 另有 {len(orphans) - 20} 个')

    if not args.apply:
        print('\n这是演练。确认无误后加 --apply 真正删除。')
        return

    removed = 0
    for name, _size in orphans:
        try:
            os.remove(os.path.join(upload_dir, name))
            removed += 1
        except OSError as exc:
            print(f'  删除失败 {name}: {exc}')
    print(f'\n已删除 {removed} 个文件。')


if __name__ == '__main__':
    main()
