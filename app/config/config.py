import copy
import errno
import os
import shutil
import socket
import tempfile
import threading
from contextlib import contextmanager

import toml
from loguru import logger

from app import __version__, paths

root_dir = str(paths.runtime_root())
config_file = f"{root_dir}/config.toml"
_CONTAINER_CGROUP_MARKERS = ("docker", "containerd", "kubepods", "libpod", "podman")
_DOCKER_HOST_GATEWAY_NAME = "host.docker.internal"
_config_save_lock = threading.RLock()
_diagnostics_update_lock = threading.Lock()
_pending_config_lock = threading.RLock()
_pending_config_updates = {}
_pending_config_save_requested = False
_pending_config_flush_scheduled = False
_MISSING = object()
_DELETE = object()
_UTF8_BOM = "\ufeff"


def _validate_runtime_security() -> None:
    """Fail closed when the server is exposed without authentication.

    This prevents the common unsafe combination of public bind + empty API key,
    or wildcard CORS + unauthenticated browser access. Security must be explicit
    and not rely on the user discovering a dangerous default.
    """
    bind_host = str(app.get("listen_host", listen_host) or "").strip()
    api_key = str(app.get("api_key", "") or "").strip()
    normalized_host = bind_host.lower()

    public_bind = (
        normalized_host in {"0.0.0.0", "::", "[::]"}
        or normalized_host.startswith("0.0.0.0")
        or normalized_host.startswith("::")
    )
    if public_bind and not api_key:
        raise RuntimeError(
            "Unsafe configuration: app.listen_host is public (0.0.0.0/::) but "
            "app.api_key is empty. Use 127.0.0.1 for local-only mode or set a "
            "strong API key before binding to a public interface."
        )

    if (
        bind_host
        and normalized_host not in {"127.0.0.1", "localhost", "::1", "[::1]"}
        and not api_key
    ):
        raise RuntimeError(
            "Unsafe configuration: non-loopback bind requires app.api_key to be set. "
            "Use 127.0.0.1 for local-only access or configure a trusted private "
            "network deployment with authentication enabled."
        )

    if os.getenv("CORS_ALLOWED_ORIGINS", "").strip() == "*" and not api_key:
        raise RuntimeError(
            "Unsafe configuration: CORS_ALLOWED_ORIGINS='*' requires app.api_key "
            "to be set. Restrict the origin allowlist to trusted URLs."
        )


class _SynchronizedConfig(dict):
    """保持 dict 使用方式不变，同时让运行期配置写操作服从同一把锁。"""

    def __setitem__(self, key, value):
        # Streamlit 每次整页 rerun 都会把当前控件值重新写回配置。视频任务持有
        # runtime_config_lock 时，如果值没有变化，这次写入没有任何副作用，也
        # 不应让刷新后的页面卡在表单中途。真正改变配置的写入仍进入下方锁，
        # 因而不能在正在生成的视频中途切换 Provider、密钥或其它全局设置。
        current = super().get(key, _MISSING)
        if current is not _MISSING and current == value:
            return
        with _config_save_lock:
            super().__setitem__(key, value)

    def __delitem__(self, key):
        with _config_save_lock:
            super().__delitem__(key)

    def clear(self):
        if not self:
            return
        with _config_save_lock:
            super().clear()

    def pop(self, key, default=_MISSING):
        # ``pop(key, default)`` 在 key 不存在时同样不会改变配置。WebUI 使用
        # 这种写法表达“采用默认策略”，刷新时必须允许它直接完成。
        if key not in self:
            if default is _MISSING:
                raise KeyError(key)
            return default
        with _config_save_lock:
            if default is _MISSING:
                return super().pop(key)
            return super().pop(key, default)

    def setdefault(self, key, default=None):
        # 与 __setitem__ 相同，已存在 key 的 setdefault 是只读操作。提前返回
        # 可以让只读取默认配置的页面刷新不受长任务配置锁影响。
        current = super().get(key, _MISSING)
        if current is not _MISSING:
            return current
        with _config_save_lock:
            return super().setdefault(key, default)

    def update(self, *args, **kwargs):
        changes = dict(*args, **kwargs)
        if all(
            (current := dict.get(self, key, _MISSING)) is not _MISSING
            and current == value
            for key, value in changes.items()
        ):
            return
        with _config_save_lock:
            super().update(changes)


# ... rest of file unchanged ...

logger.info(f"{project_name} v{project_version}")
_validate_runtime_security()
