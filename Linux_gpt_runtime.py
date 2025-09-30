#!/usr/bin/env python3
"""
Cross-platform runtime SBOM watcher for Windows / Linux / macOS.

- Detect target executables when they start
- Collect actual loaded libraries from the running process
- Try to extract version/SONAME information in a platform-appropriate way
- Emit CycloneDX JSON SBOM
- Optionally call `syft` to produce another SBOM (if syft is installed)
"""

import os
import sys
import time
import json
import psutil
import subprocess
from datetime import datetime

SBOM_DIR = os.path.join(os.getcwd(), "sbom_logs")
os.makedirs(SBOM_DIR, exist_ok=True)

# 감시 대상 실행파일 이름 (소문자/대문자 구분될 수 있으므로 비교 시 조정)
TARGET_EXECUTABLES = {"python", "python3", "node", "java", "nginx", "nginx.exe", "python.exe", "node.exe", "java.exe"}

# Windows에서 win32api가 있으면 사용 (선택적)
try:
    if sys.platform.startswith("win"):
        import win32api  # type: ignore
    else:
        win32api = None
except Exception:
    win32api = None


def get_file_version_windows(filepath: str) -> str:
    """Windows 전용: win32api로 버전 추출 시도"""
    try:
        if not win32api:
            return "unknown"
        info = win32api.GetFileVersionInfo(filepath, '\\')
        ms = info.get('FileVersionMS')
        ls = info.get('FileVersionLS')
        if ms is None or ls is None:
            return "unknown"
        version = f"{win32api.HIWORD(ms)}.{win32api.LOWORD(ms)}.{win32api.HIWORD(ls)}.{win32api.LOWORD(ls)}"
        return version
    except Exception:
        return "unknown"


def get_soname_unix(filepath: str) -> str:
    """
    Linux/macOS: try to obtain SONAME or a library identifier using objdump or readelf.
    Returns SONAME if found, otherwise 'unknown'.
    """
    # Try objdump -p
    try:
        proc = subprocess.run(["objdump", "-p", filepath], capture_output=True, text=True, timeout=5)
        out = proc.stdout
        if out:
            for line in out.splitlines():
                line = line.strip()
                # objdump prints: "SONAME               libfoo.so.1"
                if line.startswith("SONAME"):
                    parts = line.split()
                    if len(parts) >= 2:
                        return parts[1].strip()
        # fallback to readelf -d
        proc = subprocess.run(["readelf", "-d", filepath], capture_output=True, text=True, timeout=5)
        out = proc.stdout
        if out:
            for line in out.splitlines():
                if "SONAME" in line:
                    # 예: 0x000000000000000e (SONAME) Library soname: [libm.so.6]
                    if "[" in line and "]" in line:
                        return line.split("[", 1)[1].split("]", 1)[0].strip()
    except FileNotFoundError:
        # objdump/readelf 없음
        return "unknown"
    except Exception:
        return "unknown"
    return "unknown"


def get_file_version(filepath: str) -> str:
    """플랫폼에 맞게 파일 버전을 추출하려 시도한다. 실패하면 'unknown' 반환."""
    try:
        if not os.path.isfile(filepath):
            return "unknown"
        if sys.platform.startswith("win"):
            return get_file_version_windows(filepath)
        else:
            # Unix-like
            soname = get_soname_unix(filepath)
            if soname != "unknown":
                return soname
            # as a last resort, try extracting a GNU-style version symbol via strings (heuristic) - keep cheap
            try:
                proc = subprocess.run(["strings", "-n", "8", filepath], capture_output=True, text=True, timeout=5)
                out = proc.stdout
                # heuristic: look for something like "Version" or "version"
                for line in out.splitlines():
                    if "Version" in line or "version" in line:
                        token = line.strip()
                        if len(token) <= 128:
                            return token
            except Exception:
                pass
            return "unknown"
    except Exception:
        return "unknown"


def get_loaded_libs(proc: psutil.Process) -> dict:
    """프로세스에서 실제 로드된 라이브러리 목록과 (가능하면) 버전 정보 추출"""
    libs_info = {}
    try:
        for m in proc.memory_maps():
            path = getattr(m, "path", None)
            if not path:
                continue
            # 실제 파일 경로(절대경로)만 처리
            # Windows의 경우 드라이브 문자가 들어오므로 os.path.isabs로 체크
            if not os.path.isabs(path):
                continue
            # 제외: special pseudo paths like [vdso], [heap], etc.
            if path.startswith("[") and path.endswith("]"):
                continue
            if not os.path.isfile(path):
                continue
            if path in libs_info:
                continue
            version = get_file_version(path)
            libs_info[path] = version
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    except Exception:
        # 안전하게 무시
        pass
    return libs_info


def create_sbom(exe_name: str, pid: int, libs_info: dict, out_file: str):
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "timestamp": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
            "component": {"type": "application", "name": exe_name, "version": "runtime"}
        },
        "components": []
    }

    for lib_path, version in libs_info.items():
        lib_name = os.path.basename(lib_path)
        # sanitize path for purl (simple)
        cleaned_path = lib_path.replace(":", "").replace("\\", "/")
        sbom["components"].append({
            "type": "library",
            "name": lib_name,
            "version": version,
            "purl": f"pkg:generic/{lib_name}?file_path={cleaned_path}"
        })

    try:
        with open(out_file, "w", encoding="utf-8") as f:
            json.dump(sbom, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[!] SBOM 쓰기 실패: {e}")


def generate_sbom_with_syft(proc_exe: str, pid: int, timestamp: str):
    """Syft가 설치되어 있으면 syft로도 SBOM 생성 (선택적)"""
    if not proc_exe:
        return
    # syft 사용 가능성 체크
    if not shutil_which("syft"):
        return
    out_file = os.path.join(SBOM_DIR, f"syft_{os.path.basename(proc_exe)}_{pid}_{timestamp}.json")
    try:
        with open(out_file, "w", encoding="utf-8") as fout:
            subprocess.run(["syft", proc_exe, "-o", "cyclonedx-json"], stdout=fout, stderr=subprocess.DEVNULL, check=True, timeout=60)
        print(f"[+] Syft 기반 SBOM 추가 생성됨: {out_file}")
    except Exception as e:
        print(f"[!] Syft 실행 실패: {proc_exe} ({e})")


def shutil_which(cmd: str) -> bool:
    """간단한 which 체크"""
    from shutil import which
    return which(cmd) is not None


def normalize_exe_name(name: str) -> str:
    if not name:
        return ""
    # 확장자 제거, 소문자화
    base = os.path.splitext(name)[0]
    return base.lower()


def main():
    print(f"[*] 프로세스 감시 시작 (대상: {', '.join(TARGET_EXECUTABLES)})")
    seen_pids = set()

    while True:
        for proc in psutil.process_iter(attrs=["pid", "name", "exe"]):
            try:
                exe_name_raw = proc.info.get("name") or ""
                exe_name = normalize_exe_name(exe_name_raw)
                pid = proc.info.get("pid")
                if not pid or not exe_name:
                    continue

                if exe_name in {n.lower() for n in TARGET_EXECUTABLES} and pid not in seen_pids:
                    seen_pids.add(pid)
                    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                    out_file = os.path.join(SBOM_DIR, f"sbom_{exe_name}_{pid}_{timestamp}.json")

                    print(f"[+] 실행 감지: {exe_name_raw} (PID={pid}) → SBOM 생성 시작")

                    libs_info = get_loaded_libs(proc)
                    create_sbom(exe_name_raw, pid, libs_info, out_file)
                    print(f"[완료] SBOM 저장됨: {out_file} (총 {len(libs_info)}개 라이브러리)")

                    # Syft 호출 (proc.info['exe']가 None일 수 있으니 예외 처리)
                    try:
                        proc_exe = proc.info.get("exe") or ""
                    except Exception:
                        proc_exe = ""
                    # syft는 선택적이므로 실패해도 계속
                    generate_sbom_with_syft(proc_exe, pid, timestamp)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception:
                # 로그를 남기고 계속 (감시 루프는 중단하면 안 됨)
                continue
        time.sleep(1)


if __name__ == "__main__":
    main()
