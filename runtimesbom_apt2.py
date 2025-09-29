#!/usr/bin/env python3
"""
Windows 환경에서 실행 중인 프로세스를 감시하여,
- 실행 파일 감지
- 해당 프로세스에서 실제 로드된 DLL 추적
- CycloneDX SBOM(JSON) 생성
"""

import os
import time
import json
import psutil
from datetime import datetime

# SBOM 저장 경로
SBOM_DIR = os.path.join(os.getcwd(), "sbom_logs")
os.makedirs(SBOM_DIR, exist_ok=True)

# 감시 대상 실행파일 이름
TARGET_EXECUTABLES = {"python.exe", "python3.exe", "node.exe", "java.exe", "nginx.exe"}


def get_loaded_libs(proc: psutil.Process):
    """실제로 프로세스에서 로드된 DLL/라이브러리 목록"""
    libs = set()
    try:
        for m in proc.memory_maps():
            if m.path and os.path.isfile(m.path):
                libs.add(m.path)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return list(libs)


def create_sbom(exe_name, pid, libs, out_file):
    """CycloneDX SBOM JSON 생성"""
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

    for lib in libs:
        sbom["components"].append({
            "type": "library",
            "name": os.path.basename(lib),
            "version": "runtime",
            "purl": f"pkg:generic/{os.path.basename(lib)}"
        })

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)


def main():
    print(f"[*] Windows 프로세스 감시 시작 (대상: {', '.join(TARGET_EXECUTABLES)})")
    seen_pids = set()

    while True:
        for proc in psutil.process_iter(attrs=["pid", "name", "exe"]):
            try:
                exe_name = proc.info["name"]
                pid = proc.info["pid"]
                exe_path = proc.info["exe"]
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            # 신규 실행된 프로세스 감지
            if pid not in seen_pids and exe_name in TARGET_EXECUTABLES:
                seen_pids.add(pid)

                timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                out_file = os.path.join(SBOM_DIR, f"sbom_{exe_name}_{pid}_{timestamp}.json")

                print(f"[+] 실행 감지: {exe_name} (PID={pid}) → SBOM: {out_file}")

                libs = get_loaded_libs(proc)
                create_sbom(exe_name, pid, libs, out_file)

        time.sleep(1)


if __name__ == "__main__":
    main()
