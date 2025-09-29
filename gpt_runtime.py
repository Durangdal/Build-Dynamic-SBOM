#!/usr/bin/env python3
"""
Windows 환경에서 실행 중인 프로세스를 감시하여,
- 실행 파일 감지
- 해당 프로세스에서 실제 로드된 DLL 추적
- DLL 파일의 버전 정보를 추출하여 SBOM에 포함
- CycloneDX SBOM(JSON) 생성
"""

import os
import time
import json
import psutil
import win32api  # 버전 정보 추출을 위한 라이브러리 추가
from datetime import datetime
import subprocess

# SBOM 저장 경로
SBOM_DIR = os.path.join(os.getcwd(), "sbom_logs")
os.makedirs(SBOM_DIR, exist_ok=True)

# 감시 대상 실행파일 이름
TARGET_EXECUTABLES = {"python.exe", "python3.exe", "node.exe", "java.exe", "nginx.exe"}


def get_file_version(filepath):
    """Win32 API를 사용하여 실행 파일/DLL의 버전 정보를 추출"""
    try:
        # 파일 버전 정보를 가져옴
        info = win32api.GetFileVersionInfo(filepath, '\\')
        
        # 파일 버전 정보가 담긴 튜플 (Major, Minor, Build, Private)
        ms = info['FileVersionMS']
        ls = info['FileVersionLS']
        
        # 16진수 값을 10진수로 변환하여 버전 문자열 생성 (예: 1.2.3.4)
        version = f"{win32api.HIWORD(ms)}.{win32api.LOWORD(ms)}.{win32api.HIWORD(ls)}.{win32api.LOWORD(ls)}"
        return version
    except Exception:
        # 버전 정보가 없거나 접근 오류 발생 시 'unknown' 반환
        return "unknown"


def get_loaded_libs(proc: psutil.Process):
    """실제로 프로세스에서 로드된 DLL/라이브러리 목록과 버전 추출"""
    libs_info = {} # 경로: 버전
    try:
        for m in proc.memory_maps():
            # 파일이 실제로 존재하고, 이미 목록에 없는 경우에만 처리
            if m.path and os.path.isfile(m.path) and m.path not in libs_info:
                # 1. 버전 정보 추출
                version = get_file_version(m.path)
                # 2. 로드된 라이브러리 경로와 추출된 버전 저장
                libs_info[m.path] = version
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    return libs_info


def create_sbom(exe_name, pid, libs_info: dict, out_file):
    """CycloneDX SBOM JSON 생성 (추출된 버전 정보 포함)"""
    # 주 실행 애플리케이션의 버전은 여전히 'runtime'으로 둠 (버전 정보가 불분명할 수 있으므로)
    # 로드된 DLL/라이브러리만 버전 정보를 사용함
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

        # F-string 외부에서 미리 계산
        cleaned_path = lib_path.replace(':', '').replace('\\', '/')
            
        sbom["components"].append({
            "type": "library",
            "name": lib_name,
            # 추출된 실제 버전 정보 사용
            "version": version, 
            # 파일 경로를 PURL로 인코딩하여 고유성 확보 (Windows 환경 경로 정보 포함)
             
            # F-string 내부에서는 변수만 사용
            "purl": f"pkg:generic/{lib_name}?file_path={cleaned_path}"
        })

    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)


def generate_sbom_with_syft(proc_exe, pid, timestamp):
    out_file = os.path.join(SBOM_DIR, f"syft_{os.path.basename(proc_exe)}_{pid}_{timestamp}.json")
    try:
        subprocess.run(
            ["syft", proc_exe, "-o", "cyclonedx-json"],
            stdout=open(out_file, "w", encoding="utf-8"),
            stderr=subprocess.DEVNULL,
            check=True
        )
        print(f"[+] Syft 기반 SBOM 추가 생성됨: {out_file}")
    except Exception as e:
        print(f"[!] Syft 실행 실패: {proc_exe} ({e})")

def main():
    print(f"[*] Windows 프로세스 감시 시작 (대상: {', '.join(TARGET_EXECUTABLES)})")
    seen_pids = set()

    while True:
        for proc in psutil.process_iter(attrs=["pid", "name", "exe"]):
            try:
                exe_name = proc.info["name"]
                pid = proc.info["pid"]
                
                # 신규 실행된 프로세스 감지
                if pid not in seen_pids and exe_name in TARGET_EXECUTABLES:
                    seen_pids.add(pid)

                    timestamp = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
                    out_file = os.path.join(SBOM_DIR, f"sbom_{exe_name}_{pid}_{timestamp}.json")

                    print(f"[+] 실행 감지: {exe_name} (PID={pid}) → SBOM 생성 시작")

                    libs_info = get_loaded_libs(proc)
                    create_sbom(exe_name, pid, libs_info, out_file)
                    print(f"[완료] SBOM 저장됨: {out_file} (총 {len(libs_info)}개 라이브러리)")

                    print(f"[완료] DLL 기반 SBOM 저장: {out_file}")

                    # Syft 기반 SBOM
                    generate_sbom_with_syft(proc.info["exe"], pid, timestamp)
    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # 프로세스가 감시 사이에 종료되거나 권한이 없는 경우
                continue

        time.sleep(1)


if __name__ == "__main__":
    main()
