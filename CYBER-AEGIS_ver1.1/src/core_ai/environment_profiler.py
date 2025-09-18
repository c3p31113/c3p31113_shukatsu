# src/core_ai/environment_profiler.py
import os
import subprocess
import json
from pathlib import Path
import ctypes
from ctypes import wintypes
import re

# --- Windows APIを直接呼び出すための準備 (変更なし) ---
CSIDL_DESKTOP = 0
CSIDL_PERSONAL = 5 # My Documents
CSIDL_DOWNLOADS = 36 # Vista以降

_SHGetFolderPath = ctypes.windll.shell32.SHGetFolderPathW
_SHGetFolderPath.argtypes = [wintypes.HWND, ctypes.c_int, wintypes.HANDLE, wintypes.DWORD, wintypes.LPCWSTR]

def _get_known_folder_path(csidl):
    path_buf = ctypes.create_unicode_buffer(wintypes.MAX_PATH)
    return path_buf.value if _SHGetFolderPath(0, csidl, 0, 0, path_buf) == 0 else None
# --- ここまで ---

class EnvironmentProfiler:
    def __init__(self):
        self.profile = {
            "user_specific_paths": {},
            "installed_software": [],
            "security_software": [],
            "profiling_errors": []
        }

    # ... (_get_user_paths, _get_installed_software メソッドは変更なし) ...
    def _get_user_paths(self):
        print("  [Profiler] Analyzing user directory structure (using Windows API and robust fallbacks)...")
        found_paths = {}
        home = Path.home()
        
        paths_to_find = {
            "desktop": CSIDL_DESKTOP, "documents": CSIDL_PERSONAL, "downloads": CSIDL_DOWNLOADS,
        }
        for name, csidl in paths_to_find.items():
            path_str = _get_known_folder_path(csidl)
            if path_str and Path(path_str).exists() and str(path_str).upper() != "C:\\WINDOWS":
                found_paths[name] = path_str
                print(f"    - Found '{name}': {path_str}")
            else:
                print(f"    - API failed for '{name}', trying registry fallback...")
                try:
                    cmd_map = {
                        "downloads": f'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" /v "{{374DE290-123F-4565-9164-39C4925E467B}}"',
                        "desktop": f'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" /v "Desktop"',
                        "documents": f'reg query "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\User Shell Folders" /v "Personal"'
                    }
                    cmd = cmd_map.get(name)
                    if not cmd: continue
                    result = subprocess.run(cmd, capture_output=True, text=True, encoding='oem', errors='ignore', timeout=10)
                    if result.returncode == 0:
                        path_match = re.search(r'REG_EXPAND_SZ\s+(.*)', result.stdout)
                        if path_match:
                            reg_path_str = os.path.expandvars(path_match.group(1).strip())
                            if Path(reg_path_str).exists():
                                found_paths[name] = reg_path_str
                                print(f"    - Found '{name}' via Registry: {reg_path_str}")
                                continue
                except Exception as e:
                    print(f"  [Profiler Warning] Registry scan for {name} failed: {e}")

                potential_paths = [home / name.capitalize(), home / f"OneDrive/{name.capitalize()}", home / name, home / f"OneDrive/{name}"]
                found = False
                for path in potential_paths:
                    if path.exists():
                        found_paths[name] = str(path)
                        print(f"    - Found '{name}' (fallback): {str(path)}")
                        found = True
                        break
                if not found:
                    error_msg = f"Could not resolve known folder '{name}'."
                    print(f"  [Profiler Warning] {error_msg}")
                    self.profile["profiling_errors"].append(error_msg)

        appdata_path = os.getenv("LOCALAPPDATA")
        if appdata_path and (temp_path := Path(appdata_path) / "Temp").exists():
            found_paths["temp"] = str(temp_path)
            print(f"    - Found 'temp': {str(temp_path)}")
            
        return found_paths

    def _get_installed_software(self):
        print("  [Profiler] Scanning for installed software...")
        try:
            print("    [Profiler Attempt 1/1] Using direct 'reg query'...")
            registry_paths = [
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall",
                "HKLM\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"
            ]
            software_map = {}
            for path in registry_paths:
                try:
                    cmd_keys = f'reg query "{path}"'
                    result_keys = subprocess.run(cmd_keys, capture_output=True, text=True, encoding='oem', errors='ignore', timeout=60)
                    if result_keys.returncode != 0: continue
                    for line in result_keys.stdout.splitlines():
                        if line.startswith("HKEY_"):
                            key_path = line.strip()
                            try:
                                cmd_details_name = f'reg query "{key_path}" /v "DisplayName"'
                                result_name = subprocess.run(cmd_details_name, capture_output=True, text=True, encoding='oem', errors='ignore', timeout=5)
                                if result_name.returncode == 0 and "DisplayName" in result_name.stdout:
                                    name = re.search(r'DisplayName\s+REG_SZ\s+(.*)', result_name.stdout)
                                    if name:
                                        software_map.setdefault(key_path, {})["name"] = name.group(1).strip()

                                cmd_details_version = f'reg query "{key_path}" /v "DisplayVersion"'
                                result_version = subprocess.run(cmd_details_version, capture_output=True, text=True, encoding='oem', errors='ignore', timeout=5)
                                if result_version.returncode == 0 and "DisplayVersion" in result_version.stdout:
                                    version = re.search(r'DisplayVersion\s+REG_SZ\s+(.*)', result_version.stdout)
                                    if version:
                                        software_map.setdefault(key_path, {})["version"] = version.group(1).strip()
                            except Exception: continue
                except Exception as e: raise RuntimeError(f"Failed to query registry path {path}: {e}")

            software_list = [v for v in software_map.values() if v.get("name")]
            if not software_list: raise ValueError("Registry query returned no software.")
            
            print(f"    [Profiler SUCCESS] Found {len(software_list)} applications.")
            return software_list
        except Exception as e:
            error_msg = f"Scan method (_get_installed_software) failed: {e}"
            print(f"  [Profiler CRITICAL] {error_msg}")
            self.profile["profiling_errors"].append(error_msg)
            return [{"name": "PROFILING_FAILED", "version": "0.0.0"}]

    def _identify_security_software(self, all_software):
        """
        インストール済みソフトとWindowsサービスの状態から、有効なセキュリティ製品を特定する。
        """
        print("  [Profiler] Identifying security software...")
        found_security_software = []
        
        # ★★★ 新ロジック：Windows Defenderのサービス状態を直接確認 ★★★
        try:
            print("    - Checking Windows Defender service status...")
            cmd = "sc.exe query WinDefend"
            result = subprocess.run(cmd, capture_output=True, text=True, encoding='oem', errors='ignore', timeout=10)
            if result.returncode == 0 and "RUNNING" in result.stdout:
                print("    - Found active service: Windows Defender (WinDefend)")
                found_security_software.append({
                    "name": "Windows Defender",
                    "version": "active_service"
                })
        except FileNotFoundError:
            print("    - 'sc.exe' not found. Skipping Windows Defender service check.")
        except Exception as e:
            print(f"  [Profiler Warning] Failed to check Windows Defender service: {e}")

        # ★★★ 既存ロジック：インストール済みソフト名からサードパーティ製品を特定 ★★★
        print("    - Searching for third-party security software in program list...")
        SECURITY_KEYWORDS = [
            'eset', 'norton', 'mcafee', 'kaspersky', 'avast', 'avg', 
            'bitdefender', 'malwarebytes', 'avira', 'sophos',
            'trend micro', 'f-secure', 'panda', 'emsisoft'
        ]
        
        # 重複追加を防ぐためのセット
        found_names = {s['name'] for s in found_security_software}

        for software in all_software:
            software_name_lower = software.get("name", "").lower()
            for keyword in SECURITY_KEYWORDS:
                if keyword in software_name_lower:
                    if software['name'] not in found_names:
                        print(f"    - Found security software by name: {software['name']}")
                        found_security_software.append(software)
                        found_names.add(software['name'])
                        break
        
        if not found_security_software:
            print("    - No specific security software found.")
            # サービスチェックも失敗し、名前も見つからなかった場合の最終手段
            found_security_software.append({ "name": "Unknown (Default Windows Security assumed)", "version": "unknown" })

        return found_security_software

    def generate_profile(self):
        """
        デジタルツインのプロファイルを生成するメインメソッド。
        """
        print("--- [START] Generating Personal Digital Twin Profile ---")
        self.profile["user_specific_paths"] = self._get_user_paths()
        self.profile["installed_software"] = self._get_installed_software()
        self.profile["security_software"] = self._identify_security_software(self.profile["installed_software"])
        
        print("--- [COMPLETE] Profile Generation Finished ---")
        return self.profile