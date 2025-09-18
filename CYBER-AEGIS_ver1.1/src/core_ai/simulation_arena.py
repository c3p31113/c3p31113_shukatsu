# src/core_ai/simulation_arena.py
import datetime
import os
import json
import random

class SimulationArena:
    def __init__(self, environment_profile, objective_file, security_profile=None):
        print("--- [Arena] Building dynamic arena based on user's digital twin...")
        self.objective_file = objective_file
        self.filesystem = {
            "C:\\Windows\\System32": { "kernel32.dll": "system_file", "cmd.exe": "<exe>", "powershell.exe": "<exe>" },
            "C:\\Program Files": {}
        }
        for path_name, path_str in environment_profile.get("user_specific_paths", {}).items():
            if path_str: # パスがNoneでないことを確認
                self.filesystem[path_str] = {}
                if path_name == 'documents':
                    self.filesystem[path_str][objective_file] = "sensitive_data"
                if path_name == 'downloads':
                    self.filesystem[path_str]["setup.exe"] = "<downloaded_file>"
        
        self.installed_software = environment_profile.get("installed_software", [])
        
        if security_profile:
            self.security_profile = security_profile
        else:
            self.security_profile = {"name": "None", "rules": []}
        print(f"  [Arena Security] Profile '{self.security_profile.get('name', 'Unnamed')}' is ACTIVE with rules: {self.security_profile.get('rules', [])}")

        self.processes = [{"pid": 101, "name": "explorer.exe", "user": "SYSTEM"}]
        self.event_logs = []
        self.next_pid = 1000
        self.quarantined_files = {}
        print("--- [Arena] Dynamic arena construction complete. ---")

    def get_current_state_for_ai(self):
        state = {
            "filesystem": list(self.filesystem.keys()),
            "running_processes": [{"pid": p["pid"], "name": p["name"]} for p in self.processes],
            "installed_software": self.installed_software,
            "security_software": self.security_profile.get("name", "Unknown")
        }
        return json.dumps(state, indent=2, ensure_ascii=False)

    def _log_event(self, event_type, details):
        timestamp = datetime.datetime.now().isoformat()
        log_entry = f"[{timestamp}] - {event_type}: {details}"
        self.event_logs.append(log_entry)
        print(f"  [Arena Log] {log_entry}")

    def get_all_logs(self):
        return "\n".join(self.event_logs)

    def execute_red_team_tactic(self, tactic_cmd):
        if not tactic_cmd or not tactic_cmd.get("parameters"):
            self._log_event("TACTIC_VALIDATION_FAILURE", f"Invalid command: {tactic_cmd}")
            return
        
        params = tactic_cmd.get("parameters", {})
        tactic = tactic_cmd.get("tactic")
        
        if "command_to_execute" in params:
            commandline = params["command_to_execute"]
            process_name = "powershell.exe" if "powershell.exe" in commandline.lower() else "cmd.exe"
            if "powershell" in process_name or "cmd" in process_name:
                self._create_process(name=process_name, commandline=commandline)
            elif "reg" in commandline.lower():
                self._execute_registry_command(commandline)
        elif tactic == "T1105":
            self.execute_t1105_ingress_tool_transfer(**params)
        else:
            self._log_event("TACTIC_NOT_IMPLEMENTED", f"Tactic '{tactic}' is not implemented.")

    def _execute_registry_command(self, commandline):
        self._log_event("TACTIC_EXECUTION", f"Executing registry command: {commandline}")
        # (将来的に、レジストリ操作に対するセキュリティルールもここに追加可能)
        self._log_event("REGISTRY_MODIFY_SUCCESS", f"Registry command executed.")

    def execute_blue_team_action(self, action_details):
        action = action_details.get("action")
        parameters = action_details.get("parameters", {})
        if not action:
            return
        
        if action == "terminate_process":
            pid = parameters.get("pid")
            try:
                self._terminate_process(int(pid))
            except (ValueError, TypeError):
                self._log_event("BLUE_TEAM_FAIL", f"Invalid PID '{pid}'.")
        elif action == "quarantine_file":
            filepath = parameters.get("filepath")
            if filepath:
                self._quarantine_file(filepath)
    
    def execute_t1105_ingress_tool_transfer(self, url, destination):
        self._log_event("TACTIC_EXECUTION", f"T1105: Transfer from {url} to {destination}")
        
        for rule in self.security_profile.get("rules", []):
            if (rule.get("action") == "block" and
                rule.get("trigger_file_extension") in destination.lower() and
                rule.get("trigger_location", "").lower() in destination.lower()):
                
                if random.random() < rule.get("confidence", 1.0):
                    self._log_event("TACTIC_BLOCKED", f"'{self.security_profile.get('name')}' probabilistically blocked file creation based on evidence: {rule.get('source', 'N/A')}")
                    return
        
        if self._create_file(path=destination, content="<simulated_exploit_code>"):
            self._log_event("TACTIC_SUCCESS", f"Transfer to '{destination}' completed.")
        else:
            self._log_event("TACTIC_FAIL", f"Transfer from '{url}' failed.")
    
    def _create_process(self, name, commandline):
        for rule in self.security_profile.get("rules", []):
            if (rule.get("action") == "alert" and
                rule.get("trigger_process", "").lower() in name.lower()):
                
                if random.random() < rule.get("confidence", 1.0):
                     self._log_event("SECURITY_ALERT", f"Suspicious process '{name}' detected by '{self.security_profile.get('name')}' based on evidence: {rule.get('source', 'N/A')}")
        
        pid = self.next_pid
        self.processes.append({"pid": pid, "name": name, "commandline": commandline})
        self.next_pid += 1
        self._log_event("PROCESS_CREATE_SUCCESS", f"Process '{name}' (PID: {pid}) created...")
        return pid

    def _create_file(self, path, content):
        dir_path_str, filename = os.path.split(path)
        if dir_path_str in self.filesystem:
            self.filesystem[dir_path_str][filename] = content
            self._log_event("FILE_CREATE_SUCCESS", f"File '{path}' created.")
            return True
        self._log_event("FILE_CREATE_FAIL", f"Directory '{dir_path_str}' not found.")
        return False
        
    def _terminate_process(self, pid_to_terminate):
        proc_to_kill = next((p for p in self.processes if p["pid"] == pid_to_terminate), None)
        if proc_to_kill:
            self.processes.remove(proc_to_kill)
            self._log_event("PROCESS_TERMINATE_SUCCESS", f"PID {pid_to_terminate} ('{proc_to_kill['name']}') terminated.")
        else:
            self._log_event("PROCESS_TERMINATE_FAIL", f"PID {pid_to_terminate} not found.")
        
    def _quarantine_file(self, filepath):
        dir_path, filename = os.path.split(filepath)
        if dir_path in self.filesystem and filename in self.filesystem[dir_path]:
            self.filesystem[dir_path].pop(filename)
            self.quarantined_files[filepath] = "quarantined"
            self._log_event("FILE_QUARANTINE_SUCCESS", f"File '{filepath}' quarantined.")