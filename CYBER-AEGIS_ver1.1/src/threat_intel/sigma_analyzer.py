import os
import yaml
import re
import json

def flatten_dict(d, parent_key='', sep='.'):
    items = []
    for k, v in d.items():
        new_key = parent_key + sep + k if parent_key else k
        if isinstance(v, dict):
            items.extend(flatten_dict(v, new_key, sep=sep).items())
        else:
            items.append((new_key.lower(), v))
    return dict(items)

class SigmaAnalyzer:
    def __init__(self, rule_dirs):
        self.rule_dirs = rule_dirs
        self.rules = self._load_rules()

    def _load_rules(self):
        rules = []
        for rule_dir in self.rule_dirs:
            if not os.path.exists(rule_dir):
                continue
            for root, _, files in os.walk(rule_dir):
                for file in files:
                    if file.endswith((".yml", ".yaml")):
                        rule_path = os.path.join(root, file)
                        try:
                            with open(rule_path, 'r', encoding='utf-8') as f:
                                rule_content = yaml.safe_load(f)
                                if rule_content and rule_content.get('detection'):
                                    rules.append(rule_content)
                        except Exception:
                            pass
        return rules

    def analyze_log_entry(self, log_entry):
        matches = []
        flat_log = flatten_dict(log_entry)
        for rule in self.rules:
            try:
                if self._check_rule_match(rule, flat_log):
                    matches.append(rule)
            except Exception:
                pass
        return matches

    def _check_rule_match(self, rule, flat_log):
        detection = rule.get('detection', {})
        condition_str = detection.get('condition')
        if not condition_str:
            return False
        
        selection_results = {}
        for key, value in detection.items():
            if key != 'condition':
                selection_results[key] = self._evaluate_selection(value, flat_log)

        return self._evaluate_condition(condition_str, selection_results)

    def _evaluate_condition(self, condition_str, results):
        def replacer(match):
            aggregator = match.group(1)
            pattern = match.group(2).replace('*', '.*')
            
            matching_keys = [k for k in results if re.fullmatch(pattern, k)]
            
            if not matching_keys:
                return 'False'

            func = 'any' if aggregator in ('1', 'any') else 'all'
            keys_for_expression = ", ".join([f"results['{key}']" for key in matching_keys])
            return f"{func}([{keys_for_expression}])"

        processed_condition = re.sub(r'\b(1|all)\s+of\s+([a-zA-Z0-9_*]+)\b', replacer, condition_str)

        for key in sorted(results.keys(), key=len, reverse=True):
            processed_condition = re.sub(r'\b' + re.escape(key) + r'\b', f"results['{key}']", processed_condition)

        try:
            return eval(processed_condition, {"__builtins__": {}, "any": any, "all": all}, {'results': results})
        except Exception:
            return False

    def _evaluate_selection(self, selection, flat_log):
        if isinstance(selection, dict):
            return all(self._match_kv(k, v, flat_log) for k, v in selection.items())
        elif isinstance(selection, list):
            return any(self._evaluate_selection(item, flat_log) for item in selection)
        return False

    def _match_kv(self, key, value, flat_log):
        winlog_field_map = {
            'image': 'winlog.event_data.newprocessname',
            'commandline': 'winlog.event_data.commandline',
            'parentimage': 'winlog.event_data.parentprocessname',
            'processid': 'winlog.event_data.newprocessid',
            'parentprocessid': 'winlog.event_data.creatorprocessid'
        }
        
        modifier = 'contains'
        if '|' in key:
            key, *modifiers = key.split('|')
            modifier = modifiers[0] if modifiers else 'contains'

        lookup_key = key.lower()

        log_key_to_use = winlog_field_map.get(lookup_key, lookup_key)
        log_val = flat_log.get(log_key_to_use)
        
        if log_val is None and not log_key_to_use.startswith('winlog.'):
             log_val = flat_log.get('winlog.' + log_key_to_use)

        # --- ▼ここから修正 (最終ロジック) ---
        if log_val is None:
            # lookup_keyが'commandline'の場合、imageの値で代用してチェックを試みる
            if lookup_key == 'commandline':
                image_key_in_map = winlog_field_map.get('image', 'image')
                image_val = flat_log.get(image_key_in_map)
                if image_val is None:
                    return False
                log_val = image_val
            else:
                return False
        # --- ▲ここまで修正 ---

        values_to_check = value if isinstance(value, list) else [value]
        log_values = log_val if isinstance(log_val, list) else [log_val]

        for v_check in values_to_check:
            for v_log in log_values:
                v_check_str = str(v_check).lower()
                v_log_str = str(v_log).lower()
                
                if modifier == 'contains' and v_check_str in v_log_str: return True
                if modifier == 'startswith' and v_log_str.startswith(v_check_str): return True
                if modifier == 'endswith' and v_log_str.endswith(v_check_str): return True
                if modifier == 're' and re.search(v_check_str, v_log_str): return True
        return False