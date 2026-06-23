import yara
import os
import logging
import concurrent.futures
import asyncio

class YaraEngine:
    """
    Engine for performing static analysis on files using YARA rules.
    It supports both synchronous and asynchronous scanning.
    """
    def __init__(self, rules_dir="rules/yara-rules"):
        """
        Initializes the YaraEngine and loads rules from the specified directory.
        """
        self.rules_dir = rules_dir
        self.rules = None
        self.logger = logging.getLogger(__name__)
        self.load_rules()

    def load_rules(self):
        """
        Compiles YARA rules from the rules directory.
        Attempts to load index.yar first, then falls back to loading files individually with namespaces
        to avoid identifier collisions.
        """
        if not os.path.exists(self.rules_dir):
            self.logger.warning(f"YARA rules directory not found: {self.rules_dir}")
            return

        index_path = os.path.join(self.rules_dir, "index.yar")

        # Try to compile the main index if it exists
        if os.path.exists(index_path):
            try:
                self.rules = yara.compile(filepath=index_path)
                self.logger.info("Successfully loaded YARA rules from index.yar")
                return
            except Exception as e:
                self.logger.error(f"Failed to compile index.yar: {e}")

        # Fallback: Load rules individually to avoid collisions
        self.logger.info("Attempting to load rules individually to avoid collisions...")

        compiled_rules = []
        for root, _, files in os.walk(self.rules_dir):
            for file in files:
                if (file.endswith(".yar") or file.endswith(".yara")) and file != "index.yar":
                    full_path = os.path.join(root, file)
                    try:
                        # Test compile individual file to ensure it's valid
                        yara.compile(filepath=full_path)
                        compiled_rules.append(full_path)
                    except Exception:
                        self.logger.debug(f"Skipping invalid YARA rule file: {full_path}")
                        continue

        # Compile all valid rules using unique namespaces
        rule_files = {}
        for idx, path in enumerate(compiled_rules):
            namespace = f"ns_{idx}"
            rule_files[namespace] = path

        try:
            if rule_files:
                self.rules = yara.compile(filepaths=rule_files)
                self.logger.info(f"Successfully loaded {len(rule_files)} YARA rule files with namespaces.")
            else:
                self.logger.warning("No valid YARA rules found.")
        except Exception as e:
            self.logger.error(f"Bulk YARA compilation with namespaces failed: {e}")
            # Final attempt: load just the first successful one
            if compiled_rules:
                try:
                    self.rules = yara.compile(filepath=compiled_rules[0])
                    self.logger.info(f"Loaded single YARA rule file: {compiled_rules[0]}")
                except Exception:
                    self.logger.error("Failed to load any YARA rules.")

    def scan_file(self, filepath):
        """
        Scans a file on disk using the loaded YARA rules.
        Returns a list of match strings.
        """
        if not self.rules:
            return []
        try:
            matches = self.rules.match(filepath)
            return [str(m) for m in matches]
        except Exception as e:
            self.logger.error(f"Error scanning file {filepath}: {e}")
            return []

    async def scan_file_async(self, filepath):
        """
        Asynchronously scans a file on disk.
        """
        loop = asyncio.get_running_loop()
        with concurrent.futures.ThreadPoolExecutor() as pool:
            return await loop.run_in_executor(pool, self.scan_file, filepath)

    def scan_memory(self, dump_path):
        """
        Scans a memory dump using the loaded YARA rules.
        """
        if not self.rules:
            return []
        try:
            # yara.match works on both files and memory dumps passed as paths
            matches = self.rules.match(dump_path)
            return [str(m) for m in matches]
        except Exception as e:
            self.logger.error(f"Error scanning memory dump {dump_path}: {e}")
            return []
