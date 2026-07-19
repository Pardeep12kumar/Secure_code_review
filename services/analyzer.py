import os

from services.python_rules import PythonRules
from services.java_rules import JavaRules


class CodeAnalyzer:

    def __init__(self, filepath):

        self.filepath = filepath

        self.language = self.detect_language()

        self.code = self.load_code()

    def detect_language(self):

        extension = os.path.splitext(
            self.filepath
        )[1].lower()

        mapping = {
   	 ".py": "Python",
   	 ".java": "Java",
   	 ".c": "C",
   	 ".cpp": "C++",
   	 ".js": "JavaScript"
	}

        return mapping.get(
            extension,
            "Unknown"
        )

    def load_code(self):

        with open(
            self.filepath,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:

            return file.readlines()

    def analyze(self):

        if self.language == "Python":

            return PythonRules(
                self.code
            ).run()

        elif self.language == "Java":

            return JavaRules(
                self.code
            ).run()

        return []
