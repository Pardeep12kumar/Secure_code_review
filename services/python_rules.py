import re


class PythonRules:

    def __init__(self, code):

        self.code = code

        self.results = []

    def add_result(
        self,
        line,
        title,
        message,
        severity,
        recommendation,
        cwe,
        owasp
    ):

        self.results.append({

            "line": line,

            "title": title,

            "message": message,

            "severity": severity,

            "recommendation": recommendation,

            "cwe": cwe,

            "owasp": owasp

        })

    def check_eval(self):

        for number, line in enumerate(self.code, start=1):

            if "eval(" in line:

                self.add_result(

                    line=number,

                    title="Use of eval()",

                    message="eval() executes arbitrary Python code.",

                    severity="High",

                    recommendation="Avoid eval(). Use safer alternatives.",

                    cwe="CWE-95",

                    owasp="A03:2021 Injection"

                )

    def check_exec(self):

        for number, line in enumerate(self.code, start=1):

            if "exec(" in line:

                self.add_result(

                    line=number,

                    title="Use of exec()",

                    message="exec() executes arbitrary Python code.",

                    severity="High",

                    recommendation="Remove exec() whenever possible.",

                    cwe="CWE-95",

                    owasp="A03:2021 Injection"

                )

    def check_pickle(self):

        for number, line in enumerate(self.code, start=1):

            if "pickle.loads(" in line:

                self.add_result(

                    line=number,

                    title="Unsafe Pickle Deserialization",

                    message="pickle.loads() may execute malicious code.",

                    severity="High",

                    recommendation="Use JSON instead of pickle when possible.",

                    cwe="CWE-502",

                    owasp="A08:2021 Software and Data Integrity Failures"

                )

    def check_shell_true(self):

        for number, line in enumerate(self.code, start=1):

            if "shell=True" in line:

                self.add_result(

                    line=number,

                    title="shell=True Detected",

                    message="shell=True may allow command injection.",

                    severity="High",

                    recommendation="Avoid shell=True and pass arguments as a list.",

                    cwe="CWE-78",

                    owasp="A03:2021 Injection"

                )

    def check_passwords(self):

        pattern = re.compile(
            r'(password|passwd)\s*=\s*["\'].*["\']',
            re.IGNORECASE
        )

        for number, line in enumerate(self.code, start=1):

            if pattern.search(line):

                self.add_result(

                    line=number,

                    title="Hardcoded Password",

                    message="Hardcoded passwords are insecure.",

                    severity="Medium",

                    recommendation="Store passwords securely using environment variables or a secrets manager.",

                    cwe="CWE-798",

                    owasp="A07:2021 Identification and Authentication Failures"

                )

    def check_api_keys(self):

        pattern = re.compile(

            r'(api_key|apikey|secret|token)\s*=\s*["\'].*["\']',

            re.IGNORECASE

        )

        for number, line in enumerate(self.code, start=1):

            if pattern.search(line):

                self.add_result(

                    line=number,

                    title="Hardcoded Secret",

                    message="A secret or API key appears to be hardcoded.",

                    severity="Medium",

                    recommendation="Store secrets in environment variables or a secure vault.",

                    cwe="CWE-798",

                    owasp="A02:2021 Cryptographic Failures"

                )

    def run(self):

        self.check_eval()

        self.check_exec()

        self.check_pickle()

        self.check_shell_true()

        self.check_passwords()

        self.check_api_keys()

        return self.results
