import re


class JavaRules:

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

    def check_runtime_exec(self):

        for number, line in enumerate(self.code, start=1):

            if "Runtime.getRuntime().exec(" in line:

                self.add_result(

                    line=number,

                    title="Runtime.exec() Usage",

                    message="Runtime.exec() may lead to command injection.",

                    severity="High",

                    recommendation="Avoid Runtime.exec() with user input. Prefer ProcessBuilder with validated arguments.",

                    cwe="CWE-78",

                    owasp="A03:2021 Injection"

                )

    def check_passwords(self):

        pattern = re.compile(
            r'(password|passwd)\s*=.*".*"',
            re.IGNORECASE
        )

        for number, line in enumerate(self.code, start=1):

            if pattern.search(line):

                self.add_result(

                    line=number,

                    title="Hardcoded Password",

                    message="Hardcoded password detected.",

                    severity="Medium",

                    recommendation="Store passwords securely outside the source code.",

                    cwe="CWE-798",

                    owasp="A07:2021 Identification and Authentication Failures"

                )

    def check_secrets(self):

        pattern = re.compile(
            r'(apikey|api_key|secret|token)\s*=.*".*"',
            re.IGNORECASE
        )

        for number, line in enumerate(self.code, start=1):

            if pattern.search(line):

                self.add_result(

                    line=number,

                    title="Hardcoded Secret",

                    message="Hardcoded secret or API key detected.",

                    severity="Medium",

                    recommendation="Store secrets in environment variables or a secure secret manager.",

                    cwe="CWE-798",

                    owasp="A02:2021 Cryptographic Failures"

                )

    def check_sql_injection(self):

        for number, line in enumerate(self.code, start=1):

            if (
                "executeQuery(" in line
                and "+"
                in line
            ):

                self.add_result(

                    line=number,

                    title="Possible SQL Injection",

                    message="SQL query appears to be built using string concatenation.",

                    severity="High",

                    recommendation="Use PreparedStatement with parameterized queries.",

                    cwe="CWE-89",

                    owasp="A03:2021 Injection"

                )

    def check_weak_random(self):

        for number, line in enumerate(self.code, start=1):

            if "new Random(" in line:

                self.add_result(

                    line=number,

                    title="Weak Random Number Generator",

                    message="java.util.Random is not suitable for security-sensitive operations.",

                    severity="Medium",

                    recommendation="Use SecureRandom for cryptographic purposes.",

                    cwe="CWE-338",

                    owasp="A02:2021 Cryptographic Failures"

                )

    def check_weak_hash(self):

        for number, line in enumerate(self.code, start=1):

            if (
                'MessageDigest.getInstance("MD5")' in line
                or 'MessageDigest.getInstance("SHA-1")' in line
            ):

                self.add_result(

                    line=number,

                    title="Weak Cryptographic Hash",

                    message="MD5 or SHA-1 detected.",

                    severity="Medium",

                    recommendation="Use SHA-256 or stronger algorithms.",

                    cwe="CWE-327",

                    owasp="A02:2021 Cryptographic Failures"

                )

    def run(self):

        self.check_runtime_exec()

        self.check_passwords()

        self.check_secrets()

        self.check_sql_injection()

        self.check_weak_random()

        self.check_weak_hash()

        return self.results
