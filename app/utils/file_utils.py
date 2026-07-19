import os

def allowed_file(filename, allowed_extensions):
    if "." not in filename:
        return False

    extension = filename.rsplit(".", 1)[1].lower()
    return extension in allowed_extensions


def detect_language(filename):
    extension = os.path.splitext(filename)[1].lower()

    mapping = {
        ".py": "Python",
        ".java": "Java",
        ".c": "C",
        ".cpp": "C++",
        ".js": "JavaScript"
    }

    return mapping.get(extension, "Unknown")
