import os

with open(".env", "r") as fp:
    for line in fp:
        line = line.strip()
        if not line.startswith("#"):
            k, v = line.split("=", 1)
            os.environ[k] = v

#if not os.environ.get("GOOGLE_API_KEY"):
#  os.environ["GOOGLE_API_KEY"] = getpass.getpass("Enter API key for Google Gemini: ")