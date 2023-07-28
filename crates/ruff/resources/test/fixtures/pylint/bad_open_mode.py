def foo(file_path):
    with open(file_path, "lol") as file:  # [bad-open-mode]
        contents = file.read()

def bar(file_path):
    with open(file_path, "r") as file:
        contents = file.read()
