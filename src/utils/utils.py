from os import getcwd, path


def read_file(filepath):
    with open(path.join(getcwd(), *filepath), "r", encoding='utf-8') as f:
        text = f.read()
        if text:
            return text
        else:
            raise ValueError(f"File {filepath[-1]} is empty.")


def write_file(text, filepath):
    with open(path.join(getcwd(), *filepath), "w") as f:
        # Clearing file
        open(path.join(getcwd(), *filepath), "w").close()
        f.write(text)
