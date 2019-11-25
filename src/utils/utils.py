from os import path, getcwd
from re import sub


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


def normalize_text(text):
    '''Returns lowercase, stripped text with spaces.'''
    return sub(r'[^a-zA-Z ]+', '', text).strip().lower()
