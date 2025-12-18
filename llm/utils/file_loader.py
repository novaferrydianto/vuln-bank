
import os

def read_file(path):
    path=os.path.abspath(path)
    with open(path) as f:
        return f.read()
