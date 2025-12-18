
import os

def sanitize_path(p): return os.path.normpath(p)
def safe_join(root,p): return os.path.join(root,sanitize_path(p))
