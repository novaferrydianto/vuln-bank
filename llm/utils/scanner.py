
import os

def scan_files(root):
    result=[]
    for base,_,files in os.walk(root):
        for f in files:
            if f.endswith((".py",".js",".yaml",".yml",".tf",".json")):
                result.append(os.path.join(base,f))
    return result
