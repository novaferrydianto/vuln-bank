
import argparse, os, json
from llm.provider import ModelProvider
from llm.analyzers import BacAgent, SQLiAgent, SSRFAgent, SSTIAgent, TraversalAgent
from llm.utils.scanner import scan_files
from llm.utils.file_loader import read_file

def run(scan_path, output):
    provider = ModelProvider(
        os.getenv("AI_API_ENDPOINT"),
        os.getenv("AI_API_KEY")
    )

    agents = [
        BacAgent(), SQLiAgent(),
        SSRFAgent(), SSTIAgent(),
        TraversalAgent()
    ]

    files = scan_files(scan_path)
    results = []

    for f in files:
        content = read_file(f)
        for agent in agents:
            r = agent.analyze(provider, content)
            results.append({"file": f, "agent": agent.name, "result": r})

    with open(output, "w") as fp:
        json.dump(results, fp, indent=2)

if __name__ == "__main__":
    p=argparse.ArgumentParser()
    p.add_argument("--scan-path",required=True)
    p.add_argument("--output",required=True)
    args=p.parse_args()
    run(args.scan_path,args.output)
