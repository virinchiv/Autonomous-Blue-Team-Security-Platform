import argparse
from ingestion.parser import LogParser
from ingestion.normalizer import LogNormalizer

def main():
    parser = argparse.ArgumentParser(description="Blue Team Agent MVP")
    parser.add_argument("--input", type=str, required=True, help="Path to raw log file (CSV, JSON, syslog)")
    args = parser.parse_args()

    parser = LogParser()
    raw_logs = parser.load_file(args.input)
    
    normalizer = LogNormalizer()
    normalized_logs = normalizer.normalize(raw_logs)

    print("✅ Logs normalized:")
    for log in normalized_logs[:5]:
        print(log)

if __name__ == "__main__":
    main()