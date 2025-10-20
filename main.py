#!/usr/bin/env python3
"""
LogShield AI - Intelligent Log Analysis & Threat Detection
Main CLI interface for log analysis and real-time monitoring.
"""

import sys
import os
import argparse
from pathlib import Path

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def setup_command(args):
    """Run the setup process."""
    print("🔧 LogShield AI Setup")
    print("=" * 50)
    
    # Import and run the setup script
    try:
        from setup import main as setup_main
        success = setup_main()
        if success:
            print("\n✅ Setup completed successfully!")
            print("\n📝 Next steps:")
            print("1. Edit .env file and add your Groq API key")
            print("2. Run: python main.py analyze /path/to/your/logfile.log")
        else:
            print("\n❌ Setup failed. Please check the errors above.")
            sys.exit(1)
    except ImportError as e:
        print(f"❌ Setup script not found: {e}")
        sys.exit(1)

def analyze_command(args):
    """Run log analysis mode."""
    if not args.logfile:
        print("❌ Error: Please specify a log file to analyze")
        print("Usage: python logshield_ai.py analyze /path/to/logfile.log")
        sys.exit(1)
    
    logfile_path = Path(args.logfile)
    if not logfile_path.exists():
        print(f"❌ Error: Log file not found: {logfile_path}")
        sys.exit(1)
    
    print("🔍 LogShield AI Analysis Mode")
    print("=" * 50)
    print(f"📁 Analyzing log file: {logfile_path}")
    print("=" * 50)
    
    # Import and run analysis
    try:
        from cli.analyze import run_analysis
        success = run_analysis(logfile_path, args)
        if success:
            print("\n✅ Analysis completed successfully!")
        else:
            print("\n❌ Analysis failed. Please check the errors above.")
            sys.exit(1)
    except ImportError as e:
        print(f"❌ Analysis module not found: {e}")
        print("Please ensure all dependencies are installed.")
        sys.exit(1)

def monitor_command(args):
    """Run real-time monitoring mode."""
    print("👁️ LogShield AI Real-Time Monitoring")
    print("=" * 50)
    print("This mode continuously monitors Elasticsearch for new logs")
    print("and processes them in real-time.")
    print("=" * 50)
    
    # Import and run monitoring
    try:
        from cli.monitor import run_monitoring
        run_monitoring(args)
    except ImportError as e:
        print(f"❌ Monitor module not found: {e}")
        print("Please ensure all dependencies are installed.")
        sys.exit(1)

def clear_command(args):
    """Clear all data from Elasticsearch."""
    print("🧹 AION Elasticsearch Data Cleanup")
    print("=" * 50)
    print("This will clear ALL logs and incidents from Elasticsearch.")
    print("Use this for testing purposes only!")
    print("=" * 50)
    
    # Import and run cleanup
    try:
        from clear_elasticsearch import main as clear_main
        # Override sys.argv to pass force flag if needed
        import sys
        original_argv = sys.argv.copy()
        if args.force:
            sys.argv = ['clear_elasticsearch.py', '--force']
        else:
            sys.argv = ['clear_elasticsearch.py']
        
        clear_main()
        
        # Restore original argv
        sys.argv = original_argv
        
    except ImportError as e:
        print(f"❌ Cleanup script not found: {e}")
        print("Please ensure clear_elasticsearch.py is in the project root.")
        sys.exit(1)

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(
        description="AION - Autonomous Blue Team Security Platform",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py setup                                    # Initial setup
  python main.py analyze /var/log/apache2/access.log     # Analyze log file
  python main.py analyze /var/log/auth.log --keep-data   # Keep data in ES
  python main.py monitor                                  # Real-time monitoring
  python main.py monitor --interval 60                   # Custom interval
  python main.py clear                                    # Clear all ES data
  python main.py clear --force                           # Clear without confirmation

For more information, visit: https://github.com/your-repo/aion
        """
    )
    
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Setup command
    setup_parser = subparsers.add_parser('setup', help='Run initial setup')
    setup_parser.set_defaults(func=setup_command)
    
    # Analyze command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze log files for threats')
    analyze_parser.add_argument('logfile', help='Path to log file to analyze')
    analyze_parser.add_argument('--keep-data', action='store_true', 
                              help='Keep processed data in Elasticsearch (default: True)')
    analyze_parser.add_argument('--cleanup', action='store_true',
                              help='Remove processed data from Elasticsearch after analysis')
    analyze_parser.add_argument('--output', '-o', 
                              help='Output directory for reports (default: current directory)')
    analyze_parser.add_argument('--format', choices=['markdown', 'json', 'html'], 
                              default='markdown', help='Report format (default: markdown)')
    analyze_parser.set_defaults(func=analyze_command)
    
    # Monitor command
    monitor_parser = subparsers.add_parser('monitor', help='Run real-time monitoring')
    monitor_parser.add_argument('--interval', '-i', type=int, default=30,
                              help='Processing interval in seconds (default: 30)')
    monitor_parser.add_argument('--batch-size', '-b', type=int, default=1000,
                              help='Batch size for processing (default: 1000)')
    monitor_parser.set_defaults(func=monitor_command)
    
    # Clear command
    clear_parser = subparsers.add_parser('clear', help='Clear all data from Elasticsearch')
    clear_parser.add_argument('--force', action='store_true',
                              help='Skip confirmation prompt')
    clear_parser.set_defaults(func=clear_command)
    
    # Parse arguments
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Run the selected command
    try:
        args.func(args)
    except KeyboardInterrupt:
        print("\n🛑 Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
