#!/usr/bin/env python3
"""
Demo script for the AION Security Orchestrator.
This script runs the orchestrator in demo mode to process existing logs
and generate a comprehensive security intelligence report.
"""

import sys
import os

# Add the current directory to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from orchestrator import run_demo_mode

def main():
    """Run the AION Security Orchestrator in demo mode."""
    print("🎬 AION Security Orchestrator Demo")
    print("=" * 50)
    print("This demo will:")
    print("1. Connect to Elasticsearch")
    print("2. Fetch existing logs (up to 2000)")
    print("3. Process them through the complete incident workflow")
    print("4. Generate a comprehensive security intelligence report")
    print("5. Store incidents in the backend")
    print("=" * 50)
    
    try:
        # Run the demo mode
        incidents, report_filename = run_demo_mode()
        
        if incidents:
            print(f"\n🎉 Demo completed successfully!")
            print(f"📊 Generated {len(incidents)} incidents")
            print(f"📄 Report saved as: {report_filename}")
            print(f"\n📋 Next steps:")
            print(f"   1. Review the generated report: {report_filename}")
            print(f"   2. Check the incidents in Elasticsearch index: aion-incidents")
            print(f"   3. Run the real-time service: python orchestrator.py --service")
        else:
            print(f"\n⚠️  Demo completed but no incidents were generated.")
            print(f"   This could mean:")
            print(f"   - No logs were found in Elasticsearch")
            print(f"   - All logs were classified as benign")
            print(f"   - No threats were detected")
            
    except KeyboardInterrupt:
        print(f"\n🛑 Demo interrupted by user")
    except Exception as e:
        print(f"\n❌ Demo failed with error: {e}")
        print(f"   Please check your Elasticsearch connection and configuration")

if __name__ == "__main__":
    main()
