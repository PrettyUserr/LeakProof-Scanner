import sys
import click
from detectors.scanner import scan_directory
from reporters.console import print_report, get_exit_code

@click.command()
@click.option('--path', default='.', help='File or directory to scan')
def main(path):
    findings = scan_directory(path)
    print_report(findings, path)
    exit_code = get_exit_code(findings)
    sys.exit(exit_code)

if __name__ == "__main__":
    main()