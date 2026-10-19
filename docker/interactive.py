"""Interactive Docker launcher; delegates scans to the unmodified CLI."""
import subprocess
import sys
from pathlib import Path


def main():
    if len(sys.argv) > 1:
        return subprocess.call(['malwhunter', *sys.argv[1:]])

    print('\nMalwHunter — interactive scanner')
    print('Enter an exact package, e.g. left-pad@1.3.0.')
    print('Enter /project to scan the mounted project, or q to quit.')
    print('Mode: static Recon; AI and detonation are off.\n', flush=True)
    while True:
        try:
            target = input('Scan target > ').strip()
            if target.lower() in {'q', 'quit', 'exit'}:
                return 0
            if not target:
                continue
            if Path(target).is_dir():
                args = ['scan', target]
            elif target.startswith(('/', './', '../')):
                print('Project folder not found. Set PROJECT_DIR before starting to mount your project at /project.\n')
                continue
            else:
                args = ['inspect', target]
            result = subprocess.run(['malwhunter', *args, '--no-ai', '--no-detonate', '--format', 'terminal'], check=False)
            print(f'\nScan finished (exit code {result.returncode}). Enter another target or q to quit.\n', flush=True)
        except EOFError:
            print('\nInput closed. Goodbye.', flush=True)
            return 0
        except KeyboardInterrupt:
            print('\nCancelled. Enter another target or q to quit.\n', flush=True)


if __name__ == '__main__':
    raise SystemExit(main())
