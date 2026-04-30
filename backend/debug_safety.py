import subprocess
import sys
import os

def debug_safety():
    python_executable = sys.executable
    print(f"Python: {python_executable}")
    
    test_file = "demo_vulnerable.txt"
    
    if not os.path.exists(test_file):
        print(f"Error: {test_file} no existe")
        return
    
    print(f"\nEjecutando: {python_executable} -m safety check -r {test_file} --json")
    print("=" * 60)
    
    result = subprocess.run(
        [python_executable, '-m', 'safety', 'check', '-r', test_file, '--json'],
        capture_output=True, text=True
    )
    
    print(f"Return code: {result.returncode}")
    print(f"\nSTDOUT:")
    print(result.stdout)
    print(f"\nSTDERR:")
    print(result.stderr)
    
    print("\n" + "=" * 60)
    print("Analizando salida:")
    print("=" * 60)
    
    if result.stdout:
        lines = result.stdout.split('\n')
        print(f"Total lineas: {len(lines)}")
        
        for i, line in enumerate(lines[:20]):
            print(f"{i}: {line[:100]}")
        
        if result.stdout.strip():
            first_char = result.stdout.strip()[0]
            print(f"\nPrimer caracter: '{first_char}'")
            
            if first_char == '{':
                print("Parece JSON válido")
            else:
                print("NO comienza con {{ - puede haber texto antes del JSON")
                
                import re
                json_match = re.search(r'\{.*\}', result.stdout, re.DOTALL)
                if json_match:
                    print("Se encontró JSON en el texto")
                    print(f"JSON encontrado: {json_match.group()[:200]}")
                else:
                    print("No se encontró JSON en la salida")

if __name__ == '__main__':
    debug_safety()