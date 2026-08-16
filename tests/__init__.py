"""
Test Suite for Cybersecurity Toolkit
"""

import sys
import os

# Asegurar que el directorio raíz del toolkit esté en el PATH para las pruebas
toolkit_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if toolkit_root not in sys.path:
    sys.path.insert(0, toolkit_root)
