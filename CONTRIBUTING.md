# Guía de Contribución 🤝

¡Gracias por tu interés en contribuir a **Cybersecurity Toolkit**!

---

## 📜 Código de Conducta
Este proyecto sigue altos estándares éticos. Todas las herramientas y contribuciones deben estar diseñadas para fines educativos, investigación académica y auditoría defensiva autorizada.

---

## 🛠️ Cómo Contribuir

1. **Haz un Fork del Repositorio**:
   Crea tu copia en GitHub.

2. **Crea una Rama Descriptiva**:
   ```bash
   git checkout -b feature/nueva-herramienta
   ```

3. **Escribe Pruebas Unitarias**:
   Cualquier módulo nuevo debe incluir sus correspondientes tests en la carpeta `tests/` y mantener una cobertura superior al 80%.

4. **Verifica la Calidad del Código**:
   ```bash
   python -m unittest discover -s tests
   bandit -r tools/
   ```

5. **Envía un Pull Request (PR)**:
   Explica claramente qué mejoras o correcciones introduce tu cambio.
