"""Producción y CI usan Python 3.11 (runtime.txt). En local se puede probar con
una versión más nueva, que acepta f-strings que 3.11 rechaza (PEP 701). Este
test las detecta para que no vuelvan a tumbar el despliegue."""
import io
import pathlib
import sys
import tokenize

import pytest

RAIZ = pathlib.Path(__file__).resolve().parent.parent
FICHEROS = ["server.py", "reconbase_engine.py", "models.py"]


def _problemas_pep701(fuente):
    problemas, comillas, llaves = [], [], []
    for tok in tokenize.generate_tokens(io.StringIO(fuente).readline):
        if tok.type == tokenize.FSTRING_START:
            comillas.append(tok.string.lstrip("rRbBfFuU"))
            llaves.append(0)
            continue
        if tok.type == tokenize.FSTRING_END:
            comillas.pop()
            llaves.pop()
            continue
        if not comillas:
            continue
        if tok.type == tokenize.OP and tok.string in "{}":
            llaves[-1] += 1 if tok.string == "{" else -1
        if llaves[-1] <= 0 or tok.type == tokenize.FSTRING_MIDDLE:
            continue
        if tok.type == tokenize.COMMENT:
            problemas.append((tok.start[0], "comentario"))
        elif tok.type == tokenize.STRING:
            cuerpo = tok.string.lstrip("rRbBuU")
            if "\\" in tok.string:
                problemas.append((tok.start[0], "barra invertida"))
            elif cuerpo.startswith(comillas[-1]):
                problemas.append((tok.start[0], "mismas comillas"))
    return problemas


@pytest.mark.skipif(sys.version_info < (3, 12), reason="En 3.11 el propio import ya falla si hay f-strings incompatibles")
@pytest.mark.parametrize("fichero", FICHEROS)
def test_fstrings_compatibles_con_python_311(fichero):
    fuente = (RAIZ / fichero).read_text(encoding="utf-8")
    assert _problemas_pep701(fuente) == []


@pytest.mark.skipif(sys.version_info < (3, 12), reason="Solo tiene sentido con el tokenizador de 3.12+")
def test_el_detector_encuentra_el_fallo_original():
    roto = 'x = f"{\'<p style=\\"a\\">\' + y}"\n'
    assert _problemas_pep701(roto)
