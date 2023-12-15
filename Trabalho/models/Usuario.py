from dataclasses import dataclass
from typing import Optional

@dataclass
class Usuario:
    id: Optional[int] = None
    nome: Optional[str] = None
    email: Optional[str] = None
    senha: Optional[str] = None
    admin: Optional[bool] = False
    token: Optional[str] = None
