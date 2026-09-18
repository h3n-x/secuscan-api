# Registra todos los modelos en Base.metadata con un solo import ("import app.models"),
# en vez de tener que saber de memoria cuáles archivos individuales tocar. app.main ya logra
# esto indirectamente porque cada router importa User para el type hint de get_current_user,
# pero cualquier script suelto (o el env.py de Alembic en el Paso 10) debe pasar por acá.
from app.models.domain_verification import DomainVerification
from app.models.scan import Scan, ScanModuleResult
from app.models.user import User

__all__ = ["User", "DomainVerification", "Scan", "ScanModuleResult"]
