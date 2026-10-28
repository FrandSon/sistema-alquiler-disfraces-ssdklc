import uuid
from datetime import datetime, timezone
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import CheckConstraint

db = SQLAlchemy()


def generar_uuid() -> str:
    """Genera un identificador único universal UUID v4 no predecible (RS-06)."""
    return str(uuid.uuid4())


class Usuario(db.Model):
    """Modelo para personal interno con RBAC estricto (RF-01, RF-02, ACT-02)."""

    __tablename__ = "usuarios"

    id = db.Column(db.String(36), primary_key=True, default=generar_uuid)
    username = db.Column(db.String(30), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    rol = db.Column(db.String(20), nullable=False, default="Empleado")
    activo = db.Column(db.Boolean, nullable=False, default=True)

    __table_args__ = (
        CheckConstraint("rol IN ('Administrador', 'Empleado')", name="chk_usuario_rol"),
    )


class Disfraz(db.Model):
    """Modelo de catálogo e inventario de disfraces (RF-03, RF-04, ACT-03)."""

    __tablename__ = "disfraces"

    id = db.Column(db.String(36), primary_key=True, default=generar_uuid)
    sku = db.Column(db.String(20), unique=True, nullable=False, index=True)
    nombre = db.Column(db.String(80), nullable=False)
    categoria = db.Column(db.String(40), nullable=False, index=True)
    talla = db.Column(db.String(10), nullable=False)
    piezas = db.Column(db.String(150), nullable=False)
    valor_alquiler = db.Column(db.Numeric(10, 2), nullable=False)
    monto_garantia = db.Column(db.Numeric(10, 2), nullable=False)
    estado = db.Column(db.String(20), nullable=False, default="Disponible", index=True)

    tickets = db.relationship("Ticket", back_populates="disfraz", lazy="joined")

    __table_args__ = (
        CheckConstraint(
            "talla IN ('XS', 'S', 'M', 'L', 'XL', 'Unica')", name="chk_disfraz_talla"
        ),
        CheckConstraint("valor_alquiler > 0", name="chk_valor_alquiler_positivo"),
        CheckConstraint("monto_garantia >= 0", name="chk_monto_garantia_no_negativo"),
        CheckConstraint(
            "estado IN ('Disponible', 'Alquilado', 'En lavanderia', 'Danado', 'Baja')",
            name="chk_disfraz_estado",
        ),
    )


class Ticket(db.Model):
    """Modelo de transacciones de alquiler, devoluciones y garantías (RF-05, RF-06, ACT-01, ACT-04)."""

    __tablename__ = "tickets"

    id = db.Column(db.String(36), primary_key=True, default=generar_uuid)
    disfraz_id = db.Column(
        db.String(36),
        db.ForeignKey("disfraces.id", ondelete="RESTRICT"),
        nullable=False,
    )
    cliente_nombre = db.Column(db.String(80), nullable=False)
    cliente_dni = db.Column(db.String(13), nullable=False)
    cliente_telefono = db.Column(db.String(15), nullable=False)
    estado_entrega_piezas = db.Column(db.String(150), nullable=False)
    fecha_salida = db.Column(db.Date, nullable=False)
    fecha_limite_retorno = db.Column(db.Date, nullable=False)
    fecha_devolucion_real = db.Column(db.Date, nullable=True)
    deposito_garantia = db.Column(db.Numeric(10, 2), nullable=False)
    retencion_garantia = db.Column(db.Numeric(10, 2), nullable=False, default=0.00)
    observaciones_incidencia = db.Column(db.String(200), nullable=True)
    estado_ticket = db.Column(
        db.String(20), nullable=False, default="Activo", index=True
    )
    emitido_por = db.Column(db.String(30), nullable=False)

    disfraz = db.relationship("Disfraz", back_populates="tickets")

    __table_args__ = (
        CheckConstraint("deposito_garantia >= 0", name="chk_deposito_no_negativo"),
        CheckConstraint("retencion_garantia >= 0", name="chk_retencion_no_negativa"),
        CheckConstraint(
            "fecha_limite_retorno >= fecha_salida", name="chk_coherencia_fechas"
        ),
        CheckConstraint(
            "estado_ticket IN ('Activo', 'Cerrado', 'Con Incidencia')",
            name="chk_estado_ticket",
        ),
    )

    # Propiedades puente para compatibilidad directa con las plantillas Jinja2 (t.sku y t.disfraz_nombre)
    @property
    def sku(self) -> str:
        return self.disfraz.sku if self.disfraz else "N/A"

    @property
    def disfraz_nombre(self) -> str:
        return self.disfraz.nombre if self.disfraz else "Desconocido"


class LogAuditoria(db.Model):
    """Bitácora inmutable de eventos de seguridad y operaciones críticas (RF-08, RS-14)."""

    __tablename__ = "logs_auditoria"

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    timestamp = db.Column(
        db.String(25),
        nullable=False,
        default=lambda: datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
    )
    usuario = db.Column(db.String(30), nullable=False, index=True)
    accion = db.Column(db.String(50), nullable=False)
    detalle = db.Column(db.String(255), nullable=False)
    ip_origen = db.Column(db.String(45), nullable=False)
