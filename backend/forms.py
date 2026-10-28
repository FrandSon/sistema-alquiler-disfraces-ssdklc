import re
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SelectField, DecimalField, DateField
from wtforms.validators import (
    DataRequired,
    Length,
    Regexp,
    NumberRange,
    AnyOf,
    ValidationError,
    Optional,
)


def sanitizar_cadena(valor: str) -> str:
    """Filtro de limpieza que remueve etiquetas HTML/scripts y espacios extremos (RS-07, RS-09)."""
    if not isinstance(valor, str):
        return ""
    limpio = valor.strip()
    # Erradicar caracteres de apertura/cierre de etiquetas HTML antes de procesar
    return re.sub(r"[<>]", "", limpio)


class LoginForm(FlaskForm):
    """Formulario de autenticación interna (RF-01)."""

    username = StringField(
        "Nombre de Usuario",
        filters=[sanitizar_cadena],
        validators=[
            DataRequired(message="El usuario es obligatorio."),
            Length(min=4, max=30),
            Regexp(r"^[a-zA-Z0-9_]{4,30}$", message="Formato de usuario inválido."),
        ],
    )
    password = PasswordField(
        "Contraseña",
        validators=[
            DataRequired(message="La contraseña es obligatoria."),
            Length(min=8, max=128),
        ],
    )


class RegistrarDisfrazForm(FlaskForm):
    """Validación por listas blancas para alta de inventario (RF-03, RS-07)."""

    sku = StringField(
        "Código SKU",
        filters=[lambda x: sanitizar_cadena(x).upper() if x else ""],
        validators=[
            DataRequired(),
            Regexp(
                r"^[A-Z0-9\-]{3,20}$",
                message="Código SKU inválido. Use solo mayúsculas, números y guiones (3-20 caracteres).",
            ),
        ],
    )
    nombre = StringField(
        "Nombre del Disfraz",
        filters=[sanitizar_cadena],
        validators=[DataRequired(), Length(min=2, max=80)],
    )
    categoria = StringField(
        "Categoría",
        filters=[sanitizar_cadena],
        validators=[DataRequired(), Length(min=2, max=40)],
    )
    talla = SelectField(
        "Talla Oficial",
        choices=[
            ("XS", "XS"),
            ("S", "S"),
            ("M", "M"),
            ("L", "L"),
            ("XL", "XL"),
            ("Unica", "Única"),
        ],
        validators=[DataRequired(), AnyOf(["XS", "S", "M", "L", "XL", "Unica"])],
    )
    piezas = StringField(
        "Detalle de Piezas Incluidas",
        filters=[sanitizar_cadena],
        validators=[DataRequired(), Length(min=3, max=150)],
    )
    valor_alquiler = DecimalField(
        "Valor de Alquiler",
        places=2,
        validators=[
            DataRequired(message="Ingrese un valor de alquiler numérico válido."),
            NumberRange(
                min=0.01,
                max=10000.00,
                message="El alquiler debe ser positivo (> $0.00).",
            ),
        ],
    )
    monto_garantia = DecimalField(
        "Monto de Garantía",
        places=2,
        validators=[
            DataRequired(message="Ingrese un monto de garantía válido."),
            NumberRange(
                min=0.00,
                max=10000.00,
                message="La garantía no puede ser un monto negativo.",
            ),
        ],
    )


class EmitirTicketForm(FlaskForm):
    """Validación sintáctica y semántica para emisión de tickets de alquiler (RF-05, RS-07)."""

    disfraz_id = StringField(
        "ID del Disfraz",
        filters=[sanitizar_cadena],
        validators=[DataRequired(), Length(min=36, max=36)],
    )
    cliente_nombre = StringField(
        "Nombre Completo del Cliente",
        filters=[sanitizar_cadena],
        validators=[DataRequired(), Length(min=3, max=80)],
    )
    cliente_dni = StringField(
        "Cédula / DNI",
        filters=[sanitizar_cadena],
        validators=[
            DataRequired(),
            Regexp(
                r"^[0-9]{8,13}$",
                message="Cédula/DNI inválido. Debe contener de 8 a 13 dígitos numéricos.",
            ),
        ],
    )
    cliente_telefono = StringField(
        "Teléfono de Contacto",
        filters=[sanitizar_cadena],
        validators=[
            DataRequired(),
            Regexp(
                r"^[0-9\+\-\s]{7,15}$",
                message="Formato de teléfono inválido (7 a 15 dígitos).",
            ),
        ],
    )
    deposito_garantia = DecimalField(
        "Depósito de Garantía",
        places=2,
        validators=[
            DataRequired(message="El depósito de garantía es obligatorio."),
            NumberRange(
                min=0.00,
                max=10000.00,
                message="El depósito de garantía no puede ser negativo.",
            ),
        ],
    )
    fecha_salida = DateField(
        "Fecha de Salida",
        format="%Y-%m-%d",
        validators=[DataRequired(message="Formato de fecha de salida inválido.")],
    )
    fecha_limite_retorno = DateField(
        "Fecha Límite de Retorno",
        format="%Y-%m-%d",
        validators=[
            DataRequired(message="Formato de fecha límite de retorno inválido.")
        ],
    )
    estado_entrega_piezas = StringField(
        "Estado de Entrega de las Piezas",
        filters=[sanitizar_cadena],
        validators=[DataRequired(), Length(min=3, max=150)],
    )

    def validate_fecha_limite_retorno(self, field):
        """Regla de coherencia semántica: fecha_limite_retorno >= fecha_salida (RS-07)."""
        if self.fecha_salida.data and field.data:
            if field.data < self.fecha_salida.data:
                raise ValidationError(
                    "Error semántico (RS-07): La fecha límite de retorno debe ser igual o posterior a la fecha de salida."
                )


class DevolverTicketForm(FlaskForm):
    """Validación para liquidación de devoluciones e incidencias (RF-06, RS-07, RS-09)."""

    tipo_incidencia = SelectField(
        "Resultado de Inspección Física",
        choices=[
            ("Ninguna", "Sin daños ni faltantes"),
            ("Mancha Grave", "Mancha Grave"),
            ("Dano Parcial", "Daño Parcial"),
            ("Perdida o Dano Total", "Pérdida o Daño Total"),
        ],
        validators=[
            DataRequired(),
            AnyOf(["Ninguna", "Mancha Grave", "Dano Parcial", "Perdida o Dano Total"]),
        ],
    )
    nuevo_estado_disfraz = SelectField(
        "Siguiente Estado del Disfraz",
        choices=[
            ("En lavanderia", "En lavandería"),
            ("Disponible", "Disponible"),
            ("Danado", "Dañado"),
        ],
        validators=[DataRequired(), AnyOf(["En lavanderia", "Disponible", "Danado"])],
    )
    observaciones = StringField(
        "Observaciones",
        filters=[sanitizar_cadena],
        validators=[Optional(), Length(max=200)],
    )


class CrearUsuarioForm(FlaskForm):
    """Validación estricta de creación de cuentas y política de contraseñas (RF-02, RS-02, RS-10)."""

    username = StringField(
        "Usuario",
        filters=[sanitizar_cadena],
        validators=[
            DataRequired(),
            Regexp(
                r"^[a-zA-Z0-9_]{4,30}$",
                message="El nombre de usuario solo permite letras, números y guion bajo (4 a 30 caracteres).",
            ),
        ],
    )
    rol = SelectField(
        "Rol de Acceso",
        choices=[("Empleado", "Empleado"), ("Administrador", "Administrador")],
        validators=[DataRequired(), AnyOf(["Empleado", "Administrador"])],
    )
    password = PasswordField(
        "Contraseña Robusta", validators=[DataRequired(), Length(min=10, max=128)]
    )

    def validate_password(self, field):
        """Cumplimiento estricto de RS-02: Mín. 10 caract., Mayús, Minús, Dígito, Especial y != username."""
        pwd = field.data or ""
        uname = self.username.data or ""

        if uname and uname.lower() in pwd.lower():
            raise ValidationError(
                "La contraseña no puede contener el nombre de usuario (RS-02)."
            )
        if not re.search(r"[A-Z]", pwd):
            raise ValidationError(
                "La contraseña debe incluir al menos una letra mayúscula (RS-02)."
            )
        if not re.search(r"[a-z]", pwd):
            raise ValidationError(
                "La contraseña debe incluir al menos una letra minúscula (RS-02)."
            )
        if not re.search(r"[0-9]", pwd):
            raise ValidationError(
                "La contraseña debe incluir al menos un dígito numérico (RS-02)."
            )
        if not re.search(r"[\W_]", pwd):
            raise ValidationError(
                "La contraseña debe incluir al menos un carácter especial (RS-02)."
            )
