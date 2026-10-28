from forms import (
    sanitizar_cadena,
    LoginForm,
    RegistrarDisfrazForm,
    EmitirTicketForm,
    DevolverTicketForm,
    CrearUsuarioForm,
)
from models import db, Usuario, Disfraz, Ticket, LogAuditoria
from config import Config
import os
import sys
from datetime import datetime, date, timedelta
from functools import wraps
import bcrypt
from flask import (
    Flask,
    render_template,
    request,
    redirect,
    url_for,
    session,
    flash,
    abort,
)
from flask_wtf.csrf import CSRFProtect, CSRFError
from sqlalchemy import func
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

# Asegurar que el directorio backend esté en el path de importación (compatible con ejecución directa y Gunicorn)
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)


# Rutas absolutas hacia la carpeta /frontend/ para garantizar 100% de compatibilidad (RNF-01)
FRONTEND_TEMPLATES = os.path.abspath(
    os.path.join(CURRENT_DIR, "..", "frontend", "templates")
)
FRONTEND_STATIC = os.path.abspath(os.path.join(CURRENT_DIR, "..", "frontend", "static"))

app = Flask(__name__, template_folder=FRONTEND_TEMPLATES, static_folder=FRONTEND_STATIC)
app.config.from_object(Config)

# Inicializar ORM SQLAlchemy y Protección Global Anti-CSRF (RS-08, RS-10)
db.init_app(app)
csrf = CSRFProtect(app)

# Diccionario de control en memoria para mitigación de Fuerza Bruta (RS-03)
INTENTOS_FALLIDOS = {}
MAX_INTENTOS_LOGIN = 5
TIEMPO_BLOQUEO_CUENTA = timedelta(minutes=15)

TALLAS_PERMITIDAS = {"XS", "S", "M", "L", "XL", "Unica"}


# ==============================================================================
# 1. AUDITORÍA DE SEGURIDAD E INICIALIZACIÓN DE SEMILLA (RS-01, RS-14)
# ==============================================================================
def registrar_auditoria(usuario: str, accion: str, detalle: str) -> None:
    """Registra eventos críticos de seguridad en PostgreSQL sin almacenar secretos (RS-14)."""
    ip_cliente = (
        request.headers.get("X-Forwarded-For", request.remote_addr) or "127.0.0.1"
    )
    try:
        nuevo_log = LogAuditoria(
            usuario=str(usuario)[:30],
            accion=str(accion)[:50],
            detalle=str(detalle)[:255],
            ip_origen=str(ip_cliente)[:45],
        )
        db.session.add(nuevo_log)
        db.session.commit()
    except SQLAlchemyError:
        db.session.rollback()


def inicializar_datos_semilla() -> None:
    """Crea las tablas en PostgreSQL e inserta usuarios/disfraces iniciales con bcrypt factor 12 (RS-01)."""
    db.create_all()

    # Semilla de cuentas iniciales (Administrador y Empleado de mostrador)
    cuentas_iniciales = [
        ("admin_seguro", "Admin#2026!", "Administrador"),
        ("empleado_mostrador", "Emple#2026!", "Empleado"),
    ]
    for uname, raw_pwd, rol in cuentas_iniciales:
        existe = Usuario.query.filter_by(username=uname).first()
        if not existe:
            pwd_hash = bcrypt.hashpw(
                raw_pwd.encode("utf-8"), bcrypt.gensalt(rounds=12)
            ).decode("utf-8")
            db.session.add(
                Usuario(username=uname, password_hash=pwd_hash, rol=rol, activo=True)
            )

    # Semilla de catálogo inicial de disfraces
    catalogo_inicial = [
        (
            "DIS-VAMP-001",
            "Conde Vampiro Clásico",
            "Terror",
            "L",
            "Capa de terciopelo, Chaleco, Medallón",
            25.00,
            50.00,
            "Disponible",
        ),
        (
            "DIS-MEDI-002",
            "Caballero Templario",
            "Histórico",
            "M",
            "Túnica bordada, Casco, Cinturón",
            35.00,
            70.00,
            "Disponible",
        ),
        (
            "DIS-EPOC-003",
            "Dama Victoriana",
            "Histórico",
            "S",
            "Vestido largo, Sombrero de época, Guantes",
            40.00,
            80.00,
            "Disponible",
        ),
        (
            "DIS-PIRA-004",
            "Capitán Corsario",
            "Aventura",
            "XL",
            "Tricornio, Casaca, Botas altas",
            30.00,
            60.00,
            "En lavanderia",
        ),
    ]
    for sku, nombre, cat, talla, piezas, alquiler, garantia, estado in catalogo_inicial:
        if not Disfraz.query.filter_by(sku=sku).first():
            db.session.add(
                Disfraz(
                    sku=sku,
                    nombre=nombre,
                    categoria=cat,
                    talla=talla,
                    piezas=piezas,
                    valor_alquiler=alquiler,
                    monto_garantia=garantia,
                    estado=estado,
                )
            )

    db.session.commit()


# ==============================================================================
# 2. MIDDLEWARES RBAC Y ENDURECIMIENTO DE CABECERAS HTTP (RS-05, RS-09, RS-12)
# ==============================================================================
def login_required(f):
    """Verifica sesión activa antes de permitir acceso a rutas operativas (RF-01, RS-04)."""

    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "user_id" not in session:
            flash("Por favor, inicie sesión para acceder al sistema.", "warning")
            return redirect(url_for("login"))
        return f(*args, **kwargs)

    return decorated_function


def role_required(rol_requerido: str):
    """Middleware RBAC de mínimo privilegio verificando explícitamente el rol en el servidor (RS-05)."""

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if "user_id" not in session:
                return redirect(url_for("login"))
            if session.get("rol") != rol_requerido:
                registrar_auditoria(
                    session.get("username", "Desconocido"),
                    "ACCESO_DENEGADO_RBAC",
                    f"Intento no autorizado a {request.path} (Requiere rol {
                        rol_requerido
                    })",
                )
                abort(403)
            return f(*args, **kwargs)

        return decorated_function

    return decorator


@app.after_request
def inyectar_cabeceras_seguridad(response):
    """Aplica cabeceras HTTP de seguridad y Content-Security-Policy estricta (RS-09, RS-12)."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Strict-Transport-Security"] = (
        "max-age=31536000; includeSubDomains"
    )
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self'; "
        "style-src 'self' https://cdn.jsdelivr.net 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self' https://cdn.jsdelivr.net; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "frame-ancestors 'none';"
    )
    return response


# ==============================================================================
# 3. MANEJO SEGURO DE EXCEPCIONES Y ERRORES (RS-10, RS-13)
# ==============================================================================
@app.errorhandler(CSRFError)
def manejar_error_csrf(e):
    registrar_auditoria(
        session.get("username", "Anonimo"),
        "BLOQUEO_CSRF",
        f"Token CSRF ausente o inválido en petición hacia {request.path}",
    )
    flash(
        "La sesión o el token de seguridad (CSRF) expiró. Intente nuevamente.", "danger"
    )
    return redirect(url_for("login" if "user_id" not in session else "index"))


@app.errorhandler(403)
def manejar_error_403(e):
    flash(
        "Acceso denegado (403): No cuenta con los privilegios necesarios para esta operación.",
        "danger",
    )
    return redirect(url_for("index" if "user_id" in session else "login"))


@app.errorhandler(404)
def manejar_error_404(e):
    flash("El recurso o registro solicitado no fue encontrado (404).", "warning")
    return redirect(url_for("index" if "user_id" in session else "login"))


@app.errorhandler(413)
def manejar_error_413(e):
    registrar_auditoria(
        session.get("username", "Anonimo"),
        "LIMITE_PAYLOAD_DOS",
        "Petición excedió 1 MB (RNF-03)",
    )
    flash(
        "El tamaño de los datos enviados excede el límite máximo permitido de 1 MB.",
        "danger",
    )
    return redirect(url_for("index" if "user_id" in session else "login"))


@app.errorhandler(500)
def manejar_error_500(e):
    db.session.rollback()
    registrar_auditoria(
        session.get("username", "Sistema"),
        "ERROR_SERVIDOR_500",
        "Excepción interna controlada",
    )
    flash(
        "Ocurrió un error interno controlado. No se expusieron datos sensibles (RS-13).",
        "danger",
    )
    return redirect(url_for("index" if "user_id" in session else "login"))


# ==============================================================================
# 4. RUTAS DE AUTENTICACIÓN Y GESTIÓN DE SESIONES (RF-01, RS-01, RS-03, RS-04)
# ==============================================================================
@app.route("/login", methods=["GET", "POST"])
def login():
    if "user_id" in session:
        return redirect(url_for("index"))

    form = LoginForm()
    if request.method == "POST":
        ip_cliente = (
            request.headers.get("X-Forwarded-For", request.remote_addr) or "127.0.0.1"
        )
        username_intento = sanitizar_cadena(request.form.get("username", ""))[:30]
        llave_rate_limit = f"{ip_cliente}:{username_intento.lower()}"

        # Verificar si la cuenta o IP está bloqueada temporalmente por Fuerza Bruta (RS-03)
        estado_bloqueo = INTENTOS_FALLIDOS.get(llave_rate_limit)
        if estado_bloqueo and estado_bloqueo["conteo"] >= MAX_INTENTOS_LOGIN:
            ahora = datetime.now()
            if ahora < estado_bloqueo["desbloqueo"]:
                minutos_restantes = (
                    int((estado_bloqueo["desbloqueo"] - ahora).total_seconds() // 60)
                    + 1
                )
                registrar_auditoria(
                    username_intento or "Anonimo",
                    "LOGIN_BLOQUEADO_FUERZA_BRUTA",
                    f"Intento durante bloqueo activo desde IP {ip_cliente}",
                )
                flash(
                    f"Cuenta bloqueada temporalmente por múltiples intentos fallidos (RS-03). "
                    f"Intente nuevamente en {minutos_restantes} minuto(s).",
                    "danger",
                )
                return render_template("login.html"), 429
            else:
                INTENTOS_FALLIDOS.pop(llave_rate_limit, None)

        if form.validate_on_submit():
            usuario = Usuario.query.filter_by(username=form.username.data).first()
            password_plana = form.password.data.encode("utf-8")

            if (
                usuario
                and usuario.activo
                and bcrypt.checkpw(
                    password_plana, usuario.password_hash.encode("utf-8")
                )
            ):
                INTENTOS_FALLIDOS.pop(llave_rate_limit, None)
                session.clear()
                session.permanent = True
                session["user_id"] = usuario.id
                session["username"] = usuario.username
                session["rol"] = usuario.rol

                registrar_auditoria(
                    usuario.username,
                    "LOGIN_EXITOSO",
                    f"Autenticación satisfactoria con rol {usuario.rol}",
                )
                flash(f"Bienvenido(a) al sistema, {usuario.username}.", "success")
                return redirect(url_for("index"))

        # Registrar intento fallido y aplicar bloqueo progresivo si llega a 5 (RS-03)
        registro = INTENTOS_FALLIDOS.get(
            llave_rate_limit, {"conteo": 0, "desbloqueo": datetime.now()}
        )
        registro["conteo"] += 1
        if registro["conteo"] >= MAX_INTENTOS_LOGIN:
            registro["desbloqueo"] = datetime.now() + TIEMPO_BLOQUEO_CUENTA

        INTENTOS_FALLIDOS[llave_rate_limit] = registro
        registrar_auditoria(
            username_intento or "Desconocido",
            "LOGIN_FALLIDO",
            f"Fallo de autenticación #{registro['conteo']} desde {ip_cliente}",
        )
        flash("Credenciales inválidas o cuenta inactiva.", "danger")

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
@login_required
def logout():
    usuario_actual = session.get("username", "Desconocido")
    registrar_auditoria(
        usuario_actual, "LOGOUT", "Cierre de sesión seguro e invalidación de cookie"
    )
    session.clear()
    flash("Ha cerrado sesión de forma segura.", "success")
    return redirect(url_for("login"))


# ==============================================================================
# 5. PANEL OPERATIVO PRINCIPAL: CATÁLOGO, MÉTRICAS Y BITÁCORA (RF-04, RF-07, RF-08)
# ==============================================================================
@app.route("/", methods=["GET"])
@login_required
def index():
    filtro_sku = sanitizar_cadena(request.args.get("sku", "")).upper()[:20]
    filtro_categoria = sanitizar_cadena(request.args.get("categoria", ""))[:40]
    filtro_talla = sanitizar_cadena(request.args.get("talla", ""))[:10]

    # Consulta parametrizada mediante ORM SQLAlchemy (RS-08 - Cero concatenación SQL)
    consulta_disfraces = Disfraz.query.filter(Disfraz.estado != "Baja")

    if filtro_sku:
        consulta_disfraces = consulta_disfraces.filter(
            Disfraz.sku.ilike(f"%{filtro_sku}%")
        )
    if filtro_categoria:
        consulta_disfraces = consulta_disfraces.filter(
            Disfraz.categoria.ilike(f"%{filtro_categoria}%")
        )
    if filtro_talla in TALLAS_PERMITIDAS:
        consulta_disfraces = consulta_disfraces.filter(Disfraz.talla == filtro_talla)

    disfraces = consulta_disfraces.order_by(Disfraz.sku.asc()).all()
    tickets = Ticket.query.order_by(Ticket.fecha_salida.desc()).all()

    metricas = None
    logs = []
    usuarios = []

    # Cargar Dashboard Operativo y Auditoría únicamente si el rol es Administrador (RS-05)
    if session.get("rol") == "Administrador":
        hoy = date.today()
        alquilados_activos = Disfraz.query.filter_by(estado="Alquilado").count()
        en_lavanderia = Disfraz.query.filter(
            Disfraz.estado.in_(["En lavanderia", "Danado"])
        ).count()
        vencidos = Ticket.query.filter(
            Ticket.estado_ticket == "Activo", Ticket.fecha_limite_retorno < hoy
        ).count()

        garantias_custodia = (
            db.session.query(func.coalesce(func.sum(Ticket.deposito_garantia), 0.0))
            .filter(Ticket.estado_ticket == "Activo")
            .scalar()
        )

        ingresos_retenciones = (
            db.session.query(func.coalesce(func.sum(Ticket.retencion_garantia), 0.0))
            .filter(Ticket.estado_ticket != "Activo")
            .scalar()
        )

        metricas = {
            "alquilados_activos": alquilados_activos,
            "en_lavanderia": en_lavanderia,
            "vencidos": vencidos,
            "garantias_custodia": float(garantias_custodia or 0.0),
            "ingresos_retenciones": float(ingresos_retenciones or 0.0),
        }
        logs = LogAuditoria.query.order_by(LogAuditoria.id.desc()).limit(40).all()
        usuarios = Usuario.query.order_by(Usuario.username.asc()).all()

    return render_template(
        "index.html",
        disfraces=disfraces,
        tickets=tickets,
        metricas=metricas,
        logs=logs,
        usuarios=usuarios,
    )


# ==============================================================================
# 6. GESTIÓN DE INVENTARIO DE DISFRACES (RF-03, RS-05, RS-06, RS-07, RS-08)
# ==============================================================================
@app.route("/inventario/registrar", methods=["POST"])
@login_required
def registrar_disfraz():
    form = RegistrarDisfrazForm()
    if not form.validate_on_submit():
        for campo, errores in form.errors.items():
            for error in errores:
                flash(f"Error de validación ({campo}): {error}", "danger")
        registrar_auditoria(
            session["username"],
            "VALIDACION_FALLIDA_INVENTARIO",
            "Rechazo de formulario de disfraz",
        )
        return redirect(url_for("index"))

    nuevo_disfraz = Disfraz(
        sku=form.sku.data,
        nombre=form.nombre.data,
        categoria=form.categoria.data,
        talla=form.talla.data,
        piezas=form.piezas.data,
        valor_alquiler=form.valor_alquiler.data,
        monto_garantia=form.monto_garantia.data,
        estado="Disponible",
    )

    try:
        db.session.add(nuevo_disfraz)
        db.session.commit()
        registrar_auditoria(
            session["username"],
            "ALTA_INVENTARIO",
            f"Registrado SKU {nuevo_disfraz.sku}",
        )
        flash(
            f"Disfraz {nuevo_disfraz.sku} ({
                nuevo_disfraz.nombre
            }) registrado en el catálogo.",
            "success",
        )
    except IntegrityError:
        db.session.rollback()
        flash(
            "Error: El código SKU ingresado ya se encuentra registrado en la base de datos.",
            "danger",
        )

    return redirect(url_for("index"))


@app.route("/inventario/baja/<string:disfraz_id>", methods=["POST"])
@role_required("Administrador")
def dar_baja_disfraz(disfraz_id: str):
    disfraz = Disfraz.query.filter_by(id=disfraz_id).first()
    if not disfraz:
        abort(404)

    if disfraz.estado == "Alquilado":
        flash(
            "No se puede dar de baja un disfraz que tiene un alquiler activo en curso.",
            "danger",
        )
        return redirect(url_for("index"))

    disfraz.estado = "Baja"
    db.session.commit()
    registrar_auditoria(
        session["username"],
        "BAJA_INVENTARIO",
        f"Baja lógica aplicada al SKU {disfraz.sku}",
    )
    flash(
        f"El disfraz {disfraz.sku} ha sido retirado del inventario activo.", "success"
    )
    return redirect(url_for("index"))


# ==============================================================================
# 7. EMISIÓN Y LIQUIDACIÓN DE TICKETS DE ALQUILER (RF-05, RF-06, RS-07, RS-09)
# ==============================================================================
@app.route("/tickets/emitir", methods=["POST"])
@login_required
def emitir_ticket():
    form = EmitirTicketForm()
    if not form.validate_on_submit():
        for campo, errores in form.errors.items():
            for error in errores:
                flash(f"{error}", "danger")
        registrar_auditoria(
            session["username"],
            "VALIDACION_FALLIDA_TICKET",
            "Rechazo de emisión por datos inválidos",
        )
        return redirect(url_for("index"))

    disfraz = Disfraz.query.filter_by(
        id=form.disfraz_id.data, estado="Disponible"
    ).first()
    if not disfraz:
        flash(
            "La prenda seleccionada no existe o ya no se encuentra disponible en stock.",
            "danger",
        )
        return redirect(url_for("index"))

    nuevo_ticket = Ticket(
        disfraz_id=disfraz.id,
        cliente_nombre=form.cliente_nombre.data,
        cliente_dni=form.cliente_dni.data,
        cliente_telefono=form.cliente_telefono.data,
        estado_entrega_piezas=form.estado_entrega_piezas.data,
        fecha_salida=form.fecha_salida.data,
        fecha_limite_retorno=form.fecha_limite_retorno.data,
        deposito_garantia=form.deposito_garantia.data,
        retencion_garantia=0.00,
        estado_ticket="Activo",
        emitido_por=session["username"],
    )

    disfraz.estado = "Alquilado"
    db.session.add(nuevo_ticket)
    db.session.commit()

    registrar_auditoria(
        session["username"],
        "EMISION_TICKET",
        f"Ticket emitido para SKU {disfraz.sku} (Cliente DNI: {
            nuevo_ticket.cliente_dni
        })",
    )
    flash(
        f"Ticket de alquiler emitido exitosamente para la prenda {disfraz.sku}.",
        "success",
    )
    return redirect(url_for("index"))


@app.route("/tickets/devolver/<string:ticket_id>", methods=["POST"])
@login_required
def devolver_ticket(ticket_id: str):
    form = DevolverTicketForm()
    if not form.validate_on_submit():
        flash("Datos de inspección de retorno inválidos.", "danger")
        return redirect(url_for("index"))

    ticket = Ticket.query.filter_by(id=ticket_id, estado_ticket="Activo").first()
    if not ticket:
        abort(404)

    hoy = date.today()
    deposito = float(ticket.deposito_garantia)
    tipo_incidencia = form.tipo_incidencia.data

    # Cálculo automatizado de retención de garantía en el servidor (RF-06)
    porcentaje_retencion = 0.0
    if hoy > ticket.fecha_limite_retorno:
        porcentaje_retencion += 0.25  # +25% por mora en la fecha de devolución

    if tipo_incidencia == "Mancha Grave":
        porcentaje_retencion += 0.30
    elif tipo_incidencia == "Dano Parcial":
        porcentaje_retencion += 0.50
    elif tipo_incidencia == "Perdida o Dano Total":
        porcentaje_retencion = 1.00

    porcentaje_retencion = min(1.00, porcentaje_retencion)
    monto_retenido = round(deposito * porcentaje_retencion, 2)

    observacion_limpia = (
        form.observaciones.data or f"Inspección completada ({tipo_incidencia})"
    )
    ticket.fecha_devolucion_real = hoy
    ticket.retencion_garantia = monto_retenido
    ticket.observaciones_incidencia = observacion_limpia
    ticket.estado_ticket = (
        "Con Incidencia"
        if (monto_retenido > 0 or tipo_incidencia != "Ninguna")
        else "Cerrado"
    )

    if ticket.disfraz:
        ticket.disfraz.estado = form.nuevo_estado_disfraz.data

    db.session.commit()
    registrar_auditoria(
        session["username"],
        "DEVOLUCION_LIQUIDADA",
        f"Retorno SKU {ticket.sku} | Incidencia: {tipo_incidencia} | Retenido: ${
            monto_retenido:.2f}",
    )
    flash(
        f"Retorno procesado para {ticket.sku}. Garantía retenida: ${
            monto_retenido:.2f}.",
        "success",
    )
    return redirect(url_for("index"))


# ==============================================================================
# 8. GESTIÓN DE PERSONAL Y ROLES RBAC - SOLO ADMINISTRADOR (RF-02, RS-01, RS-02, RS-05)
# ==============================================================================
@app.route("/admin/usuarios/crear", methods=["POST"])
@role_required("Administrador")
def crear_usuario():
    form = CrearUsuarioForm()
    if not form.validate_on_submit():
        for _, errores in form.errors.items():
            for error in errores:
                flash(error, "danger")
        registrar_auditoria(
            session["username"],
            "POLITICA_PASSWORD_FALLIDA",
            "Intento de alta incumpliendo RS-02",
        )
        return redirect(url_for("index"))

    # Derivación de clave adaptativa con Bcrypt factor de costo 12 (RS-01)
    pwd_hash = bcrypt.hashpw(
        form.password.data.encode("utf-8"), bcrypt.gensalt(rounds=12)
    ).decode("utf-8")
    nuevo_usuario = Usuario(
        username=form.username.data,
        password_hash=pwd_hash,
        rol=form.rol.data,
        activo=True,
    )

    try:
        db.session.add(nuevo_usuario)
        db.session.commit()
        registrar_auditoria(
            session["username"],
            "ALTA_USUARIO_RBAC",
            f"Creada cuenta '{nuevo_usuario.username}' con rol '{nuevo_usuario.rol}'",
        )
        flash(
            f"Cuenta de personal '{nuevo_usuario.username}' creada satisfactoriamente.",
            "success",
        )
    except IntegrityError:
        db.session.rollback()
        flash("El nombre de usuario ingresado ya existe en el sistema.", "danger")

    return redirect(url_for("index"))


@app.route("/admin/usuarios/estado/<string:user_id>", methods=["POST"])
@role_required("Administrador")
def cambiar_estado_usuario(user_id: str):
    if user_id == session.get("user_id"):
        flash(
            "Medida de seguridad: No puede desactivar su propia sesión de Administrador activa.",
            "danger",
        )
        return redirect(url_for("index"))

    usuario = Usuario.query.filter_by(id=user_id).first()
    if not usuario:
        abort(404)

    usuario.activo = not usuario.activo
    db.session.commit()

    estado_str = "Activo" if usuario.activo else "Inactivo"
    registrar_auditoria(
        session["username"],
        "CAMBIO_ESTADO_CUENTA",
        f"Cuenta '{usuario.username}' cambiada a estado: {estado_str}",
    )
    flash(
        f"Estado del usuario '{usuario.username}' actualizado a {estado_str}.",
        "success",
    )
    return redirect(url_for("index"))


# Inicialización automática de esquema y datos semilla al arrancar el contexto de la aplicación
with app.app_context():
    try:
        inicializar_datos_semilla()
    except Exception as exc:
        print(
            f"[AVISO] Esperando conexión activa a PostgreSQL para inicializar tablas: {exc}"
        )


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
