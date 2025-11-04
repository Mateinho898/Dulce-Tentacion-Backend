from datetime import datetime, timedelta
from typing import List, Optional
from sqlmodel import SQLModel, Field, Relationship, Session, create_engine, select
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError
from passlib.context import CryptContext

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
# =========================
# CONFIG
# =========================
SECRET_KEY = "CAMBIA_ESTE_SECRETO_ULTRA_SEGURO"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

engine = create_engine("sqlite:///dulce.db", echo=False)
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

# =========================
# MODELOS DB
# =========================
class Cliente(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    nombre: str
    email: str = Field(index=True, unique=True)
    hash_password: str
    telefono: Optional[str] = None
    rol: str = Field(default="cliente")  # cliente|admin|repartidor
    created_at: datetime = Field(default_factory=datetime.utcnow)

    direcciones: List["Direccion"] = Relationship(back_populates="cliente")
    pedidos: List["Pedido"] = Relationship(back_populates="cliente")


class Direccion(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    cliente_id: int = Field(foreign_key="cliente.id")
    calle: str
    comuna: str
    ciudad: str
    referencia: Optional[str] = None

    cliente: "Cliente" = Relationship(back_populates="direcciones")


class Producto(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    nombre: str
    descripcion: Optional[str] = None
    precio: int
    activo: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)


class PedidoItem(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    pedido_id: int = Field(foreign_key="pedido.id")
    producto_id: int = Field(foreign_key="producto.id")
    cantidad: int
    precio_unitario: int
    nota_personalizacion: Optional[str] = None


class Pago(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    pedido_id: int = Field(foreign_key="pedido.id", unique=True)
    metodo: str  # webpay|servipag|transferencia|simulado
    estado: str = "pendiente"  # pendiente|aprobado|rechazado
    tx_ref: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class Despacho(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    pedido_id: int = Field(foreign_key="pedido.id", unique=True)
    repartidor_id: Optional[int] = None  # id de Cliente con rol "repartidor"
    estado: str = "asignado"  # asignado|en_reparto|entregado
    tracking: Optional[str] = None
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class Pedido(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    cliente_id: int = Field(foreign_key="cliente.id")
    estado: str = "creado"  # creado|pagado|asignado|en_ruta|entregado|cancelado
    total: int = 0
    created_at: datetime = Field(default_factory=datetime.utcnow)

    cliente: Cliente = Relationship(back_populates="pedidos")
    items: List[PedidoItem] = Relationship()
    pago: Optional[Pago] = Relationship()
    despacho: Optional[Despacho] = Relationship()

# =========================
# SCHEMAS (I/O)
# =========================
from pydantic import BaseModel

class ClienteCreate(BaseModel):
    nombre: str
    email: str
    password: str
    telefono: Optional[str] = None

class ClienteOut(BaseModel):
    id: int
    nombre: str
    email: str
    rol: str
    class Config:
        from_attributes = True

class ProductoIn(BaseModel):
    nombre: str
    descripcion: Optional[str] = None
    precio: int
    activo: bool = True

class ProductoOut(BaseModel):
    id: int
    nombre: str
    descripcion: Optional[str]
    precio: int
    activo: bool
    class Config:
        from_attributes = True

class PedidoItemIn(BaseModel):
    producto_id: int
    cantidad: int
    precio_unitario: int
    nota_personalizacion: Optional[str] = None

class PedidoCreate(BaseModel):
    items: List[PedidoItemIn]
    metodo_pago: str  # webpay|servipag|transferencia|simulado

class PedidoOut(BaseModel):
    id: int
    cliente_id: int
    estado: str
    total: int
    class Config:
        from_attributes = True

class PagoOut(BaseModel):
    id: int
    pedido_id: int
    metodo: str
    estado: str
    tx_ref: Optional[str]
    class Config:
        from_attributes = True

class DespachoUpdate(BaseModel):
    repartidor_id: Optional[int] = None
    estado: Optional[str] = None
    tracking: Optional[str] = None

# =========================
# UTILES AUTH
# =========================
def create_db():
    SQLModel.metadata.create_all(engine)

def get_session():
    with Session(engine) as session:
        yield session

def create_access_token(data: dict, expires_delta: int = ACCESS_TOKEN_EXPIRE_MINUTES):
    to_encode = data.copy()
    expire = datetime.utcnow() + timedelta(minutes=expires_delta)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

def get_current_user(token: str = Depends(oauth2_scheme), session: Session = Depends(get_session)) -> Cliente:
    credentials_exception = HTTPException(status_code=401, detail="Token inválido")
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id: int = int(payload.get("sub"))
    except JWTError:
        raise credentials_exception
    user = session.get(Cliente, user_id)
    if not user:
        raise credentials_exception
    return user

def require_role(*roles):
    def wrapper(user: Cliente = Depends(get_current_user)):
        if user.rol not in roles:
            raise HTTPException(status_code=403, detail="Permisos insuficientes")
        return user
    return wrapper
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain: str, hashed: str) -> bool:
    return pwd_context.verify(plain, hashed)

# =========================
# APP
# =========================
app = FastAPI(title="Dulce Tentación API", version="1.0.0")


@app.on_event("startup")
def on_startup():
    create_db()
    with Session(engine) as s:
        admin = s.exec(select(Cliente).where(Cliente.email == "admin@dulce.cl")).first()
        if not admin:
            admin = Cliente(
                nombre="Admin",
                email="admin@dulce.cl",
                # 👇 OJO: el nombre del campo es hash_password
                hash_password=hash_password("tortas123"),
                rol="admin",
            )
            s.add(admin)
            s.commit()

# -------------------------
# AUTH
# -------------------------
@app.post("/auth/register", response_model=ClienteOut, status_code=201)
def register(data: ClienteCreate, session: Session = Depends(get_session)):
    if session.exec(select(Cliente).where(Cliente.email == data.email)).first():
        raise HTTPException(400, "Email ya registrado")
    user = Cliente(
        nombre=data.nombre,
        email=data.email,
        hash_password=bcrypt.hash(data.password),
        telefono=data.telefono,
        rol="cliente"
    )
    session.add(user)
    session.commit()
    session.refresh(user)
    return user

@app.post("/auth/login")
def login(form: OAuth2PasswordRequestForm = Depends(), session: Session = Depends(get_session)):
    user = session.exec(select(Cliente).where(Cliente.email == form.username)).first()
    if not user or not verify_password(form.password, user.hash_password):
        raise HTTPException(400, "Credenciales inválidas")
    token = create_access_token({"sub": str(user.id), "role": user.rol})
    return {"access_token": token, "token_type": "bearer", "user": {"id": user.id, "email": user.email, "rol": user.rol}}

# -------------------------
# PRODUCTOS (CRUD)
# -------------------------
@app.get("/productos", response_model=List[ProductoOut])
def list_productos(session: Session = Depends(get_session)):
    return session.exec(select(Producto)).all()

@app.post("/productos", response_model=ProductoOut, status_code=201)
def create_producto(data: ProductoIn, _: Cliente = Depends(require_role("admin")), session: Session = Depends(get_session)):
    p = Producto(**data.model_dump())
    session.add(p)
    session.commit()
    session.refresh(p)
    return p

@app.put("/productos/{producto_id}", response_model=ProductoOut)
def update_producto(producto_id: int, data: ProductoIn, _: Cliente = Depends(require_role("admin")), session: Session = Depends(get_session)):
    p = session.get(Producto, producto_id)
    if not p:
        raise HTTPException(404, "Producto no encontrado")
    for k, v in data.model_dump().items():
        setattr(p, k, v)
    session.add(p)
    session.commit()
    session.refresh(p)
    return p

@app.delete("/productos/{producto_id}", status_code=204)
def delete_producto(producto_id: int, _: Cliente = Depends(require_role("admin")), session: Session = Depends(get_session)):
    p = session.get(Producto, producto_id)
    if not p:
        raise HTTPException(404, "Producto no encontrado")
    session.delete(p)
    session.commit()
    return

# -------------------------
# PEDIDOS + ITEMS + PAGO
# -------------------------
@app.post("/pedidos", response_model=PedidoOut, status_code=201)
def create_pedido(body: PedidoCreate, user: Cliente = Depends(require_role("cliente","admin")), session: Session = Depends(get_session)):
    # Calcula total y crea pedido + items
    total = 0
    pedido = Pedido(cliente_id=user.id, estado="creado", total=0)
    session.add(pedido)
    session.commit()
    session.refresh(pedido)

    for it in body.items:
        producto = session.get(Producto, it.producto_id)
        if not producto or not producto.activo:
            raise HTTPException(400, f"Producto {it.producto_id} inválido")
        total += it.cantidad * it.precio_unitario
        item = PedidoItem(
            pedido_id=pedido.id,
            producto_id=producto.id,
            cantidad=it.cantidad,
            precio_unitario=it.precio_unitario,
            nota_personalizacion=it.nota_personalizacion
        )
        session.add(item)

    pedido.total = total
    session.add(pedido)
    session.commit()

    # Crea pago pendiente (simulado)
    pago = Pago(pedido_id=pedido.id, metodo=body.metodo_pago, estado="pendiente", tx_ref=None)
    session.add(pago)
    session.commit()
    return pedido

@app.get("/pedidos/{pedido_id}", response_model=PedidoOut)
def get_pedido(pedido_id: int, user: Cliente = Depends(get_current_user), session: Session = Depends(get_session)):
    p = session.get(Pedido, pedido_id)
    if not p:
        raise HTTPException(404, "Pedido no encontrado")
    # Cliente solo ve su pedido
    if user.rol == "cliente" and p.cliente_id != user.id:
        raise HTTPException(403, "No autorizado")
    return p

@app.post("/pagos/{pedido_id}/confirmar", response_model=PagoOut)
def confirmar_pago(pedido_id: int, user: Cliente = Depends(get_current_user), session: Session = Depends(get_session)):
    pedido = session.get(Pedido, pedido_id)
    if not pedido:
        raise HTTPException(404, "Pedido no encontrado")
    if user.rol == "cliente" and pedido.cliente_id != user.id:
        raise HTTPException(403, "No autorizado")
    pago = session.exec(select(Pago).where(Pago.pedido_id==pedido_id)).first()
    if not pago:
        raise HTTPException(400, "Pago inexistente")
    pago.estado = "aprobado"
    pago.tx_ref = f"SIM-{pedido_id}-{int(datetime.utcnow().timestamp())}"
    pedido.estado = "pagado"
    session.add(pago)
    session.add(pedido)
    session.commit()
    session.refresh(pago)
    return pago

# -------------------------
# DESPACHO
# -------------------------
@app.patch("/despachos/{pedido_id}", response_model=dict)
def actualizar_despacho(pedido_id: int, body: DespachoUpdate, _: Cliente = Depends(require_role("admin","repartidor")), session: Session = Depends(get_session)):
    pedido = session.get(Pedido, pedido_id)
    if not pedido:
        raise HTTPException(404, "Pedido no encontrado")

    despacho = session.exec(select(Despacho).where(Despacho.pedido_id==pedido_id)).first()
    if not despacho:
        despacho = Despacho(pedido_id=pedido_id, estado="asignado")
        session.add(despacho)
        session.commit()
        session.refresh(despacho)

    if body.repartidor_id is not None:
        despacho.repartidor_id = body.repartidor_id
        pedido.estado = "asignado"
    if body.estado is not None:
        despacho.estado = body.estado
        if body.estado == "en_reparto":
            pedido.estado = "en_ruta"
        if body.estado == "entregado":
            pedido.estado = "entregado"
    if body.tracking is not None:
        despacho.tracking = body.tracking

    despacho.updated_at = datetime.utcnow()
    session.add(despacho)
    session.add(pedido)
    session.commit()
    return {"ok": True, "pedido_estado": pedido.estado, "despacho_estado": despacho.estado}
