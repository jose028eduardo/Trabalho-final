import bcrypt
from fastapi import APIRouter, Depends, Form, Path, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from models.Usuario import Usuario
from repositories.ProdutoRepo import ProdutoRepo
from repositories.UsuarioRepo import UsuarioRepo
from util.mensagem import adicionar_cookie_mensagem, redirecionar_com_mensagem
from util.seguranca import (
    adicionar_cookie_autenticacao,
    conferir_senha,
    excluir_cookie_autenticacao,
    gerar_token,
    obter_usuario_logado,
    obter_hash_senha,
)

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/", response_class=HTMLResponse)
async def get_index(
    request: Request,
    usuario: Usuario = Depends(obter_usuario_logado),
):
    produtos = ProdutoRepo.obter_todos()

    return templates.TemplateResponse(
        "root/index.html",
        {"request": request, "usuario": usuario, "produtos": produtos},
    )


@router.get("/login", response_class=HTMLResponse)
async def get_login(
    request: Request,
    usuario: Usuario = Depends(obter_usuario_logado),
):
    return templates.TemplateResponse(
        "root/login.html",
        {"request": request, "usuario": usuario},
    )


@router.post("/login", response_class=RedirectResponse)
async def post_login(
    email: str = Form(...),
    senha: str = Form(...),
    return_url: str = Query("/"),
):
    hash_senha_bd = UsuarioRepo.obter_senha_por_email(email)
    if conferir_senha(senha, hash_senha_bd):
        token = gerar_token()
        UsuarioRepo.alterar_token_por_email(token, email)
        response = RedirectResponse(return_url, status.HTTP_302_FOUND)
        adicionar_cookie_autenticacao(response, token)
        adicionar_cookie_mensagem(response, "Login realizado com sucesso.")
    else:
        response = redirecionar_com_mensagem(
            "/login",
            "Credenciais inválidas. Tente novamente.",
        )
    return response


@router.get("/logout")
async def get_logout(usuario: Usuario = Depends(obter_usuario_logado)):
    if usuario:
        UsuarioRepo.alterar_token_por_email("", usuario.email)
        response = RedirectResponse("/", status.HTTP_302_FOUND)
        excluir_cookie_autenticacao(response)
        adicionar_cookie_mensagem(response, "Saída realizada com sucesso.")
        return response


@router.get("/detalhes/{id_produto:int}")
async def get_detalhes(
    request: Request,
    id_produto: int = Path(),
    usuario: Usuario = Depends(obter_usuario_logado),
):
    produto = ProdutoRepo.obter_por_id(id_produto)

    return templates.TemplateResponse(
        "root/detalhes.html",
        {"request": request, "usuario": usuario, "produto": produto},
    )


@router.get("/cadastro")
async def get_cadastro(
    request: Request,
):
    return templates.TemplateResponse(
        "root/cadastro.html",
        {
            "request": request,
        },
    )


@router.post("/cadastro")
async def post_cadastro(
    nome: str = Form(...),
    email: str = Form(...),
    senha: str = Form(...),
):
    hash = obter_hash_senha(senha)
    usuario = Usuario(nome=nome, email=email, senha=hash)
    usuario = UsuarioRepo.inserir(usuario)

    response = redirecionar_com_mensagem("/", "Usuário cadastrado com sucesso!")
    return response


from fastapi import Form


@router.post("/alterar")
async def post_alterar_perfil(
    nome: str = Form(...),
    email: str = Form(...),
    usuario_logado: Usuario = Depends(obter_usuario_logado),
):
    usuario_logado.nome = nome
    usuario_logado.email = email
    UsuarioRepo.alterar(usuario_logado)

    response = redirecionar_com_mensagem("/", "Usuário cadastrado com sucesso!")
    return response





