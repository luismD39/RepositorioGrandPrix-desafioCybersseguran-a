from flask import Flask, request, jsonify, make_response, send_from_directory
import jwt
import datetime
from functools import wraps
### NOVO ### Importações para criptografia
from cryptography.fernet import Fernet
import base64
import os

app = Flask(__name__)

# Configurações de segurança
app.config['SECRET_KEY'] = 'chave-super-secreta-da-petrobras'
JWT_ALGORITHM = 'HS256'
JWT_EXPIRATION_MINUTES = 30

### NOVO ### Geração de uma chave para criptografia simétrica (Fernet)
# Em um sistema real, essa chave seria armazenada em um cofre de segredos (HSM, Vault)
# Para nossa demonstração, geramos uma nova a cada execução ou fixamos para teste.
# Vamos gerar uma fixa para facilitar o teste, mas em produção seria variável de ambiente.
CHAVE_CRIPTO = Fernet.generate_key()
cipher_suite = Fernet(CHAVE_CRIPTO)

# Simulação de um banco de dados de usuários COM ROLES (perfis)
USUARIOS = {
    "admin": {
        "password": "admin123",
        "role": "admin"
    },
    "engenheiro": {
        "password": "engenheiro123",
        "role": "engenheiro"
    },
    "estagiario": {
        "password": "estag123",
        "role": "visualizador"
    }
}

### NOVO ### Simulação de um banco de dados com informações sensíveis
# Imagine que isso vem de um sistema real, como uma tabela de funcionários.
# O CPF está armazenado de forma CRIPTOGRAFADA.
cpf_criptografado = cipher_suite.encrypt(b"123.456.789-00")  # CPF de exemplo

DADOS_SENSIVEIS = {
    "colaborador_id": 1001,
    "nome": "João da Silva",
    "cpf": cpf_criptografado  # Armazenamos o valor cifrado!
}

# ------------------------------------------------------------
# Função auxiliar para gerar token JWT (AGORA COM ROLE)
# ------------------------------------------------------------
def gerar_token(username, role):
    payload = {
        'sub': username,
        'role': role,  ### NOVO ### Inclui o perfil no payload do token
        'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=JWT_EXPIRATION_MINUTES)
    }
    token = jwt.encode(payload, app.config['SECRET_KEY'], algorithm=JWT_ALGORITHM)
    return token

# ------------------------------------------------------------
# Decorador para proteger rotas (AGORA EXTRAI TAMBÉM A ROLE)
# ------------------------------------------------------------
def token_obrigatorio(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization')
        if auth_header:
            partes = auth_header.split()
            if len(partes) == 2 and partes[0] == 'Bearer':
                token = partes[1]
        
        if not token:
            return jsonify({'erro': 'Token de autenticação não fornecido'}), 401

        try:
            dados = jwt.decode(token, app.config['SECRET_KEY'], algorithms=[JWT_ALGORITHM])
            usuario_atual = dados['sub']
            role_atual = dados.get('role', 'visualizador')  ### NOVO ###
        except jwt.ExpiredSignatureError:
            return jsonify({'erro': 'Token expirado. Faça login novamente.'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'erro': 'Token inválido'}), 401

        # Passa o usuário e a role para a função da rota
        return f(usuario_atual, role_atual, *args, **kwargs)
    return decorated

# ------------------------------------------------------------
# ROTA DE LOGIN (atualizada para incluir role no token)
# ------------------------------------------------------------
@app.route('/login', methods=['POST'])
def login():
    dados = request.get_json()
    if not dados:
        return jsonify({'erro': 'Requisição deve ser JSON'}), 400

    username = dados.get('username')
    password = dados.get('password')

    if username in USUARIOS and USUARIOS[username]["password"] == password:
        user_data = USUARIOS[username]
        token = gerar_token(username, user_data["role"])  ### NOVO ###
        return jsonify({
            'mensagem': 'Login bem-sucedido',
            'token_acesso': token,
            'tipo': 'Bearer',
            'role': user_data["role"]  # Retornamos a role para o cliente saber
        }), 200
    else:
        return jsonify({'erro': 'Credenciais inválidas'}), 401

# ------------------------------------------------------------
# ROTA PROTEGIDA (exemplo anterior, sem dados sensíveis)
# ------------------------------------------------------------
@app.route('/consulta-dados', methods=['GET'])
@token_obrigatorio
def consulta_dados(usuario_atual, role_atual):
    dados_publicos = {
        'mensagem': f'Olá {usuario_atual} ({role_atual}), aqui estão os dados operacionais.',
        'producao_diaria': '15000 barris',
        'status': 'Operando normalmente'
    }
    return jsonify(dados_publicos), 200

### NOVO ### ROTA COM DADOS SENSÍVEIS E CONTROLE DE ACESSO GRANULAR
@app.route('/dados-sensiveis', methods=['GET'])
@token_obrigatorio
def dados_sensiveis(usuario_atual, role_atual):
    # Copia o dicionário para não modificar o original
    resposta = DADOS_SENSIVEIS.copy()
    
    # Por padrão, o CPF vai criptografado (seguro para qualquer um ver)
    # Mas se o usuário tiver a role 'admin', descriptografamos antes de enviar
    if role_atual == 'admin':
        try:
            # Descriptografa o CPF para exibição
            cpf_bytes = cipher_suite.decrypt(resposta['cpf'])
            resposta['cpf'] = cpf_bytes.decode('utf-8')
            resposta['aviso'] = 'CPF descriptografado pois você é admin.'
        except Exception as e:
            resposta['cpf'] = 'ERRO_NA_DESCRIPTOGRAFIA'
    else:
        # Para não-admins, mantemos o CPF criptografado (em base64 para fácil visualização)
        # Convertendo bytes para string base64 para aparecer legível no JSON
        resposta['cpf'] = base64.b64encode(resposta['cpf']).decode('utf-8')
        resposta['aviso'] = 'CPF criptografado. Apenas usuários com perfil "admin" veem o valor real.'
    
    resposta['acessado_por'] = usuario_atual
    resposta['role'] = role_atual
    return jsonify(resposta), 200

# ------------------------------------------------------------
# SERVIÇO DE ARQUIVOS ESTÁTICOS (mantido)
# ------------------------------------------------------------
@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

# ------------------------------------------------------------
# ROTA RAIZ - Serve a interface visual
# ------------------------------------------------------------
@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

# ------------------------------------------------------------
# NOVA ROTA: Validação de Token JWT (para ativação manual)
# ------------------------------------------------------------
@app.route('/validar-token', methods=['POST'])
def validar_token():
    dados = request.get_json()
    if not dados or 'token' not in dados:
        return jsonify({'valido': False, 'erro': 'Token não fornecido'}), 400

    token = dados['token']

    try:
        # Decodifica e valida a assinatura, expiração, etc.
        payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=[JWT_ALGORITHM])
        username = payload.get('sub')
        role = payload.get('role', 'visualizador')

        # (Opcional) Verificar se o usuário ainda existe no "banco"
        if username not in USUARIOS:
            return jsonify({'valido': False, 'erro': 'Usuário não encontrado'}), 401

        return jsonify({
            'valido': True,
            'username': username,
            'role': role
        }), 200

    except jwt.ExpiredSignatureError:
        return jsonify({'valido': False, 'erro': 'Token expirado'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'valido': False, 'erro': 'Token inválido (assinatura ou formato)'}), 401

# ------------------------------------------------------------
# PONTO DE ENTRADA
# ------------------------------------------------------------
if __name__ == '__main__':
    # Mostra a chave de criptografia no console para debug (apenas para demonstração)
    print(f"🔐 Chave de criptografia gerada: {CHAVE_CRIPTO.decode()}")
    app.run(debug=True, host='0.0.0.0', port=5000)