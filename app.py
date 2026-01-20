# ============================================================================
# BACKEND PYTHON - SISTEMA DE LOGIN SEGURO
# UFCD 10795 - Segurança de Aplicações
# ============================================================================

from flask import Flask, request, jsonify, render_template_string
from flask_cors import CORS
import mysql.connector
from mysql.connector import Error
import hashlib
import re
from datetime import datetime
import os

app = Flask(__name__)
CORS(app)  # Permitir requests do frontend

# ============================================================================
# CONFIGURAÇÃO DA BASE DE DADOS
# ============================================================================

DB_CONFIG = {
    'host': 'localhost',
    'user': 'root',           # ⚠️ ALTERAR para o teu user MySQL
    'password': 'tua_password',  # ⚠️ ALTERAR para a tua password MySQL
    'database': 'sistema_login_seguro'
}
# ============================================================================
# FUNÇÕES DE SEGURANÇA
# ============================================================================

def criar_hash_password(password):
    """
    Cria hash SHA-256 da password com salt
    Em produção: usar bcrypt ou Argon2
    """
    salt = "salt_seguro_2025"
    password_com_salt = password + salt
    return hashlib.sha256(password_com_salt.encode()).hexdigest()


def sanitizar_input(texto):
    """
    Remove caracteres perigosos para prevenir XSS
    """
    if not texto:
        return ""
    
    # Remove caracteres perigosos
    caracteres_perigosos = ['<', '>', '"', "'", ';', '&', '|', '(', ')']
    texto_limpo = texto
    
    for char in caracteres_perigosos:
        texto_limpo = texto_limpo.replace(char, '')
    
    return texto_limpo.strip()


def validar_username(username):
    """
    Valida username segundo as regras de segurança
    """
    if not username or len(username.strip()) == 0:
        return False, "Username não pode estar vazio"
    
    if len(username) < 3:
        return False, "Username deve ter pelo menos 3 caracteres"
    
    if len(username) > 20:
        return False, "Username não pode ter mais de 20 caracteres"
    
    # Apenas letras, números e underscore
    if not re.match(r'^[a-zA-Z0-9_]+$', username):
        return False, "Username só pode conter letras, números e underscore"
    
    return True, ""


def validar_email(email):
    """
    Valida formato de email
    """
    if not email:
        return False, "Email não pode estar vazio"
    
    # Regex para validar email
    padrao_email = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(padrao_email, email):
        return False, "Formato de email inválido"
    
    if len(email) > 100:
        return False, "Email demasiado longo"
    
    return True, ""


def validar_password(password):
    """
    Valida password segundo requisitos de segurança
    """
    if not password:
        return False, "Password não pode estar vazia"
    
    if len(password) < 8:
        return False, "Password deve ter pelo menos 8 caracteres"
    
    if len(password) > 50:
        return False, "Password não pode ter mais de 50 caracteres"
    
    # Verificar maiúsculas
    if not any(c.isupper() for c in password):
        return False, "Password deve conter pelo menos uma letra maiúscula"
    
    # Verificar minúsculas
    if not any(c.islower() for c in password):
        return False, "Password deve conter pelo menos uma letra minúscula"
    
    # Verificar números
    if not any(c.isdigit() for c in password):
        return False, "Password deve conter pelo menos um número"
    
    return True, ""


# ============================================================================
# FUNÇÕES DE BASE DE DADOS
# ============================================================================

def get_db_connection():
    """
    Cria conexão segura com a base de dados
    """
    try:
        connection = mysql.connector.connect(**DB_CONFIG)
        return connection
    except Error as e:
        print(f"Erro ao conectar à base de dados: {e}")
        return None


def executar_stored_procedure(procedure_name, params):
    """
    Executa stored procedure de forma segura
    PROTEÇÃO: Usa prepared statements automaticamente
    """
    connection = get_db_connection()
    if not connection:
        return None, "Erro de conexão à base de dados"
    
    try:
        cursor = connection.cursor()
        cursor.callproc(procedure_name, params)
        
        # Obter resultados
        results = []
        for result in cursor.stored_results():
            results.extend(result.fetchall())
        
        connection.commit()
        cursor.close()
        connection.close()
        
        return results, None
        
    except Error as e:
        if connection:
            connection.close()
        return None, f"Erro ao executar operação: {str(e)}"


# ============================================================================
# ROTAS DA API
# ============================================================================

@app.route('/')
def index():
    """
    Página principal - serve o HTML
    """
    # Ler o ficheiro HTML que criaste
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            html_content = f.read()
        return html_content
    except FileNotFoundError:
        return """
        <h1>⚠️ Ficheiro index.html não encontrado</h1>
        <p>Por favor, cria o ficheiro index.html na mesma pasta deste script Python.</p>
        <p>Ou acede diretamente às rotas da API:</p>
        <ul>
            <li>POST /api/register - Registar utilizador</li>
            <li>POST /api/login - Fazer login</li>
            <li>GET /api/users - Listar utilizadores</li>
            <li>GET /api/logs - Ver logs de segurança</li>
        </ul>
        """


@app.route('/api/register', methods=['POST'])
def registar_utilizador():
    """
    Endpoint para registar novo utilizador
    PROTEÇÃO: Validações + Stored Procedure + Sanitização
    """
    try:
        # Obter dados do request
        dados = request.get_json()
        username = dados.get('username', '')
        email = dados.get('email', '')
        password = dados.get('password', '')
        
        # Sanitizar inputs (PROTEÇÃO XSS)
        username = sanitizar_input(username)
        email = sanitizar_input(email)
        
        # Validar username
        valido, mensagem = validar_username(username)
        if not valido:
            return jsonify({
                'success': False,
                'message': mensagem
            }), 400
        
        # Validar email
        valido, mensagem = validar_email(email)
        if not valido:
            return jsonify({
                'success': False,
                'message': mensagem
            }), 400
        
        # Validar password
        valido, mensagem = validar_password(password)
        if not valido:
            return jsonify({
                'success': False,
                'message': mensagem
            }), 400
        
        # Criar hash da password (PROTEÇÃO: nunca guardar em texto simples)
        password_hash = criar_hash_password(password)
        
        # Chamar stored procedure (PROTEÇÃO SQL INJECTION)
        connection = get_db_connection()
        if not connection:
            return jsonify({
                'success': False,
                'message': 'Erro de conexão à base de dados'
            }), 500
        
        try:
            cursor = connection.cursor()
            
            # Variáveis de output
            args = [username, email, password_hash, 0, '']
            
            # Executar stored procedure
            cursor.callproc('sp_register_user', args)
            
            # Obter resultados
            cursor.execute("SELECT @_sp_register_user_3, @_sp_register_user_4")
            result = cursor.fetchone()
            
            connection.commit()
            cursor.close()
            connection.close()
            
            if result and result[0] == 1:
                return jsonify({
                    'success': True,
                    'message': '✓ Utilizador registado com sucesso!'
                }), 201
            else:
                mensagem_erro = result[1] if result else 'Erro ao registar utilizador'
                return jsonify({
                    'success': False,
                    'message': mensagem_erro
                }), 400
                
        except Error as e:
            if connection:
                connection.close()
            return jsonify({
                'success': False,
                'message': f'Erro: {str(e)}'
            }), 500
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro no servidor: {str(e)}'
        }), 500


@app.route('/api/login', methods=['POST'])
def fazer_login():
    """
    Endpoint para login
    PROTEÇÃO: Stored Procedure + Hash + Rate Limiting
    """
    try:
        # Obter dados
        dados = request.get_json()
        username = sanitizar_input(dados.get('username', ''))
        password = dados.get('password', '')
        
        # Obter IP do cliente
        ip_address = request.remote_addr
        
        # Criar hash da password
        password_hash = criar_hash_password(password)
        
        # Chamar stored procedure de login
        connection = get_db_connection()
        if not connection:
            return jsonify({
                'success': False,
                'message': 'Erro de conexão à base de dados'
            }), 500
        
        try:
            cursor = connection.cursor()
            
            # Executar stored procedure
            args = [username, password_hash, ip_address, 0, '', 0]
            cursor.callproc('sp_login_user', args)
            
            # Obter resultados
            cursor.execute("SELECT @_sp_login_user_3, @_sp_login_user_4, @_sp_login_user_5")
            result = cursor.fetchone()
            
            connection.commit()
            cursor.close()
            connection.close()
            
            if result and result[0] == 1:
                return jsonify({
                    'success': True,
                    'message': f'✓ Bem-vindo, {username}! Login efetuado com sucesso.',
                    'user_id': result[2]
                }), 200
            else:
                mensagem = result[1] if result else 'Username ou password incorretos'
                return jsonify({
                    'success': False,
                    'message': mensagem
                }), 401
                
        except Error as e:
            if connection:
                connection.close()
            return jsonify({
                'success': False,
                'message': 'Erro ao processar login'
            }), 500
        
    except Exception as e:
        return jsonify({
            'success': False,
            'message': f'Erro no servidor: {str(e)}'
        }), 500


@app.route('/api/users', methods=['GET'])
def listar_utilizadores():
    """
    Lista todos os utilizadores (SEM passwords!)
    PROTEÇÃO: Usa view segura que não expõe password_hash
    """
    connection = get_db_connection()
    if not connection:
        return jsonify({
            'success': False,
            'message': 'Erro de conexão'
        }), 500
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        # Usar view segura (sem password_hash)
        cursor.execute("SELECT * FROM vw_users_safe ORDER BY created_at DESC")
        
        users = cursor.fetchall()
        
        cursor.close()
        connection.close()
        
        # Converter datetime para string
        for user in users:
            if user['created_at']:
                user['created_at'] = user['created_at'].isoformat()
            if user['updated_at']:
                user['updated_at'] = user['updated_at'].isoformat()
            if user['last_login']:
                user['last_login'] = user['last_login'].isoformat()
        
        return jsonify({
            'success': True,
            'users': users
        }), 200
        
    except Error as e:
        if connection:
            connection.close()
        return jsonify({
            'success': False,
            'message': f'Erro: {str(e)}'
        }), 500


@app.route('/api/logs', methods=['GET'])
def listar_logs():
    """
    Lista logs de segurança recentes
    """
    connection = get_db_connection()
    if not connection:
        return jsonify({
            'success': False,
            'message': 'Erro de conexão'
        }), 500
    
    try:
        cursor = connection.cursor(dictionary=True)
        
        cursor.execute("SELECT * FROM vw_security_logs_recent LIMIT 50")
        
        logs = cursor.fetchall()
        
        cursor.close()
        connection.close()
        
        # Converter datetime
        for log in logs:
            if log['created_at']:
                log['created_at'] = log['created_at'].isoformat()
        
        return jsonify({
            'success': True,
            'logs': logs
        }), 200
        
    except Error as e:
        if connection:
            connection.close()
        return jsonify({
            'success': False,
            'message': f'Erro: {str(e)}'
        }), 500


@app.route('/api/test-db', methods=['GET'])
def testar_conexao():
    """
    Testa conexão à base de dados
    """
    connection = get_db_connection()
    
    if connection:
        try:
            cursor = connection.cursor()
            cursor.execute("SELECT VERSION()")
            version = cursor.fetchone()
            cursor.close()
            connection.close()
            
            return jsonify({
                'success': True,
                'message': 'Conexão bem-sucedida!',
                'mysql_version': version[0]
            }), 200
        except Error as e:
            return jsonify({
                'success': False,
                'message': f'Erro: {str(e)}'
            }), 500
    else:
        return jsonify({
            'success': False,
            'message': 'Não foi possível conectar à base de dados'
        }), 500


# ============================================================================
# INICIALIZAÇÃO
# ============================================================================

if __name__ == '__main__':
    print("=" * 70)
    print("🔒 SISTEMA DE LOGIN SEGURO - UFCD 10795")
    print("=" * 70)
    print("\n📋 Medidas de Segurança Implementadas:")
    print("  ✓ Validação completa de inputs")
    print("  ✓ Sanitização contra XSS")
    print("  ✓ Proteção SQL Injection (Prepared Statements)")
    print("  ✓ Passwords com hash SHA-256")
    print("  ✓ Rate limiting (bloqueio após 5 tentativas)")
    print("  ✓ Logs de segurança")
    print("\n🌐 Servidor a iniciar...")
    print("📍 URL: http://localhost:5000")
    print("=" * 70)
    print("\n⚙️  Rotas disponíveis:")
    print("  GET  /                - Página principal")
    print("  POST /api/register    - Registar utilizador")
    print("  POST /api/login       - Fazer login")
    print("  GET  /api/users       - Listar utilizadores")
    print("  GET  /api/logs        - Ver logs")
    print("  GET  /api/test-db     - Testar conexão DB")
    print("=" * 70)
    print("\n🚀 Pressiona CTRL+C para parar o servidor\n")
    
    # Iniciar servidor
    app.run(debug=True, host='0.0.0.0', port=5000)