-- ============================================================================
-- BASE DE DADOS SEGURA - SISTEMA DE LOGIN
-- UFCD 10795 - Segurança de Aplicações
-- ============================================================================

-- Criar base de dados
CREATE DATABASE IF NOT EXISTS sistema_login_seguro
CHARACTER SET utf8mb4
COLLATE utf8mb4_unicode_ci;

USE sistema_login_seguro;

-- ============================================================================
-- TABELA DE UTILIZADORES
-- ============================================================================

CREATE TABLE IF NOT EXISTS users (
    -- Chave primária
    id INT AUTO_INCREMENT PRIMARY KEY,
    
    -- Dados do utilizador
    username VARCHAR(20) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    
    -- Password SEMPRE armazenada como hash (SHA-256, bcrypt, etc.)
    -- NUNCA guardar passwords em texto simples!
    password_hash VARCHAR(255) NOT NULL,
    
    -- Metadados
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    
    -- Estado da conta
    is_active BOOLEAN DEFAULT TRUE,
    login_attempts INT DEFAULT 0,
    locked_until TIMESTAMP NULL,
    
    -- Índices para otimização
    INDEX idx_username (username),
    INDEX idx_email (email),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- TABELA DE LOGS DE SEGURANÇA
-- ============================================================================

CREATE TABLE IF NOT EXISTS security_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    action_type ENUM('login_success', 'login_failed', 'register', 'password_change', 'account_locked') NOT NULL,
    ip_address VARCHAR(45) NULL,
    user_agent TEXT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL,
    INDEX idx_user_id (user_id),
    INDEX idx_action_type (action_type),
    INDEX idx_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- ============================================================================
-- STORED PROCEDURES SEGUROS
-- ============================================================================

-- ---------------------------------------------------------------------------
-- 1. REGISTAR UTILIZADOR (com validações de segurança)
-- ---------------------------------------------------------------------------

DELIMITER //

CREATE PROCEDURE sp_register_user(
    IN p_username VARCHAR(20),
    IN p_email VARCHAR(100),
    IN p_password_hash VARCHAR(255),
    OUT p_result INT,
    OUT p_message VARCHAR(255)
)
BEGIN
    DECLARE v_user_count INT;
    
    -- Iniciar transação
    START TRANSACTION;
    
    -- Validação 1: Username não pode estar vazio
    IF p_username IS NULL OR TRIM(p_username) = '' THEN
        SET p_result = 0;
        SET p_message = 'Username não pode estar vazio';
        ROLLBACK;
        
    -- Validação 2: Username deve ter entre 3 e 20 caracteres
    ELSEIF LENGTH(p_username) < 3 OR LENGTH(p_username) > 20 THEN
        SET p_result = 0;
        SET p_message = 'Username deve ter entre 3 e 20 caracteres';
        ROLLBACK;
        
    -- Validação 3: Email válido
    ELSEIF p_email NOT REGEXP '^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$' THEN
        SET p_result = 0;
        SET p_message = 'Email inválido';
        ROLLBACK;
        
    -- Validação 4: Verificar se username já existe
    ELSEIF EXISTS (SELECT 1 FROM users WHERE username = p_username) THEN
        SET p_result = 0;
        SET p_message = 'Username já está registado';
        ROLLBACK;
        
    -- Validação 5: Verificar se email já existe
    ELSEIF EXISTS (SELECT 1 FROM users WHERE email = p_email) THEN
        SET p_result = 0;
        SET p_message = 'Email já está registado';
        ROLLBACK;
        
    ELSE
        -- Inserir utilizador (PROTEÇÃO: usando parâmetros, não concatenação)
        INSERT INTO users (username, email, password_hash)
        VALUES (p_username, p_email, p_password_hash);
        
        -- Registar log de segurança
        INSERT INTO security_logs (user_id, action_type)
        VALUES (LAST_INSERT_ID(), 'register');
        
        SET p_result = 1;
        SET p_message = 'Utilizador registado com sucesso';
        COMMIT;
    END IF;
    
END //

DELIMITER ;

-- ---------------------------------------------------------------------------
-- 2. LOGIN SEGURO (com proteção contra força bruta)
-- ---------------------------------------------------------------------------

DELIMITER //

CREATE PROCEDURE sp_login_user(
    IN p_username VARCHAR(20),
    IN p_password_hash VARCHAR(255),
    IN p_ip_address VARCHAR(45),
    OUT p_result INT,
    OUT p_message VARCHAR(255),
    OUT p_user_id INT
)
BEGIN
    DECLARE v_stored_hash VARCHAR(255);
    DECLARE v_user_id INT;
    DECLARE v_is_active BOOLEAN;
    DECLARE v_login_attempts INT;
    DECLARE v_locked_until TIMESTAMP;
    
    -- Procurar utilizador (PROTEÇÃO: prepared statement implícito)
    SELECT id, password_hash, is_active, login_attempts, locked_until
    INTO v_user_id, v_stored_hash, v_is_active, v_login_attempts, v_locked_until
    FROM users
    WHERE username = p_username
    LIMIT 1;
    
    -- Verificar se utilizador existe
    IF v_user_id IS NULL THEN
        SET p_result = 0;
        SET p_message = 'Username ou password incorretos';
        SET p_user_id = NULL;
        
        -- Log de tentativa falhada
        INSERT INTO security_logs (action_type, ip_address)
        VALUES ('login_failed', p_ip_address);
        
    -- Verificar se conta está bloqueada
    ELSEIF v_locked_until IS NOT NULL AND v_locked_until > NOW() THEN
        SET p_result = 0;
        SET p_message = 'Conta temporariamente bloqueada. Tente novamente mais tarde.';
        SET p_user_id = NULL;
        
    -- Verificar se conta está ativa
    ELSEIF v_is_active = FALSE THEN
        SET p_result = 0;
        SET p_message = 'Conta desativada. Contacte o suporte.';
        SET p_user_id = NULL;
        
    -- Verificar password (PROTEÇÃO: comparação de hash, não texto simples)
    ELSEIF v_stored_hash = p_password_hash THEN
        -- Login bem-sucedido!
        UPDATE users
        SET last_login = NOW(),
            login_attempts = 0,
            locked_until = NULL
        WHERE id = v_user_id;
        
        -- Log de sucesso
        INSERT INTO security_logs (user_id, action_type, ip_address)
        VALUES (v_user_id, 'login_success', p_ip_address);
        
        SET p_result = 1;
        SET p_message = 'Login efetuado com sucesso';
        SET p_user_id = v_user_id;
        
    ELSE
        -- Password incorreta
        SET v_login_attempts = v_login_attempts + 1;
        
        -- Bloquear conta após 5 tentativas falhadas (proteção força bruta)
        IF v_login_attempts >= 5 THEN
            UPDATE users
            SET login_attempts = v_login_attempts,
                locked_until = DATE_ADD(NOW(), INTERVAL 15 MINUTE)
            WHERE id = v_user_id;
            
            -- Log de bloqueio
            INSERT INTO security_logs (user_id, action_type, ip_address)
            VALUES (v_user_id, 'account_locked', p_ip_address);
            
            SET p_message = 'Conta bloqueada por 15 minutos devido a tentativas falhadas';
        ELSE
            UPDATE users
            SET login_attempts = v_login_attempts
            WHERE id = v_user_id;
            
            SET p_message = 'Username ou password incorretos';
        END IF;
        
        -- Log de tentativa falhada
        INSERT INTO security_logs (user_id, action_type, ip_address)
        VALUES (v_user_id, 'login_failed', p_ip_address);
        
        SET p_result = 0;
        SET p_user_id = NULL;
    END IF;
    
END //

DELIMITER ;

-- ---------------------------------------------------------------------------
-- 3. ALTERAR PASSWORD
-- ---------------------------------------------------------------------------

DELIMITER //

CREATE PROCEDURE sp_change_password(
    IN p_user_id INT,
    IN p_old_password_hash VARCHAR(255),
    IN p_new_password_hash VARCHAR(255),
    OUT p_result INT,
    OUT p_message VARCHAR(255)
)
BEGIN
    DECLARE v_stored_hash VARCHAR(255);
    
    -- Verificar password atual
    SELECT password_hash INTO v_stored_hash
    FROM users
    WHERE id = p_user_id;
    
    IF v_stored_hash IS NULL THEN
        SET p_result = 0;
        SET p_message = 'Utilizador não encontrado';
        
    ELSEIF v_stored_hash != p_old_password_hash THEN
        SET p_result = 0;
        SET p_message = 'Password atual incorreta';
        
    ELSE
        -- Atualizar password
        UPDATE users
        SET password_hash = p_new_password_hash
        WHERE id = p_user_id;
        
        -- Log
        INSERT INTO security_logs (user_id, action_type)
        VALUES (p_user_id, 'password_change');
        
        SET p_result = 1;
        SET p_message = 'Password alterada com sucesso';
    END IF;
    
END //

DELIMITER ;

-- ============================================================================
-- VIEWS SEGURAS
-- ============================================================================

-- View para listar utilizadores (SEM mostrar password_hash)
CREATE OR REPLACE VIEW vw_users_safe AS
SELECT 
    id,
    username,
    email,
    created_at,
    updated_at,
    last_login,
    is_active,
    CASE 
        WHEN locked_until > NOW() THEN 'Bloqueada'
        WHEN is_active = 0 THEN 'Desativada'
        ELSE 'Ativa'
    END as account_status
FROM users;

-- View para logs de segurança recentes
CREATE OR REPLACE VIEW vw_security_logs_recent AS
SELECT 
    l.id,
    u.username,
    l.action_type,
    l.ip_address,
    l.created_at,
    CASE l.action_type
        WHEN 'login_success' THEN '✓ Login bem-sucedido'
        WHEN 'login_failed' THEN '✗ Login falhado'
        WHEN 'register' THEN '📝 Registo'
        WHEN 'password_change' THEN '🔑 Alteração de password'
        WHEN 'account_locked' THEN '🔒 Conta bloqueada'
    END as action_description
FROM security_logs l
LEFT JOIN users u ON l.user_id = u.id
ORDER BY l.created_at DESC
LIMIT 100;

-- ============================================================================
-- DADOS DE DEMONSTRAÇÃO
-- ============================================================================

-- Inserir utilizador de teste
-- Password: Demo123 (em produção, fazer hash no backend)
INSERT INTO users (username, email, password_hash) VALUES
('demo', 'demo@exemplo.pt', 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'),
('admin', 'admin@exemplo.pt', 'admin_hash_aqui'),
('teste', 'teste@exemplo.pt', 'teste_hash_aqui');

-- ============================================================================
-- EXEMPLOS DE USO
-- ============================================================================

-- EXEMPLO 1: Registar utilizador
CALL sp_register_user(
    'joao_silva',
    'joao.silva@email.pt',
    'hash_da_password_aqui',
    @result,
    @message
);
SELECT @result as resultado, @message as mensagem;

-- EXEMPLO 2: Fazer login
CALL sp_login_user(
    'joao_silva',
    'hash_da_password_aqui',
    '192.168.1.100',
    @result,
    @message,
    @user_id
);
SELECT @result as resultado, @message as mensagem, @user_id as user_id;

-- EXEMPLO 3: Alterar password
CALL sp_change_password(
    1, -- user_id
    'hash_password_antiga',
    'hash_password_nova',
    @result,
    @message
);
SELECT @result as resultado, @message as mensagem;

-- EXEMPLO 4: Consultar utilizadores (seguro, sem passwords)
SELECT * FROM vw_users_safe;

-- EXEMPLO 5: Ver logs de segurança
SELECT * FROM vw_security_logs_recent;

-- ============================================================================
-- QUERIES SEGURAS vs INSEGURAS
-- ============================================================================

/*
❌ INSEGURO - SQL INJECTION POSSÍVEL:
--------------------------------------
query = "SELECT * FROM users WHERE username='" + username + "' AND password='" + password + "'";

Ataque: username = admin' OR '1'='1
Resultado: SELECT * FROM users WHERE username='admin' OR '1'='1' AND password='...'
           → Login sem password!


✅ SEGURO - PREPARED STATEMENT:
--------------------------------
PREPARE stmt FROM "SELECT * FROM users WHERE username=? AND password_hash=?";
SET @username = 'admin';
SET @password_hash = 'hash_aqui';
EXECUTE stmt USING @username, @password_hash;

→ Proteção total contra SQL Injection!
→ Os parâmetros são tratados como dados, não como código SQL
*/

-- ============================================================================
-- ÍNDICES PARA PERFORMANCE E SEGURANÇA
-- ============================================================================

-- Índice para procuras rápidas por username (login)
CREATE INDEX idx_username_active ON users(username, is_active);

-- Índice para monitorização de tentativas de login falhadas
CREATE INDEX idx_security_failed_logins ON security_logs(action_type, created_at)
WHERE action_type = 'login_failed';

-- ============================================================================
-- TRIGGERS DE SEGURANÇA
-- ============================================================================

-- Trigger para prevenir eliminação acidental de utilizadores
DELIMITER //

CREATE TRIGGER trg_prevent_delete_users
BEFORE DELETE ON users
FOR EACH ROW
BEGIN
    -- Em vez de eliminar, desativar a conta
    SIGNAL SQLSTATE '45000'
    SET MESSAGE_TEXT = 'Eliminação bloqueada. Use UPDATE para desativar a conta.';
END //

DELIMITER ;

-- ============================================================================
-- FUNÇÕES ÚTEIS
-- ============================================================================

-- Função para contar logins falhados recentes
DELIMITER //

CREATE FUNCTION fn_count_failed_logins(p_username VARCHAR(20), p_minutes INT)
RETURNS INT
DETERMINISTIC
READS SQL DATA
BEGIN
    DECLARE v_count INT;
    
    SELECT COUNT(*)
    INTO v_count
    FROM security_logs l
    JOIN users u ON l.user_id = u.id
    WHERE u.username = p_username
      AND l.action_type = 'login_failed'
      AND l.created_at >= DATE_SUB(NOW(), INTERVAL p_minutes MINUTE);
    
    RETURN v_count;
END //

DELIMITER ;

-- ============================================================================
-- NOTAS DE SEGURANÇA IMPORTANTES
-- ============================================================================

/*
1. NUNCA guardar passwords em texto simples
   → Usar sempre hash (SHA-256, bcrypt, Argon2)

2. SEMPRE usar prepared statements ou stored procedures
   → Previne SQL Injection

3. Validar TODOS os inputs antes de guardar
   → Previne XSS e outros ataques

4. Implementar rate limiting e bloqueio de conta
   → Previne ataques de força bruta

5. Manter logs de todas as ações de segurança
   → Auditoria e deteção de ataques

6. Usar HTTPS em produção
   → Previne man-in-the-middle

7. Implementar 2FA (autenticação de dois fatores)
   → Camada adicional de segurança

8. Fazer backups regulares da base de dados
   → Recuperação em caso de ataque

9. Manter o MySQL atualizado
   → Correções de segurança

10. Usar princípio do menor privilégio
    → Contas da aplicação com permissões mínimas
*/

-- ============================================================================
-- FIM DO SCRIPT
-- ============================================================================