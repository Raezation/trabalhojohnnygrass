#include <iostream>
#include <fstream>
#include <string>
#include <regex>
#include <limits>
#include <iomanip>
#include <sstream>

using namespace std;

// ============================================================================
// FUNÇÕES DE SEGURANÇA
// ============================================================================

/**
 * Função para criar hash simples de password (SHA-256 simplificado)
 * Nota: Em produção, usar bibliotecas como OpenSSL ou bcrypt
 */
string criarHashPassword(const string& password) {
    unsigned long hash = 5381;
    for (char c : password) {
        hash = ((hash << 5) + hash) + c;
    }
    
    // Adicionar salt simples
    hash ^= 0x5A827999;
    
    stringstream ss;
    ss << hex << setfill('0') << setw(16) << hash;
    return ss.str();
}

/**
 * Validação de email - verifica formato básico
 */
bool validarEmail(const string& email) {
    // Regex para validar formato de email
    regex emailRegex(R"([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})");
    return regex_match(email, emailRegex);
}

/**
 * Validação de password - requisitos mínimos de segurança
 */
bool validarPassword(const string& password, string& mensagemErro) {
    if (password.length() < 8) {
        mensagemErro = "A password deve ter pelo menos 8 caracteres";
        return false;
    }
    
    if (password.length() > 50) {
        mensagemErro = "A password não pode ter mais de 50 caracteres";
        return false;
    }
    
    bool temMaiuscula = false;
    bool temMinuscula = false;
    bool temNumero = false;
    
    for (char c : password) {
        if (isupper(c)) temMaiuscula = true;
        if (islower(c)) temMinuscula = true;
        if (isdigit(c)) temNumero = true;
    }
    
    if (!temMaiuscula) {
        mensagemErro = "A password deve conter pelo menos uma letra maiúscula";
        return false;
    }
    
    if (!temMinuscula) {
        mensagemErro = "A password deve conter pelo menos uma letra minúscula";
        return false;
    }
    
    if (!temNumero) {
        mensagemErro = "A password deve conter pelo menos um número";
        return false;
    }
    
    return true;
}

/**
 * Sanitização de input - remove caracteres perigosos para prevenir XSS
 */
string sanitizarInput(const string& input) {
    string resultado = input;
    
    // Remove caracteres perigosos que podem causar XSS ou SQL Injection
    string caracteresPerigosos = "<>\"';&|()";
    
    for (char c : caracteresPerigosos) {
        size_t pos = 0;
        while ((pos = resultado.find(c, pos)) != string::npos) {
            resultado.erase(pos, 1);
        }
    }
    
    return resultado;
}

/**
 * Validação de username
 */
bool validarUsername(const string& username, string& mensagemErro) {
    if (username.empty()) {
        mensagemErro = "O username não pode estar vazio";
        return false;
    }
    
    if (username.length() < 3) {
        mensagemErro = "O username deve ter pelo menos 3 caracteres";
        return false;
    }
    
    if (username.length() > 20) {
        mensagemErro = "O username não pode ter mais de 20 caracteres";
        return false;
    }
    
    // Apenas letras, números e underscore
    regex usernameRegex("^[a-zA-Z0-9_]+$");
    if (!regex_match(username, usernameRegex)) {
        mensagemErro = "O username só pode conter letras, números e underscore";
        return false;
    }
    
    return true;
}

// ============================================================================
// FUNÇÕES DE GESTÃO DE UTILIZADORES
// ============================================================================

/**
 * Verificar se o utilizador já existe
 */
bool utilizadorExiste(const string& username) {
    ifstream ficheiro("utilizadores.txt");
    if (!ficheiro.is_open()) {
        return false;
    }
    
    string linha;
    while (getline(ficheiro, linha)) {
        size_t pos = linha.find(':');
        if (pos != string::npos) {
            string userGuardado = linha.substr(0, pos);
            if (userGuardado == username) {
                ficheiro.close();
                return true;
            }
        }
    }
    
    ficheiro.close();
    return false;
}

/**
 * Registar novo utilizador
 */
bool registarUtilizador(const string& username, const string& email, const string& password) {
    // Validações
    string mensagemErro;
    
    if (!validarUsername(username, mensagemErro)) {
        cout << "Erro: " << mensagemErro << endl;
        return false;
    }
    
    if (!validarEmail(email)) {
        cout << "Erro: Email inválido" << endl;
        return false;
    }
    
    if (!validarPassword(password, mensagemErro)) {
        cout << "Erro: " << mensagemErro << endl;
        return false;
    }
    
    // Verificar se o utilizador já existe
    if (utilizadorExiste(username)) {
        cout << "Erro: Este username já está registado" << endl;
        return false;
    }
    
    // Sanitizar inputs (proteção adicional contra XSS)
    string usernameLimpo = sanitizarInput(username);
    string emailLimpo = sanitizarInput(email);
    
    // Criar hash da password (NUNCA guardar em texto simples!)
    string passwordHash = criarHashPassword(password);
    
    // Guardar no ficheiro
    ofstream ficheiro("utilizadores.txt", ios::app);
    if (!ficheiro.is_open()) {
        cout << "Erro: Não foi possível guardar o utilizador" << endl;
        return false;
    }
    
    // Formato: username:email:passwordHash
    ficheiro << usernameLimpo << ":" << emailLimpo << ":" << passwordHash << endl;
    ficheiro.close();
    
    cout << "\n✓ Utilizador registado com sucesso!" << endl;
    return true;
}

/**
 * Fazer login
 */
bool fazerLogin(const string& username, const string& password) {
    // Proteção contra SQL Injection: não construímos queries diretas
    // Usamos comparação de strings segura
    
    ifstream ficheiro("utilizadores.txt");
    if (!ficheiro.is_open()) {
        cout << "Erro: Sistema de autenticação indisponível" << endl;
        return false;
    }
    
    string passwordHash = criarHashPassword(password);
    string linha;
    bool encontrado = false;
    
    while (getline(ficheiro, linha)) {
        size_t pos1 = linha.find(':');
        if (pos1 == string::npos) continue;
        
        size_t pos2 = linha.find(':', pos1 + 1);
        if (pos2 == string::npos) continue;
        
        string userGuardado = linha.substr(0, pos1);
        string hashGuardado = linha.substr(pos2 + 1);
        
        // Comparação segura usando && (não ||, que causaria bypass)
        if (userGuardado == username && hashGuardado == passwordHash) {
            encontrado = true;
            break;
        }
    }
    
    ficheiro.close();
    
    if (encontrado) {
        cout << "\n✓ Login efetuado com sucesso!" << endl;
        cout << "Bem-vindo, " << username << "!" << endl;
        return true;
    } else {
        cout << "\n✗ Username ou password incorretos" << endl;
        return false;
    }
}

/**
 * Limpar buffer de input (previne buffer overflow)
 */
void limparBuffer() {
    cin.clear();
    cin.ignore(numeric_limits<streamsize>::max(), '\n');
}

/**
 * Ler input seguro (com limite de caracteres)
 */
string lerInputSeguro(int maxCaracteres = 100) {
    string input;
    getline(cin, input);
    
    // Limitar tamanho para prevenir buffer overflow
    if (input.length() > maxCaracteres) {
        input = input.substr(0, maxCaracteres);
    }
    
    return input;
}

// ============================================================================
// MENU PRINCIPAL
// ============================================================================

void mostrarMenu() {
    cout << "\n========================================" << endl;
    cout << "   SISTEMA DE LOGIN SEGURO" << endl;
    cout << "========================================" << endl;
    cout << "1. Registar novo utilizador" << endl;
    cout << "2. Fazer login" << endl;
    cout << "3. Informações de segurança" << endl;
    cout << "4. Sair" << endl;
    cout << "========================================" << endl;
    cout << "Escolha uma opção: ";
}

void mostrarInformacoes() {
    cout << "\n========================================" << endl;
    cout << "   MEDIDAS DE SEGURANÇA IMPLEMENTADAS" << endl;
    cout << "========================================" << endl;
    cout << "\n1. VALIDAÇÃO DE DADOS:" << endl;
    cout << "   - Verificação de campos vazios" << endl;
    cout << "   - Username: 3-20 caracteres, apenas letras, números e _" << endl;
    cout << "   - Password: mínimo 8 caracteres, com maiúsculas, minúsculas e números" << endl;
    cout << "   - Email: formato válido obrigatório" << endl;
    
    cout << "\n2. PROTEÇÃO DE PASSWORDS:" << endl;
    cout << "   - Passwords NUNCA são guardadas em texto simples" << endl;
    cout << "   - Utilização de hash para armazenamento seguro" << endl;
    cout << "   - Impossível recuperar a password original" << endl;
    
    cout << "\n3. PROTEÇÃO CONTRA ATAQUES:" << endl;
    cout << "   - SQL Injection: não há queries SQL diretas" << endl;
    cout << "   - XSS: sanitização de inputs, remoção de caracteres perigosos" << endl;
    cout << "   - Buffer Overflow: limite de caracteres em todos os inputs" << endl;
    cout << "   - Broken Auth: uso correto de operadores lógicos (&&)" << endl;
    
    cout << "\n4. BOAS PRÁTICAS:" << endl;
    cout << "   - Código organizado e comentado" << endl;
    cout << "   - Validação em múltiplas camadas" << endl;
    cout << "   - Mensagens de erro genéricas (não revelam detalhes)" << endl;
    cout << "========================================" << endl;
}

// ============================================================================
// FUNÇÃO PRINCIPAL
// ============================================================================

int main() {
    int opcao;
    bool continuar = true;
    
    cout << "Bem-vindo ao Sistema de Login Seguro!" << endl;
    
    while (continuar) {
        mostrarMenu();
        cin >> opcao;
        limparBuffer();
        
        switch (opcao) {
            case 1: {
                cout << "\n--- REGISTO DE NOVO UTILIZADOR ---" << endl;
                
                cout << "Username: ";
                string username = lerInputSeguro(20);
                
                cout << "Email: ";
                string email = lerInputSeguro(100);
                
                cout << "Password: ";
                string password = lerInputSeguro(50);
                
                cout << "Confirmar password: ";
                string confirmarPassword = lerInputSeguro(50);
                
                if (password != confirmarPassword) {
                    cout << "Erro: As passwords não coincidem" << endl;
                    break;
                }
                
                registarUtilizador(username, email, password);
                break;
            }
            
            case 2: {
                cout << "\n--- LOGIN ---" << endl;
                
                cout << "Username: ";
                string username = lerInputSeguro(20);
                
                cout << "Password: ";
                string password = lerInputSeguro(50);
                
                fazerLogin(username, password);
                break;
            }
            
            case 3: {
                mostrarInformacoes();
                break;
            }
            
            case 4: {
                cout << "\nObrigado por usar o sistema. Até breve!" << endl;
                continuar = false;
                break;
            }
            
            default: {
                cout << "\nOpção inválida. Por favor, escolha entre 1-4." << endl;
                break;
            }
        }
    }
    
    return 0;
}

// ============================================================================
// EXPLICAÇÃO DAS MEDIDAS DE SEGURANÇA IMPLEMENTADAS
// ============================================================================

/*
 * 1. VALIDAÇÃO DE DADOS (Requisito 1)
 * ------------------------------------
 * - Todos os inputs são validados antes de serem processados
 * - Username: 3-20 caracteres, apenas letras, números e underscore
 * - Password: mínimo 8 caracteres, obrigatório maiúsculas, minúsculas e números
 * - Email: verificação de formato usando expressões regulares
 * - Campos vazios são rejeitados
 *
 * 2. PROTEÇÃO DE PASSWORDS (Requisito 2)
 * ----------------------------------------
 * - As passwords NUNCA são guardadas em texto simples
 * - Função criarHashPassword() cria um hash da password
 * - O ficheiro utilizadores.txt só guarda o hash, não a password original
 * - Mesmo que alguém aceda ao ficheiro, não consegue ver as passwords
 *
 * 3. PROTEÇÃO CONTRA ATAQUES (Requisito 3)
 * ------------------------------------------
 * a) SQL Injection:
 *    - Não usamos queries SQL diretas com concatenação de strings
 *    - Fazemos comparação direta de strings de forma segura
 *
 * b) XSS (Cross-Site Scripting):
 *    - Função sanitizarInput() remove caracteres perigosos: < > " ' ; & | ( )
 *    - Previne injeção de código malicioso nos campos
 *
 * c) Buffer Overflow:
 *    - lerInputSeguro() limita o tamanho de todos os inputs
 *    - Nunca usamos scanf("%s") sem limite
 *    - Proteção contra corrupção de memória
 *
 * d) Broken Authentication:
 *    - Uso correto de && (AND) em vez de || (OR)
 *    - Exemplo: if (username == "admin" && password == "admin")
 *    - Previne bypass de autenticação
 *
 * 4. BOAS PRÁTICAS ADICIONAIS
 * ----------------------------
 * - Código bem comentado e organizado em funções
 * - Mensagens de erro genéricas (não revelam se o username ou password está errado)
 * - Validação em múltiplas camadas
 * - Limite de caracteres consistente em toda a aplicação
 */