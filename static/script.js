// Estado da aplicação
let tokenAtual = '';      // Token obtido no login (exibido)
let tokenAtivo = '';      // Token que foi colado e ativado (usado nas requisições)
let roleAtiva = '';

// Elementos do DOM
const btnLogin = document.getElementById('btnLogin');
const btnActivateToken = document.getElementById('btnActivateToken');
const btnPublicData = document.getElementById('btnPublicData');
const btnSensitiveData = document.getElementById('btnSensitiveData');

const loginResult = document.getElementById('loginResult');
const tokenDisplay = document.getElementById('tokenDisplay');
const roleDisplay = document.getElementById('roleDisplay');
const tokenInput = document.getElementById('tokenInput');
const tokenStatus = document.getElementById('tokenStatus');

const dataResult = document.getElementById('dataResult');
const dataDisplay = document.getElementById('dataDisplay');

// Função para mostrar resultado formatado
function mostrarResultado(titulo, conteudo) {
    dataResult.classList.remove('hidden');
    if (typeof conteudo === 'object') {
        dataDisplay.textContent = JSON.stringify(conteudo, null, 2);
    } else {
        dataDisplay.textContent = conteudo;
    }
}

// Função para lidar com erros de API
function handleApiError(error) {
    console.error('Erro:', error);
    mostrarResultado('Erro', `❌ ${error.message || 'Falha na requisição'}`);
}

// Atualiza status visual do token
function atualizarStatusToken(sucesso, mensagem) {
    tokenStatus.classList.remove('hidden', 'success', 'error');
    tokenStatus.classList.add(sucesso ? 'success' : 'error');
    tokenStatus.textContent = mensagem;
}

// Login
btnLogin.addEventListener('click', async () => {
    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    try {
        const response = await fetch('/login', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ username, password }),
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.erro || 'Credenciais inválidas');
        }

        const data = await response.json();
        tokenAtual = data.token_acesso;
        const role = data.role;

        // Exibe o token e a role
        tokenDisplay.value = tokenAtual;
        roleDisplay.textContent = role.toUpperCase();
        loginResult.classList.remove('hidden');

        // Limpa campos de ativação anteriores
        tokenInput.value = '';
        tokenAtivo = '';
        btnPublicData.disabled = true;
        btnSensitiveData.disabled = true;
        tokenStatus.classList.add('hidden');

        mostrarResultado('Login', { mensagem: data.mensagem, role: role });
    } catch (error) {
        handleApiError(error);
    }
});

// Ativar Token (validação real via backend)
btnActivateToken.addEventListener('click', async () => {
    const tokenColado = tokenInput.value.trim();
    
    if (!tokenColado) {
        atualizarStatusToken(false, '❌ Por favor, cole um token JWT.');
        btnPublicData.disabled = true;
        btnSensitiveData.disabled = true;
        return;
    }

    try {
        const response = await fetch('/validar-token', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({ token: tokenColado }),
        });

        const data = await response.json();

        if (!response.ok || !data.valido) {
            throw new Error(data.erro || 'Token inválido');
        }

        // Token válido! Ativa os botões
        tokenAtivo = tokenColado;
        roleAtiva = data.role;
        atualizarStatusToken(true, `✅ Token válido! Usuário: ${data.username} | Role: ${data.role.toUpperCase()}`);
        
        btnPublicData.disabled = false;
        btnSensitiveData.disabled = false;

    } catch (error) {
        atualizarStatusToken(false, `❌ ${error.message}`);
        btnPublicData.disabled = true;
        btnSensitiveData.disabled = true;
    }
});

// Consultar dados operacionais (públicos)
btnPublicData.addEventListener('click', async () => {
    if (!tokenAtivo) {
        mostrarResultado('Erro', '❌ Nenhum token ativo. Cole e ative um token primeiro.');
        return;
    }

    try {
        const response = await fetch('/consulta-dados', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${tokenAtivo}`,
            },
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.erro || 'Erro ao consultar dados');
        }

        const data = await response.json();
        mostrarResultado('Dados Operacionais', data);
    } catch (error) {
        handleApiError(error);
    }
});

// Consultar dados sensíveis (com DLP)
btnSensitiveData.addEventListener('click', async () => {
    if (!tokenAtivo) {
        mostrarResultado('Erro', '❌ Nenhum token ativo. Cole e ative um token primeiro.');
        return;
    }

    try {
        const response = await fetch('/dados-sensiveis', {
            method: 'GET',
            headers: {
                'Authorization': `Bearer ${tokenAtivo}`,
            },
        });

        if (!response.ok) {
            const err = await response.json();
            throw new Error(err.erro || 'Erro ao consultar dados sensíveis');
        }

        const data = await response.json();
        mostrarResultado('Dados Sensíveis (com Proteção DLP)', data);
    } catch (error) {
        handleApiError(error);
    }
});