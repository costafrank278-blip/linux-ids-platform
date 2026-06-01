# Linux IDS Platform 🛡️

Plataforma de Detecção e Análise de Intrusões (IDS) em Sistemas Linux com Dashboard Web em Tempo Real.

## 📋 Características

- ✅ Monitoramento em tempo real de logs de segurança
- ✅ Detecção automática de ataques (força bruta, port scanning, anomalias)
- ✅ Dashboard web interativo com gráficos e estatísticas
- ✅ API REST para integração
- ✅ Banco de dados para armazenamento de alertas
- ✅ Sistema de notificações
- ✅ Docker ready

## 🚀 Quick Start

```bash
# Clone o repositório
git clone https://github.com/costafrank278-blip/linux-ids-platform.git
cd linux-ids-platform

# Instale as dependências
pip install -r requirements.txt

# Execute o servidor
python backend/app.py

# Acesse em http://localhost:5000
```

## 📁 Estrutura do Projeto

```
linux-ids-platform/
├── logs_collector/      # Coleta de logs em tempo real
├── analysis_engine/     # Motor de análise e detecção
├── backend/            # API REST Flask
├── frontend/           # Dashboard Web
├── tests/              # Testes
├── docs/               # Documentação
└── requirements.txt    # Dependências
```

## 🔧 Componentes

### Coletor de Logs
Monitora `/var/log/auth.log` e `/var/log/syslog` em tempo real

### Motor de Análise
- Detecção de força bruta
- Detecção de port scanning
- Análise de comportamento anormal
- Regras customizáveis

### Dashboard
- Alertas em tempo real
- Estatísticas de ataques
- Timeline de eventos
- Mapa de ameaças

## 📚 Documentação

Ver `/docs` para mais informações.

## 🤝 Contribuições

Contribuições são bem-vindas!

## 📄 Licença

MIT License
