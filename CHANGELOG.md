# Changelog

## [1.15.6] - 2026-07-11

### Segurança
- Rotas de debug e diagnóstico desativadas no ambiente de produção.
- Rotas de diagnóstico restritas ao perfil super_admin no ambiente DEV.
- Removida a rota pública de teste de autenticação.
- Sessões configuradas com chaves exclusivas para DEV e produção.
- Cookie de sessão renomeado para `inmap.sid`.
- Cookies configurados com HttpOnly, SameSite=Lax e Secure em produção.
- Removida a identificação automática do Express.
- Criado middleware central de autorização por permissão.
- Adicionado registro de tentativas de acesso negado com usuário, rota, IP, navegador e permissão exigida.
- Protegidas as rotas de administração de usuários.
- Impedida a auto-inativação de usuários.
- Impedida a alteração das próprias permissões.
- Protegido o perfil super_admin contra alterações por usuários comuns.
- Protegidas as rotas de metas, regras de receita e importação Churn.
- Protegidas as rotas que modificam O.S. no IXC.
- Protegidas as rotas de finalização de pagamento de ativação.
- Protegidas as sincronizações de Link Dedicado.
- Implementado rate limiting no login interno e no portal do assinante.
- Limitado o tamanho máximo dos corpos JSON recebidos pelo servidor.
- Iniciada a padronização de respostas de erro sem exposição de detalhes internos.

### Interface
- Substituído o alerta nativo do login por notificação visual.
- Adicionado tratamento para falhas de conexão no login.
- Adicionada identificação do Dashboard Comercial InMap, versão e autoria na tela de login.
- Adicionadas novas permissões administrativas para operações críticas.

## 2026-07-09
- Atualização estrutural do dashboard IXC/InMap.
- Inclusão de login e controle de usuários.
- Inclusão de permissões por perfil.
- Evolução do Ranking BackOffice.
- Inclusão de penalidades automáticas e manuais.
- Inclusão de página de atualizações.
- Inclusão de assets visuais do login.

## [1.16.0] - 2026-07-15

### Adicionado
- Integração com Piperun para oportunidades perdidas.
- Sincronização automática da Piperun.
- Tabela consolidada `inviabilidades_mapa`.
- Sincronização automática Piperun → mapa de inviabilidade.
- Módulo CRM com visão geral, oportunidades, vendedores e localização.
- Mapa de inviabilidade com filtros por categoria, cidade, vendedor e origem.
- Controle de acesso pela permissão `ver_crm_piperun`.

### Corrigido
- Persistência da tela e da aba do CRM após F5.
- Ocultação de menus sem permissão.
- Reinicialização do Leaflet após troca de período.
