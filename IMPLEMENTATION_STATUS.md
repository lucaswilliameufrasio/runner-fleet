# Estado de implementação

Pacote: Runner Fleet 0.1.0. Código implementado e binários Linux x64/ARM64 gerados.

## Evidência local

- Testes Go cobrem autenticação/setup/CSRF/recuperação; TOTP e criptografia; CA/CSR; mTLS em servidor TLS de teste; revogação e enrollment single-use; webhooks; scheduler/reservas concorrentes; agente idempotente e recuperação; backups; SSH; validação Spot, adapter EC2 fake, bootstrap IMDSv2 e vínculo do enrollment ao instance ID; falha de Docker sem liberar capacidade.
- `go test ./...`, `go test -race ./...`, `go vet ./...`: executados; resultado final registrado em `docs/VALIDATION.txt`.
- `npm run check`: zero erros/avisos; build SvelteKit estático concluído.
- Cross-compile de servidor e agente Linux amd64/arm64; manifestos SHA256 assinados Ed25519 e verificados.
- Smoke HTTP com o binário real passou: assets da SPA/CSP, setup, login, CSRF, reautenticação, cadastro, exportação e logout.
- Teste de ciclo de vida do agente usa fake Docker controlado para verificar idempotência/segredos/quotas. Isso não é execução Docker real.

## Fases

| Fase | Código entregue | Validação externa necessária |
|---|---|---|
| 0 — riscos | Fixtures, testes e ADRs de integração, capacidade, canal e lifecycle | Job GitHub real x64/ARM64, Docker/cgroups na distro, comparação prática com Scale Sets |
| 1 — descoberta | App, paginação, análise YAML, reutilizáveis, tentativas, histórico/runners/grupos, painel | Contas reais e permissões/plano GitHub |
| 2 — máquinas | Enrollment/SSH, CA/mTLS, doctor, systemd, rotação, revogação, release assinada | SSH privado real, rootless Docker e proxy/certificados públicos |
| 3 — execução | Pools/reservas/horários, runner efêmero, sidecar Docker opt-in, reconciliação, drain | Workloads/canários e falhas reais na infraestrutura |
| 4 — migração | Patch validado/preview/SHA/PR, métricas e estimativa | PR e canário em repo autorizado |
| 5 — operação | Backups/retention/restore, alertas, auditoria/export, updates e deploy | S3/R2/Discord real, update de máquina e restore do recovery kit |
| 6 — AWS Spot | Configuração Spot por pool; adapter EC2; launches persistidos/idempotentes; enrollment vinculado; scale-out/idle scale-in; fallback On-Demand explícito; detecção IMDSv2 e drain | IAM/AMI/subnets reais, Spot capacity/fallback, canário de interrupção e comportamento de cobrança |

## Limitações explícitas

1. Ambiente de desenvolvimento não tem daemon Docker, máquinas ARM64 ou credenciais GitHub/S3/SSH/Discord. Não registramos runners, enviamos PRs ou conectamos serviços de produção. Guia `docs/CANARY.md` cobre a homologação.
2. Teste E2E de navegador foi escrito, mas Chromium não pôde iniciar aqui: criação do socket Unix de ProcessSingleton é bloqueada pelo ambiente. Não declarar revisão visual/E2E de navegador aprovada. Build e checagem estática passaram; CSP tem teste HTTP específico.
3. Disk budget é reserva e monitoramento de espaço, não quota rígida por job. Cache local compartilhado não é implementado; actions/cache pode continuar no workflow.
4. Docker sidecar foi implementado com volumes exclusivos e rede compartilhada, mas sua compatibilidade real não foi exercitada. Exige máquina dedicada e código confiável; VM/microVM para código hostil fica no roadmap.
5. Indisponibilidade total do control plane impede retirada imediata de runners registrados. Eles podem aceitar jobs existentes enquanto o GitHub ainda os considera elegíveis. Reservas permanecem e provisionamento novo é suspenso.
6. Retry de scan é idempotente, com checkpoint por página de repositórios. Mudanças na ordem/lista de repos durante interrupção podem exigir um novo scan completo; snapshots antigos preservam data/ref de observação. Expressões complexas/matrizes include/exclude ficam explícitas como não resolvidas ou exigem revisão manual.
7. Estimativa de custo usa tarifa Linux informada pelo admin e duração/arredondamento observado. Não é fatura; não soma storage, artifacts, cache, hardware, energia ou tarifa de outros sistemas. Concorrência é a observada na janela coberta.
8. Segurança de logs é best-effort; logs de Actions podem conter dados colocados pelo próprio workflow. Repositórios públicos/forks não são ativados automaticamente.
9. Single-admin e SQLite single-server na V1. Multiusuário/RBAC, HA, API/MCP, novos sistemas operacionais e isolamento por VM ficam no roadmap aprovado.
10. Não existe API para escolher a máquina que receberá um job específico; o GitHub atribui jobs compatíveis. Label padrão hospedada não é garantia de substituição/economia.
11. Spot foi testado localmente apenas contra EC2 fake. Não foi feita chamada AWS; credenciais/permissões, custo, disponibilidade, scripts de bootstrap e interrupção real ainda exigem o canário autorizado em `docs/CANARY.md`.

A implementação entregue não deve ser descrita como homologada em produção. Complete o canário na infraestrutura alvo antes de usar para builds sensíveis.
