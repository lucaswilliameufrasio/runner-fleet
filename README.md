# Runner Fleet

Central self-hosted para inventariar GitHub Actions e administrar runners Linux em organizações e repositórios pessoais. Servidor e agente em Go, painel SvelteKit estático, SQLite. Um administrador; múltiplos usuários ficam no roadmap.

## O que está implementado

- Setup único, senha Argon2id, sessões/CSRF, TOTP, códigos de recuperação e reautenticação.
- GitHub App: instalações, repositórios, YAMLs, matrizes literais, workflows reutilizáveis, histórico/tentativas, runners e grupos com acesso selecionado.
- Cadastro por comando/SSH privado; certificados individuais; WebSocket mTLS de saída, rotação e revogação.
- Pools por escopo, budgets globais, pesos, horários e limites por organização. Reservas duráveis incluem runners ociosos.
- Containers efêmeros e runners persistentes no host. O pool escolhe imagem por digest ou o runner oficial como serviço systemd. Docker rootless fica no modo container; sidecar Docker continua opt-in em máquina dedicada. Reconciliação e drain valem para os dois.
- Capacidade nas máquinas cadastradas e, opcionalmente, workers EC2 Spot. Spot é uma fonte de máquina, não o único tipo de runner.
- Painel responsivo, histórico, motivos de fila, métricas/estimativas, alertas/webhooks, auditoria, exportação.
- Dry-run e PR de migração com validação de SHA e alteração restrita de destinos estáticos.
- Snapshot online SQLite, criptografia Argon2id + AES-GCM, backup local/S3/R2, agendamento, retenção e restore.
- Atualização de agente com manifesto assinado, verificação de digest e cópia da versão anterior.

Veja `IMPLEMENTATION_STATUS.md` para a evidência e os limites de validação. A compilação ARM64 não equivale à homologação em máquina ARM64. Integrações externas exigem seu canário antes de produção.

## Iniciar com os binários da release

`dist/` está no `.gitignore`. `scripts/release.sh` gera aí o servidor, os agentes e a assinatura. Um clone não traz esses arquivos. Para executar sem compilar, use uma release já gerada e escolha a arquitetura correta.

```sh
chmod +x dist/runner-fleet-server-linux-amd64
mkdir -p data
./dist/runner-fleet-server-linux-amd64 setup-code --data ./data
./dist/runner-fleet-server-linux-amd64 serve \
  --data ./data --web ./web/build --listen 127.0.0.1:8080 \
  --origin https://fleet.example.com \
  --agent-url wss://agents.example.com/agent \
  --agent-listen 127.0.0.1:8443 \
  --tls-cert /etc/runner-fleet/tls/fullchain.pem \
  --tls-key /etc/runner-fleet/tls/privkey.pem
```

Configure o proxy HTTPS conforme `deploy/nginx-sni.conf`. Os dois hostnames usam a porta pública 443; o endpoint do agente recebe TLS intacto e valida os certificados no Go. Certificado público deve incluir `agents.example.com`. O painel é servido por nginx; nunca exponha o HTTP 8080 diretamente em produção.

Abra `/setup`, use o código (30 minutos) e crie o admin. `/setup` e outras rotas do painel recebem o fallback da SPA. `--dev` apenas para HTTP no localhost; não use em produção.

Se usar systemd, copie binários, painel e arquivos de serviço, crie o usuário `fleet` e dê a ele acesso ao diretório de dados e ao certificado/chave TLS. `deploy/compose.yml` é a alternativa de produção: a imagem roda como UID 10001, filesystem somente leitura, sem capabilities e com portas publicadas apenas em loopback para o proxy HTTPS. Prepare `deploy/data` com UID 10001 e arquivos TLS legíveis por esse UID. A configuração exige origem/público corretos e não precisa de credenciais ou chamadas ao GitHub para build/configuração:

```sh
export RF_ORIGIN=https://fleet.example.com
export RF_AGENT_URL=wss://agents.example.com/agent
docker compose -f deploy/compose.yml build
docker compose -f deploy/compose.yml run --rm fleet setup-code --data /data
docker compose -f deploy/compose.yml up -d
```

O build requer Docker/BuildKit, acesso aos registries das imagens-base, pacotes npm (via pnpm) e módulos Go; não requer GitHub App, token ou runner do GitHub. O painel fixa pnpm 12.15.0 em `web/package.json` e aprova somente o build do `esbuild` travado no lockfile. `docker compose ... config --quiet` valida a configuração sem subir serviços. O smoke HTTP pode usar `GET /api/health` em instalação local isolada; testes de integração com a API do GitHub continuam usando fixtures/fakes e não validam permissões, rate limits ou webhooks reais.

O build Docker compila o projeto, mas as releases de agentes assinadas precisam ser publicadas em `web/build/downloads`. Esse diretório também está no `.gitignore` e é preenchido pelo `scripts/release.sh`. Para Compose, monte-o conforme o exemplo de volume no arquivo de configuração.

## Conectar o GitHub

1. Crie uma GitHub App (Settings → Developer settings → GitHub Apps).
2. Homepage: seu painel; webhook: `https://fleet.example.com/api/github/webhook`; segredo com 24+ caracteres.
3. Permissões de repo: Metadata read, Contents read, Actions read. Para runners por repo: Administration write. Para PRs de migração: Contents write, Workflows write e Pull requests write, conforme seu uso.
4. Permissão de organização: Self-hosted runners write para cadastro/grupos. Respeite restrições de sua organização/plano.
5. Eventos: `workflow_job`, installation e installation_repositories.
6. Gere uma chave RSA privada PEM. Em Configurações, reautentique e salve App ID, PEM e segredo.
7. Instale a App nas organizações/conta pessoal selecionando os repositórios desejados. No painel, Atualizar instalações → Executar inventário.

A App não faz login do administrador; autenticação do painel é local. Segredos da App ficam criptografados no banco com `data/master.key` externo ao banco. Inventário parcial mostra lacunas de permissão/rate limit.

Para orgs, crie um grupo restrito pelo painel selecionando repositórios privados. Pools ativos de organização precisam de grupo explícito; o grupo controla acesso no GitHub, não a instalação da App. Repositórios pessoais usam inscrições individuais. A aplicação nunca assume que `ubuntu-latest` vai preferir seu runner.

## Cadastrar máquinas

A máquina precisa de Linux com systemd e HTTPS de saída ao painel, ao agente e ao GitHub. O instalador prepara os pacotes de runtime com apt, rpm ou zypper: Debian, Ubuntu, RHEL e derivados, Fedora, Amazon Linux e SUSE. Pool de container também exige cgroup v2 e Docker rootless. Pool de serviço persistente não usa Docker. x64 e ARM64 são compilados; homologação local está descrita no status.

### Por comando

Reautentique no painel e gere um código de cadastro. Salve-o num arquivo `0600`, sem argumento de processo. O código dura 15 minutos e é consumido uma vez.

```sh
sudo env RF_SERVER=https://fleet.example.com \
  RF_CODE_FILE=/caminho/privado/enrollment-code \
  RF_NAME=build-host sh scripts/install.sh
sudo sh scripts/setup-rootless-docker.sh
```

O primeiro script instala os pacotes de runtime, o agente, o usuário `fleet-agent` e o helper root `runner-fleet-service`. Esse helper cria o usuário `fleet-runner`, sem sudo e fora do grupo `docker`, e registra o runner oficial quando o pool é de serviço. O segundo script configura Docker rootless e só é necessário para pools de container. Ambos precisam de HTTPS externo. Revise o instalador oficial e as políticas de user namespaces/AppArmor da distro. O painel aceita pool de container quando o doctor vê rootless, cgroup v2, driver systemd e limite de memória. Aceita pool de serviço quando o helper está ativo. Pode haver configuração específica da distro; não desative AppArmor globalmente para resolver.

Os downloads são verificados por manifesto Ed25519. O primeiro trust anchor vem do HTTPS do servidor; para bootstrap com chave previamente confiada, forneça `RF_RELEASE_PUBLIC_KEY_FILE`. Updates posteriores usam essa chave persistida.

Também pode copiar o binário assinado manualmente, executar `agent enroll` como usuário do serviço e instalar o serviço systemd. Use `--code-file`, nunca `--code=...`.

### Por SSH privado

O servidor deve alcançar o IP privado/Tailscale. Não precisa de SSH público. Preencha IP literal, usuário, chave temporária, fingerprint SHA256 confiada e nome. A sessão pode ser root, ter `sudo -n`, ou usar `su -` com a senha de root. A chave e a senha ficam só na requisição e não são gravadas no SQLite, na auditoria nem no script remoto.

O bootstrap remoto instala o agente a partir dos downloads do painel. Docker rootless deve estar pronto ou ser instalado depois pelo script próprio. Se não existe caminho de rede privado, use o cadastro por comando.

## Imagens e pools

A imagem contém o runner oficial. Não acompanha ferramentas da imagem `ubuntu-latest` automaticamente. Defina versão e checksums oficiais por arquitetura e publique a imagem:

```sh
docker buildx build --platform linux/amd64,linux/arm64 \
  --build-arg RUNNER_VERSION=VERSAO_VALIDADA \
  --build-arg RUNNER_SHA256_AMD64=CHECKSUM_OFICIAL_X64 \
  --build-arg RUNNER_SHA256_ARM64=CHECKSUM_OFICIAL_ARM64 \
  -f runner/Dockerfile -t registry.example/runner-fleet-base:VERSAO --push runner/
```

Crie perfis Node/Bun, Go, Rust e Docker com `runner/Dockerfile.tools`, `BASE_IMAGE` fixada por digest e `PROFILE=node|go|rust|docker`. Os defaults de versão são explícitos; ajuste conforme seu workflow. Publishe e copie o digest para o pool. Não use `latest` como referência de execução.

### Runner persistente

No pool, escolha execução "serviço". Informe a versão oficial do `actions/runner` e os checksums SHA256 de Linux x64 e ARM64. Não há imagem Docker. O agente pede ao helper root para baixar somente o arquivo publicado em `github.com/actions/runner`, conferir o checksum da arquitetura da máquina e registrar com `config.sh` sem `--ephemeral`. O processo fica no usuário `fleet-runner`. CPU e memória viram `CPUQuota` e `MemoryMax` do systemd. Disco continua orçamento de reserva, não quota rígida. O runner permanece entre jobs. Se a quantidade ociosa passar do mínimo e da fila, o scheduler pede o drain do excedente. O drain espera o GitHub marcar o runner como livre, remove o registro e só então o helper desinstala o serviço. Isso não é fronteira de VM.

### Workers AWS EC2 Spot

Um pool pode incluir máquinas cadastradas, workers EC2 Spot gerenciados pelo Fleet, ou ambos. O scheduler cria capacidade cloud conforme `min`, jobs compatíveis em fila, `max`, limites globais e slots por máquina; as instâncias sem runners/jobs são encerradas após o período ocioso e drain do runner. Os lançamentos ficam persistidos e reconciliados por client token e tags antes de repetir uma chamada EC2 ambígua.

Na configuração do pool, selecione região, AMI, bootstrap apt/rpm/zypper ou AMI pré-preparada, subnets, security groups, tipos Spot permitidos, máquinas máximas, slots e volume raiz. Fallback On-Demand fica desligado por padrão; para habilitar, configure uma lista separada de tipos e um atraso. O fallback só ocorre depois de erro AWS conhecido de falta/limite de capacidade Spot, não por erro de autenticação, rede ou configuração. Alterar/ativar a configuração AWS exige reautenticação. Limite o `max` do pool e a IAM policy: fallback On-Demand pode aumentar a tarifa.

O processo do servidor usa a cadeia padrão de credenciais AWS do SDK (role de instância, web identity, profile/config, conforme o ambiente); chaves não são enviadas ao navegador nem guardadas no SQLite. O operador deve fornecer IAM para `ec2:RunInstances`, `ec2:DescribeInstances`, `ec2:DescribeImages`, `ec2:DescribeInstanceTypes`, `ec2:TerminateInstances`, `ec2:CreateTags` e `iam:PassRole` apenas para o instance profile escolhido. O Fleet não cria VPC, subnets, security groups, AMIs ou roles. A instância precisa de egress HTTPS ao Fleet e GitHub. O modo bootstrap executa o mesmo `install.sh`: pacotes de runtime, agente e helper de serviço. Em seguida instala Docker rootless, necessário para pool de container. Depende dos repositórios da distro e do instalador oficial.

O bootstrap usa um código de enrollment de uso único e curta duração em user-data, valida o instance ID recebido via IMDSv2 contra o lançamento persistido, e elimina o código após enrollment. Restrinja quem pode ler user-data/metadata e não o inclua em logs. A AMI pré-configurada de pool container deve ter systemd, cgroup v2 e Docker rootless funcional para `fleet-agent`. A de pool de serviço deve ter o helper `runner-fleet-service` ativo. O modo bootstrap cobre as famílias apt, rpm e zypper com systemd. Tipos EC2 e AMI são verificados contra a arquitetura do pool e a capacidade real de vCPU/memória antes do registro.

O agente consulta o aviso Spot em IMDSv2, sinaliza a interrupção, impede novas reservas e inicia drain dos runners ociosos. Isso é best-effort: jobs ativos podem ser terminados pela AWS antes de concluir. Reclaim, suspensão do control plane e falhas de rede não têm garantia de preservação/reexecução de jobs. O painel mostra o estado dos launches. Testes locais usam EC2 fake; faça o canário de `docs/CANARY.md` em uma conta/subnets de teste antes de habilitar pools reais.

No painel: configure máquina (slots, CPU, memória, disco, horários), crie pool pausado, selecione instalação/escopo/grupo/labels/execução/máquinas, reconheça workloads confiáveis e execute canário antes de ativar. No container, CPU e memória são limites do runtime, sujeitos ao cgroup da máquina. No serviço, são `CPUQuota` e `MemoryMax`. Disco é budget de reserva + pressão de espaço livre, não quota rígida de filesystem por job.

Docker sidecar usa daemon novo por job, volumes exclusivos para workspace/socket e rede compartilhada com o runner. O socket do Docker do host nunca é montado. Exige máquina dedicada, runtime rootless, imagem Docker daemon por digest e pelo menos 2 CPUs/2 GB por slot. Sidecar é privilegiado dentro do runtime rootless: use somente código confiável. Execute build, push, container actions e service containers de canário na sua distro. Não foi homologado neste ambiente sem Docker.

Labels precisam corresponder a todas as solicitadas. ARM64 não substitui x64. Um runner elegível não significa que o GitHub vai escolher aquela máquina específica.

## Operação

- Drain retira a inscrição ociosa no GitHub antes de encerrar o ambiente. API rejeitando busy mantém a operação pendente. Jobs ativos não são cancelados por rotina.
- Máquina offline mantém reservas. Desconexão do servidor suspende novo provisionamento; runners já registrados podem continuar recebendo trabalho até serem retirados no GitHub. Nenhuma garantia de corte instantâneo durante indisponibilidade total do control plane.
- Reboot reconcilia containers/resíduos. Não reexecuta jobs por conta própria.
- Atualização: drene, espere zero instâncias ativas, reautentique e selecione o diretório HTTPS de release assinada. Agente guarda `.previous`; rollback local após drain usa a versão anterior e restart do serviço. Não há downgrade automático do banco.
- Recursos de replay são idempotentes. Histórico de jobs inclui tentativas de rerun. Polling complementa webhooks.
- Preços por minuto são informados pelo admin; estimativa não considera todos os produtos/tarifas e não substitui billing do GitHub. Public repos/armazenamento são tratados separadamente.

## Backup e recuperação

Configure senha, endpoint/bucket/credenciais S3/R2, intervalo e retenção. Bucket vazio salva em `data/backups`. Snapshot usa `VACUUM INTO` online, sem copiar arquivo WAL aberto. O arquivo `.rfbackup` tem versão, salt, AES-GCM e checksum da imagem SQLite. Defaults da tela: diário/30 dias. API permite outros valores.

Antes de depender do backup, guarde fora do servidor um recovery kit com `master.key`, `identity/ca.pem`, `identity/ca-key.pem`, senha do backup e cópia das credenciais da App. O snapshot criptografado contém dados cifrados que precisam de `master.key`. A chave privada de assinatura de releases, se você gerar novas releases, também deve ter guarda separada.

```sh
RF_BACKUP_PASSWORD_FILE=/arquivo/protegido/password \
  ./dist/runner-fleet-server-linux-amd64 restore \
  --input backup.rfbackup --output /novo/data/fleet.sqlite
# Reponha master.key e identity/ a partir do recovery kit antes de iniciar.
./dist/runner-fleet-server-linux-amd64 invalidate-sessions --data /novo/data
```

Restore recusa destino existente. Suba isolado, reconcilie registros GitHub e máquinas drenadas, só depois retome capacidade. Não existe recuperação sem as chaves/senha.

Perdeu login: `server recover --data ./data`, use o código em Recuperação por código da CLI. Sessões antigas são invalidadas. TOTP é removido nessa recuperação privilegiada; configure novamente.

## Build, testes e releases

```sh
go test ./...
go test -race ./...
go vet ./...
(cd web && corepack pnpm install --frozen-lockfile && corepack pnpm run check && corepack pnpm run build)
go build -buildvcs=false -o bin/server ./cmd/server
go build -buildvcs=false -o bin/agent ./cmd/agent
```

`tests/ui.mjs` testa a interface contra uma instalação local vazia em localhost:8080; requer Playwright/Chromium e `RF_TEST_CODE_FILE`. O script usa dados fictícios. Não aponte para instalação real.

Para novas releases, use o secret manager do ambiente para injetar o conteúdo da chave privada Ed25519 em `RF_SIGNING_KEY` ao executar `scripts/release.sh` (não coloque o valor em comandos, arquivos do repositório ou logs). O script materializa a chave em arquivo temporário com permissões restritas e o remove ao terminar. Use a chave já confiada pelas máquinas ou faça rotação manual de confiança. A chave privada da release do pacote não está distribuída.

Veja `docs/ADR.md`, `docs/CANARY.md` e `IMPLEMENTATION_STATUS.md`. O registro continua só no GitHub. Gitea, múltiplos usuários/RBAC, API/MCP, VM/microVM, Alpine, macOS e Windows ficam no roadmap.
