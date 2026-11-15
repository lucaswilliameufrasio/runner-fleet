# Estudo técnico: isolamento doméstico e roteamento

**Estado: proposta para revisão, 2026-11-14.** Pesquisa documental e leitura do código; nenhum backend, regra de firewall, VM ou mecanismo de fallback foi implementado ou validado. Complementa [o plano](PLANO-DESENVOLVIMENTO.md); não altera os ADRs aceitos dos modos existentes.

## Resultado da investigação

O primeiro incremento deve provar uma VM Linux descartável por runner e uma rede cuja proteção pertence ao host, antes de conectá-la a uma organização. O caminho recomendado para o **protótipo**, sujeito a medição e revisão, é Firecracker com KVM e jailer; QEMU/KVM permanece alternativa. A recomendação não é aprovação de dependência, instalação, configuração de rede ou decisão definitiva de produção.

O fallback para GitHub-hosted é uma capacidade distinta do escalonamento local: não deve bloquear a prova de isolamento nem ser anunciado como consequência automática de instalar um runner.

### Fatos do repositório

- `internal/agent/agent.go`: o doctor atual mede Docker rootless/cgroup e helper de serviço; `start` escolhe serviço ou container e entrega o bootstrap ao runner. Ainda não existe modo VM.
- `internal/capacity/capacity.go`: `Pool.Execution` aceita container ou serviço, `Trusted` é obrigatório, a reserva exige doctor compatível e considera instâncias diferentes de `removed`/`failed`. O novo ciclo deve definir precisamente quando uma falha libera reserva; marcar uma instância como `failed` antes de confirmar limpeza pode liberar capacidade cedo demais.
- `internal/server/operations.go`: reserva precede token e comando, mas o GitHub decide a atribuição entre runners compatíveis. O contrato de isolamento precisa ser verificado no agente imediatamente antes de criar o runner, e não só no servidor.
- `internal/discovery/workflow.go`: `Patch` altera um `runs-on` estático; não cria um seletor, não adiciona dependência entre jobs e não implementa fallback.
- `scripts/install.sh`: reconhece famílias apt, rpm e zypper. CachyOS/Arch não está contemplado; binário AMD64 não implica instalação ou suporte nessa distro.
- `go.mod` usa Go 1.25; o cliente oficial de scale sets consultado também informa Go 1.25 e estado de public preview. Compatibilidade de versão não substitui validação de API, licenciamento, permissões e operação.

## 1. Virtualização: alternativas

| Critério | Firecracker/KVM | QEMU/KVM |
|---|---|---|
| Fronteira | KVM e VMM com dispositivos reduzidos; usar jailer e filtros padrão. | KVM com máquina suportada, VMM não privilegiado e confinamento adicional. |
| Imagem | Kernel Linux e rootfs preparados; exige pipeline próprio e atualização do runner. | Várias opções de boot e disco; maior flexibilidade e maior superfície de configuração. |
| Rede | TAP no host; não filtra tráfego. | Backend de rede configurável; nenhuma opção substitui uma política externa validada. |
| Operação | API local, jailer, recursos e paths separados por instância; acompanhar suporte por kernel/CPU. | Controle QMP é privilegiado e deve ficar em socket local inacessível ao job; configurar isolamento do processo. |
| Risco de escolha | Integração e compatibilidade das imagens precisam ser demonstradas. | Mais dispositivos e opções precisam ser restringidos e mantidos. |

O [projeto Firecracker](https://github.com/firecracker-microvm/firecracker/blob/main/docs/design.md) diz explicitamente que não filtra rede e recomenda confinamento do processo. A [documentação de produção](https://github.com/firecracker-microvm/firecracker/blob/main/docs/prod-host-setup.md) exige atenção ao jailer, paths confiáveis, cgroups, logs, kernel e microcode. A [política de segurança QEMU](https://www.qemu.org/docs/master/system/security.html) pressupõe acelerador de virtualização e tipos de máquina suportados; emulação TCG não deve ser usada como fallback de segurança. QEMU recomenda processo sem privilégios, recursos limitados e controle protegido.

**Critério para decidir após protótipo:** inicialização de imagem reproduzível; bootstrap sem segredo persistente; teardown comprovado; enforcement e recuperação de rede; custo de manutenção; compatibilidade de ferramentas e Docker dentro da VM; comportamento sob carga. Testar AMD64 primeiro, ARM64 depois em hardware real. Sem `/dev/kvm` funcional, a capacidade isolada fica indisponível.

## 2. Contrato proposto de rede

### Topologia

VM → interface virtual dedicada → namespace/rede administrados pelo Fleet → ponto de enforcement do host → saída externa. O Fleet mantém gerenciamento do agente fora desse caminho. O diagrama não é uma implementação: posição exata dos hooks, namespace, NAT, DNS e roteamento deve ser definida e demonstrada em laboratório.

- Não criar bridge L2 para a LAN nem confiar no firewall dentro da VM. O job pode ser root dentro dela e alterar sua configuração local.
- Isolar cada VM de outras VMs. Tratar pacotes falsificados, rotas, tráfego não IP, IPv4, IPv6, túnel e bypass entre interfaces. Desabilitar IPv6 no caminho dos jobs somente se comprovadamente fechado em todos os pontos; caso contrário, aplicar e testar política equivalente.
- Bloquear conexões novas **e estabelecidas** da VM para destinos protegidos quando a política mudar; não colocar uma aceitação genérica de conexão estabelecida antes da verificação relevante. Avaliar conntrack, DNAT/SNAT, redirecionamentos, rotas alternativas, proxies e mudanças de interface.
- O bloqueio cobre input para o próprio host e forwarding, endereços locais/roteados da máquina, LAN, gateway, VPN, link-local e metadata, inclusive prefixos privados IPv6 e destinos resolvidos por DNS. A classificação deve usar fontes confiáveis e fail closed diante de rota ou política desconhecida; não usar apenas RFC1918.
- DNS é serviço controlado fora da VM ou destino externo permitido conforme política. Impedir que resolução, IPv6, IP literals ou redirecionamentos contornem o filtro aplicado ao destino efetivo. DNS público e internet geral não impedem exfiltração.
- Regras do Fleet têm escopo e identificação próprios, são instaladas atomicamente quando possível e nunca limpam o ruleset global. Na inicialização, o caminho deve começar fechado; só abrir após verificação. Na perda de proteção, isolar imediatamente pelo ponto independente disponível e bloquear admissão; se não for possível comprovar isolamento, parar a VM e manter estado/reserva até confirmação. Limites e tempo máximo de reação precisam ser medidos; não prometer corte instantâneo.
- Avaliar nftables como candidato, sem pressupor que uma tabela isolada ignora outras: hooks e prioridades interagem, `accept` em uma base chain não garante aceitação nas seguintes, e NAT não é filtro de pacotes. Ver [chains e hooks do nftables](https://wiki.nftables.org/wiki-nftables/index.php/Configuring_chains). Caso coexistência com regras existentes não possa ser demonstrada, diagnosticar incompatibilidade e bloquear, sem reconfigurar firewall do usuário.
- Supervisor privilegiado mínimo mantém controle de identidade/estado dos recursos e valida comandos tipados, tamanhos, paths, propriedade e versão de política. Não expor API arbitrária de nft/QEMU, shell ou socket ao job; agente/control plane não podem instruir uma exceção fora da política autorizada localmente.

### Política de saída: decisão de produto

| Opção | Usabilidade | Limite |
|---|---|---|
| Internet pública geral, bloqueando destinos protegidos | Suporta mais workflows e registries sem lista prévia. | Jobs podem contatar terceiros, exfiltrar o que recebem e usar o IP público da casa. |
| Apenas destinos aprovados | Reduz destinos acessíveis. | Requer governança e mecanismos para DNS/IP dinâmico, CDN e dependências; não elimina exfiltração por serviços permitidos. |

O padrão solicitado é **acesso geral à internet pública**, com bloqueio obrigatório da rede doméstica, do host e dos demais destinos protegidos. Restringir mais a saída fica a critério do operador; não é requisito para liberar o primeiro incremento e não pode enfraquecer os bloqueios obrigatórios. O controle exato dessas restrições adicionais permanece para desenho posterior, sem prometer que já exista.

O perfil e suas exceções devem ser versionados; o servidor não pode ampliá-los sem consentimento local. Internet pública não impede exfiltração nem abuso do IP público. O GitHub documenta HTTPS de saída e [domínios variáveis por função](https://docs.github.com/en/actions/reference/runners/self-hosted-runners#accessible-domains-by-function); uma lista fixa de IPs não comprova compatibilidade.

## 3. Roteamento GitHub e fallback

### Caminhos diferentes

1. **Workflow já self-hosted:** registrar runner que satisfaça todos os labels e grupo; não exige alteração no YAML quando política e permissões permitem. GitHub escolhe entre candidatos; sem runner livre, deixa o job na fila, até o limite documentado de 24 horas. Não há fallback implícito para hosted.
2. **Workflow com label hosted:** o comportamento padrão continua hosted. Para escolher destino por job, avaliar uma etapa de seleção explícita com saída usada no `runs-on`, com migração revisável. Um serviço externo não pode afirmar que interceptará `ubuntu-latest` sem alteração ou mecanismo oficial que o comprove.
3. **Scale sets:** o [cliente oficial em public preview](https://github.com/actions/scaleset) fornece listener e configuração JIT para escalonar runners, sem exigir Kubernetes. Não transforma por si um job self-hosted em hosted nem elimina necessidade de selecionar destino. Contrastar com registro efêmero atual antes de substituir qualquer integração; seleção futura depende de testes GitHub e ADR próprio.

### Contrato do seletor a validar

- Input por job: repositório/workflow, labels e arquitetura, destinos explicitamente permitidos, limites, autorização de custo e política de espera. Não inventar compatibilidade AMD64/ARM64, ferramentas ou equivalência de ambientes.
- Output: destino permitido e motivo, ou erro claro. Registrar versão da política e correlação com workflow/run/tentativa. Evitar escolher pago ou capacidade menos confiável sem opt-in.
- Uma decisão de capacidade é instantânea: outro job pode ocupar o runner antes da atribuição. Definir reserva, prazo, expiração e o que acontece se a atribuição não ocorrer; não prometer fallback após job já ficar enfileirado para um label sem mecanismo de redecisão comprovado.
- Webhooks duplicados/perdidos, retry, cancelamento, corrida entre seleção e registro, timeout do seletor, API indisponível e runner residual exigem reconciliação. Nenhuma resposta incerta autoriza repetir job em outro destino. Distinguir indisponibilidade do seletor de indisponibilidade de máquinas; se o próprio seletor estiver indisponível, não prometer fallback automático.
- Compatibilidade de matriz, expressões, workflows reutilizáveis, permissões, secrets, `needs`, `if`, concorrência e PRs de forks exige análise semântica e testes. A alteração proposta deve ter diff, SHA, aprovação e rollback; casos não comprovados ficam como revisão manual.
- Repositórios públicos não devem ser habilitados automaticamente em máquinas domésticas; a visibilidade deste repositório não implica autorização para executar seus workflows em hosts domésticos.

## 4. Contrato do primeiro protótipo

### Escopo

Um host de teste dedicado Debian ou Ubuntu AMD64, um slot, uma VM Linux e alvos sintéticos próprios. Sem integração GitHub real, sem credenciais, sem Docker dentro da VM, sem suporte ARM64/CachyOS e sem alteração do README. O teste de rede externa usa somente infraestrutura de teste autorizada; sem sondar a rede doméstica ou serviço compartilhado.

O host de desenvolvimento atual não é implicitamente o host de teste. Antes de instalar pacotes, habilitar KVM, alterar firewall, criar namespaces ou iniciar VMs, identificar a máquina e obter autorização para as ações e o impacto. Se não houver ambiente seguro, preparar testes e relatar bloqueio sem relaxar permissões.

### Ordem e critérios de avanço

1. Inventariar versões, CPU/KVM, cgroup v2, disco, sistema de firewall, rotas e ferramentas do host escolhido; inspecionar metadados sem capturar credenciais. Registrar matriz e incompatibilidades.
2. Definir imagem/kernel/runner verificáveis e bootstrap de uso único; isolar disco e limitar logs, CPU, RAM, processos, descritores, espaço e tempo. Sem secret persistente em imagem, log, linha de comando ou filesystem compartilhado.
3. Desenhar e revisar rede isolada com regras fail closed e remoção limitada a recursos Fleet. Ensaiar em namespace/VM de laboratório próprio com endpoints sintéticos, sem comandos de alteração na máquina doméstica como instrução genérica.
4. Validar em execução as negações input/forward e conexões existentes, IPv4/IPv6, DNS, mudança de rota/política, spoofing e comunicação entre VMs; confirmar que os alvos sintéticos não receberam tráfego. Testar comunicação pública somente se autorizada.
5. Exercitar reboot, crash do supervisor, exclusão parcial de regras, indisponibilidade de KVM, disco cheio, timeout e limpeza falha. A VM não pode iniciar sem proteção; recursos com estado desconhecido mantêm reserva.
6. Só após aprovação da evidência, integrar a jornada ao Fleet e depois realizar canário GitHub em repo de teste autorizado. Nenhum teste local prova segurança geral nem homologação de outras distribuições.

## 5. Decisões necessárias antes da implementação

1. Máquina isolada de laboratório, distro/versão, autorização das mudanças temporárias, possibilidade de KVM e acesso de recuperação independente.
2. Seleção final do VMM após protótipo; não marcar Firecracker como decisão aceita apenas por esta recomendação.
3. Política de cancelamento e isolamento quando proteção for perdida durante um job e critérios operacionais de recuperação.
4. Permissões e contrato do roteador, configuração de fallback pago e compatibilidade exigida dos workflows.

Nenhuma dessas escolhas está implementada. O README permanece como última tarefa do plano.
