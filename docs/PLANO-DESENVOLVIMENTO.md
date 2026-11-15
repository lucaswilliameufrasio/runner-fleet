# Plano de desenvolvimento: máquinas próprias com isolamento

**Estado:** planejamento; funcionalidades novas não implementadas nem homologadas.

**Direção:** usar máquinas próprias como capacidade para GitHub Actions, com conexão e operação simples, escolha transparente do destino quando possível e proteção da rede doméstica gerenciada pelo Runner Fleet.

Pesquisa, propostas e decisões abertas da primeira etapa: [estudo técnico de isolamento e roteamento](ESTUDO-ISOLAMENTO-ROTEAMENTO.md).

## Objetivo e limites

O proprietário conecta máquinas Linux, define quem pode usá-las e acompanha onde cada job executou. Máquinas disponíveis recebem jobs compatíveis; quando não puderem recebê-los, uma alternativa autorizada pode assumir, conforme a capacidade real do GitHub e o contrato do workflow. O comportamento deve ser compreensível para o desenvolvedor que apenas faz push.

O cenário prioritário é Debian e Ubuntu AMD64; Ubuntu ARM64 e CachyOS AMD64 exigem validação nativa específica. Máquinas domésticas são dedicadas a runners e não devem guardar dados pessoais nem credenciais alheias ao serviço. VLAN ou firewall externo são defesa adicional opcional, não requisito para a experiência básica.

O projeto atual administra pools, runners efêmeros em containers, serviços persistentes, capacidade e máquinas Spot. Esses modos não são uma fronteira para código hostil e não devem ser apresentados como isolamento doméstico. A reserva de disco existente não é quota rígida. A lista de limites e evidências atuais está em [IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md).

## Jornadas e responsabilidades

1. **Proprietário da máquina:** instala o agente, verifica a identidade do servidor, conecta a máquina, acompanha o diagnóstico e escolhe capacidade e escopos permitidos. Pode pausar novas execuções, drenar e remover a máquina.
2. **Administrador do Fleet:** conecta instalações GitHub, configura grupos, repositórios e políticas, escolhe destinos e aprova alterações sensíveis. A versão atual possui um único administrador; propriedade individual, múltiplos usuários e permissões separadas são trabalho futuro e não devem ser simulados com uma indicação visual.
3. **Mantenedor do repositório:** entende a compatibilidade do workflow, revisa qualquer alteração sugerida e mantém controles de branch, PR e secrets no GitHub.
4. **Agente e supervisor local:** verificam pré-requisitos, aplicam proteção antes de expor capacidade, criam e acompanham ambientes descartáveis, reconciliam falhas e não ampliam a política recebida.
5. **Job:** código e dependências potencialmente hostis; não decide permissões, não administra o host e não recebe credenciais do Fleet.

## Contrato de segurança

### Fronteira e admissão

- Um runner efêmero por VM descartável, com no máximo um job; descartar VM e disco gravável após conclusão ou interrupção. Não compartilhar workspace, cache local, home, socket do host, credenciais do agente, dispositivos ou estado de outro job.
- A VM é uma fronteira adicional, não garantia absoluta contra escape, falhas do kernel, hypervisor ou administração comprometida. Rede aplicada no host não protege contra comprometimento do próprio host; hardware, firmware, kernel e hypervisor precisam de manutenção.
- Grupo, repositório e eventual workflow autorizado controlam quem pode solicitar trabalho, não a rede alcançável pelo trabalho. Repositório privado também pode conter código hostil. Políticas para forks, PRs, bots e reruns precisam ser explícitas e testadas; não presumir que o autor do evento identifica todo código executado.
- Não ativar automaticamente repositórios públicos ou workloads de confiança indefinida em máquinas domésticas. Não prometer contenção de exfiltração nem impedir abuso do IP público se houver acesso à internet.
- A máquina só fica elegível depois de verificados virtualização, isolamento e capacidade. Falha ou estado desconhecido bloqueia admissão; nunca mudar silenciosamente para container, serviço persistente ou rede aberta.
- A configuração aceita para uma instância deve ser imutável e versionada: identidade, escopo, recursos, imagem e política de rede. Políticas mais permissivas e mudança de escopo exigem confirmação explícita e auditoria.

### Rede sob controle do host

- Criar uma rede de job separada, sem ponte direta para a LAN; impor regras fora da VM, antes de iniciar o runner. Tratar tráfego encaminhado e destinado ao próprio host, incluindo outras interfaces, VMs e serviços de gerenciamento.
- Negar acesso a LANs e rotas privadas, link-local, gateway doméstico, host, outras VMs e destinos de infraestrutura sensíveis, em IPv4 e IPv6. Tratar rotas sobrepostas, redes VPN, loopback, múltiplas interfaces, mudanças de endereço e nomes que resolvam para destinos proibidos. Não depender somente de DNS ou listas RFC1918.
- Projetar DNS e egress para manter os bloqueios após resolução e redirecionamentos. O padrão permite internet pública geral, mantendo bloqueados rede doméstica e demais destinos protegidos; restrições adicionais ficam a critério do operador. Atender endpoints dinâmicos de GitHub, registries e pacotes sem falsa segurança. Tráfego para destinos privados continua negado mesmo quando o nome aparenta ser público.
- Isolar o tráfego de gerenciamento do agente do tráfego dos jobs. Não expor credenciais, canal do Fleet ou uma API privilegiada para a VM.
- Aplicar regras próprias e identificáveis, sem apagar nem substituir regras do usuário. Investigar coexistência com nftables/iptables, Docker, firewalld, ufw, VPNs e políticas existentes; instalação, atualização e remoção não devem alterar regras não pertencentes ao Fleet.
- Reconstruir e verificar regras após reinício; detectar perda ou alteração de proteção. Bloquear novos runners e definir, implementar e testar a resposta para VMs já ativas. Não afirmar corte instantâneo durante falha total até demonstrá-lo.
- Projetar helper privilegiado mínimo com operações tipadas e validação de identidade, caminhos, recursos e política; não fornecer shell, sudo genérico ou firewall arbitrário ao agente ou job. Privilégios e instalação exigem revisão e confirmação.

### Execução e recursos

- Investigar QEMU/KVM e Firecracker com protótipos antes de selecionar backend e contrato de suporte; verificar `/dev/kvm`, arquitetura, firmware e recursos exigidos. Não escolher por preferência sem comprovar rede, compatibilidade e manutenção. Imagem, kernel, runner e artefatos devem ter proveniência e integridade verificáveis e atualização controlada.
- Limitar CPU, memória, processos, disco gravável, descritores, logs e tempo da instância inteira; definir comportamento sob esgotamento. Nenhum mount do host ou socket de gerenciamento para o job.
- Docker, container actions e service containers dentro da VM são capacidade separada a homologar; não pressupor suporte nem reutilizar o sidecar privilegiado atual. Definir isolamento e custos antes de habilitar.
- Logs e resultados são dados não confiáveis. Limitar tamanho e retenção; não expor secrets nem copiar arbitrariamente arquivos da VM. Artefatos usuais do Actions continuam sob controle do GitHub e do workflow.

## Produto e roteamento

### Conectar e administrar máquinas

- Simplificar cadastro e diagnóstico para uma jornada curta: identificar servidor, validar confiança, instalar agente, verificar capacidade/isolamento, escolher limites e ativar explicitamente. Exibir comandos adequados e ações privilegiadas antes de executá-las.
- Exibir online, pausada, drenando, offline, incompatível ou proteção indisponível, com causa e ação recomendada. Pausar impede novos jobs; jobs ativos seguem a política de drain documentada.
- Definir dono da máquina, instalações e repositórios autorizados e eventual compartilhamento com equipe/bots. Como o servidor atual é single-admin, a implementação de propriedade e autorização individual depende de um modelo de identidade/RBAC real; até lá, não prometer controle por pessoa.
- Evitar alteração de configurações globais, redes e privilégios sem consentimento. Manter enrollment e updates verificáveis, revogação, auditoria e tratamento seguro de credenciais existentes.

### Compatibilidade de workflows e fallback

- Identificar workflows que já usam runners self-hosted, seus grupos e labels; adicionar máquina compatível sem editar YAML somente quando o GitHub efetivamente permitir. Grupos restringem acesso, não garantem seleção de uma máquina específica.
- Para workflows com labels de runner hospedado, investigar uma etapa explícita de seleção e seus limites de API/protocolo, permissões, políticas de organização, indisponibilidade, segurança e custo. Não prometer que `ubuntu-latest` será atribuído automaticamente a uma máquina própria.
- Oferecer planejamento de migração por job, diff e validação de SHA, com aprovação humana e sem commit automático. Preservar comportamento, expressões e formatação quando possível; reportar matrizes, reutilizáveis, deploys, permissões e outros casos não suportados sem modificá-los silenciosamente.
- Definir ordem de destinos por política e por job, capacidades de arquitetura/SO/ferramentas e destinos permitidos. Não selecionar um destino pago ou com confiança diferente sem autorização; exibir o motivo da escolha e custo potencial.
- Especificar como tratar capacidade ocupada versus indisponível, concorrência, reserva, timeout, mudanças de estado e fallback. O destino escolhido não equivale a execução concluída. Evitar redirecionar ou repetir um job cujo estado seja incerto.
- Definir comportamento quando o control plane ou GitHub estiver indisponível, inclusive jobs já registrados. Os modos atuais podem continuar elegíveis até serem retirados no GitHub; não prometer desativação instantânea.
- Mostrar histórico por tentativa: origem, destino efetivo quando conhecido, motivo, tempos de espera/execução, falhas e fallback; distinguir decisão planejada de observação confirmada pelo GitHub.

## Integração com o código existente

- `internal/capacity/`: modelar capacidade de isolamento, backend, requisitos e política versionada; validar compatibilidade e reservar recursos com segurança. Preservar compatibilidade dos pools container/serviço existentes, sem reclassificá-los como isolados.
- `internal/agent/`: adicionar backend de VM e supervisor de rede, doctor efetivo, admissão local, observação, drain e limpeza. Refatorar os caminhos de criação/reconciliação sem degradar container/serviço; não confiar em indicação de prontidão sem verificar as garantias efetivas.
- `internal/server/`: integrar agendamento, comandos, políticas, auditoria, estado de proteção e roteamento; investigar o mecanismo de seleção antes de fixar API ou dependência de protocolo. Considerar webhooks duplicados, perdidos e atrasados e respostas externas ambíguas.
- `internal/store/`: persistir alterações e migrações compatíveis para política, instâncias, tentativas, decisões e recursos pertencentes ao Fleet. Não persistir tokens de registro em texto; expiração e limpeza devem ser verificadas.
- `internal/discovery/`, `internal/github/` e ferramentas de migração: inspecionar compatibilidade e permissões reais; propor alterações de workflow revisáveis e manter limites para expressões não resolvidas.
- `web/`: jornadas distintas para conectar/diagnosticar máquina, configurar acesso e segurança, ordenar destinos, revisar migração e acompanhar atividade. Mostrar estado desconhecido e bloqueios, não selos genéricos de segurança.
- `scripts/`, `deploy/` e releases: distribuição e verificação dos componentes necessários por arquitetura; instalação e desinstalação reversíveis e de escopo limitado; suporte explícito a famílias de distribuição comprovadas.
- Atualizar ADR, canário e status conforme decisões aceitas e evidência real, preservando o histórico dos modos existentes. Deixar a revisão do README para a última etapa do plano.

## Estados, recuperação e cancelamento

- Modelar separadamente solicitação, reserva, preparação de rede/disco, VM iniciada, runner registrado, aguardando, job ativo, drenando, limpeza, concluído e estado desconhecido/erro. Registrar transições antes de confirmar efeitos quando necessário.
- Identificar recursos por instância e posse, não apenas por PID ou nome. Em crash/restart, descobrir e reconciliar VM, disco, rede, registro no GitHub e reserva; nunca destruir recursos alheios.
- Em falha de criação, registro ou limpeza, manter reserva enquanto a existência dos recursos for desconhecida. Cancelamento e timeout devem encerrar toda a árvore de execução com prazo delimitado e confirmar limpeza; preservar histórico e efeitos externos incertos.
- Disconnect, retry, webhook duplicado e crash não autorizam executar o job novamente. GitHub continua responsável pelo resultado e por novas tentativas; não alegar execução exatamente uma vez.

## Etapas de entrega

1. **Investigação e contrato:** inventário de workflows e máquinas, ameaça, alternativas de virtualização e roteamento, política de egress, compatibilidade e decisões abertas. Produzir protótipo isolado sem serviços ou credenciais reais.
2. **Prova de isolamento local:** VM por job, rede sob controle do host, falhas fechadas, limites e limpeza. Testar Debian/Ubuntu AMD64 nativamente antes de declarar suporte.
3. **Integração vertical:** instalar/conectar máquina, diagnóstico real, criar pool isolado pausado, ativar, executar job de teste e limpar; recuperar após reinício. Manter os outros modos disponíveis com seus avisos.
4. **Roteamento e fallback:** implementar após validar os contratos GitHub; incluir análise de workflows, preview, autorização dos destinos e histórico da decisão.
5. **Experiência e governança:** pausar/drenar, visibilidade, limites, documentação, política de compartilhamento; entregar RBAC real antes de afirmar controle individual.
6. **Ampliação de plataforma:** Ubuntu ARM64 em hardware real e CachyOS AMD64; só depois ampliar a matriz publicada. Homologar Docker dentro da VM como funcionalidade separada.
7. **README, por último:** reescrever com propósito, início rápido, requisitos, limites de segurança e links para guias, refletindo apenas o que foi implementado e comprovado.

## Critérios de aceitação e evidência exigida

Todos estão **pendentes**; testes artificiais não substituem canário autorizado.

| ID | Resultado observável | Evidência mínima |
|---|---|---|
| AC-01 | Máquina suportada conecta, mostra diagnóstico e pode ser pausada/drainada sem novos jobs. | Jornada real em host de teste; estados e auditoria. |
| AC-02 | Workflow self-hosted compatível usa capacidade sem edição quando permitido; demais casos explicam e oferecem diff revisável. | Testes de descoberta e canário GitHub em repo autorizado. |
| AC-03 | Fallback usa somente destinos explicitamente permitidos e explica decisão; custo e estado desconhecido ficam visíveis. | Testes de concorrência/falhas e canário com provedores autorizados. |
| AC-04 | Job recebe VM e disco descartáveis, sem acesso a arquivos, sockets ou credenciais do host e de outros jobs. | Testes negativos em hardware real, imagens e versões registradas. |
| AC-05 | Job não alcança alvos sintéticos representando LAN, host e outras VMs; IPv4, IPv6, DNS, VPN e mudanças de rota cobertos conforme matriz suportada. | Testes controlados no host e canário isolado, sem sondar rede real alheia. |
| AC-06 | Falha ou perda de proteção impede novas execuções; reinício e falha de limpeza reconciliam sem fallback inseguro ou liberação prematura. | Injeção de falhas, reboot e evidência de recursos e reservas. |
| AC-07 | Limites e cancelamento abrangem a VM inteira; disco e logs não crescem sem limite. | Testes de pressão, timeout e limpeza em ambiente dedicado. |
| AC-08 | Regras preexistentes sobrevivem a instalação, execução e remoção; tráfego de administração permanece disponível. | Testes com configurações de firewall suportadas, antes/depois e recuperação. |
| AC-09 | Plataforma declarada funciona na distro e arquitetura reais; Docker e serviços em VM só são anunciados após validação própria. | Matriz de resultados e versões nativas, não apenas cross-compile. |
| AC-10 | Interface e documentação distinguem modos confiáveis, isolamento proposto, limitações e estado realmente verificado. | Revisão de jornadas, mensagens de falha e documentação. |

## Decisões ainda abertas

- Backend de virtualização e modelo de imagens; alternativas, manutenção, limites e suporte a KVM aninhado.
- Mecanismo opcional de restrições adicionais de saída, exceções aprovadas e compatibilidade com DNS/IPv6 e endpoints dinâmicos.
- Resposta operacional a perda de proteção durante job ativo, incluindo disponibilidade, cancelamento e evidência.
- Arquitetura e contrato do seletor de destino, compatibilidade com organizações e custo do fallback.
- Identidade, propriedade e RBAC para permitir que pessoas distintas governem suas máquinas.
- Suporte por versão de distro/firewall, instalação privilegiada, atualização e recuperação; compatibilidade de Docker em VM.

Nenhuma etapa autoriza, por si, implantação, alteração de rede, execução de jobs em infraestrutura real ou publicação de credenciais.
