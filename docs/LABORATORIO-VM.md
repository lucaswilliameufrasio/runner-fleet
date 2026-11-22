# Rede do laboratório de VM: preparação

**Estado: desenho não implementado nem validado no host.** Uma VM externa local
será o laboratório; a VM interna será o protótipo do runner. Os discos ficarão
em `/mnt/storage`. A VM externa começa sem rede. A configuração exata será
revista antes de qualquer alteração privilegiada ou inicialização.

O Tailscale existente é o caminho de recuperação do operador: não alterar suas
interfaces, tabelas, regras, marcas ou rotas. Neste ensaio, a negação de acesso
ao Tailscale a partir do guest não é um critério validado nem uma garantia de
produto. Não rotear intencionalmente tráfego do guest por ele. A política futura
do Fleet para VPN é uma decisão independente.

## Por que estes arquivos existem

Nenhum script abaixo é o controlador do Fleet. Eles ficam na árvore porque as
seções seguintes citam a execução. Apagar o arquivo apagaria o ensaio que
sustenta a conclusão. Três papéis:

- **Vigente no ensaio.** Última topologia que passou: `slirp` num namespace
  filho, sem rota default, só com `/32` para o domínio autorizado e os
  resolvedores. Não está instalada no host.
- **Rejeitado.** O desenho foi executado e não serve como controle. O arquivo
  permanece para reproduzir a falha.
- **Contrato não exercido.** Preparado e testado em namespace, sem virar a
  permissão nem a rede deste host.

Vigente no ensaio:

- `tests/lab-public-egress.py` classifica destinos, instala os blackholes e
  mede a janela em que recolocar a rota default entrega na LAN sintética.
- `tests/test_public_egress.py` cobre essa classificação sem VM.
- `tests/lab-public-egress-vm-isolated.py` e
  `tests/lab-public-egress-vm-isolated.sh` sobem a VM descartável.
- `tests/lab-public-egress-cleanup-isolated.sh` recusa liberar o slot enquanto
  sobra interface ou tabela.
- `tests/lab-public-egress-supervisor-isolated.sh` mata o supervisor com a VM
  ativa. O QEMU sai; o slot não volta sozinho para `EMPTY`.
- `tests/lab-vm-slot.py` é a máquina de estado usada por essa topologia. Os
  ensaios anteriores já mostraram que `UNKNOWN` não desliga uma VM em
  execução. O arquivo continua porque a admissão vigente ainda depende disso.

Rejeitados, na ordem em que o desenho falhou:

- `scripts/lab-network-closed.nft`,
  `scripts/lab-network-synthetic-egress.nft`,
  `scripts/lab-network-synthetic-close.nft` e
  `tests/lab-network-closed-isolated.sh`: tabela nft no namespace. Apagar a
  tabela com uma rota ainda presente abre o alvo.
- `scripts/lab-network-lease-guard.nft` e
  `tests/lab-network-lease-fixture.py`: a permissão expira, mas a rota que
  sobra continua encaminhando.
- `tests/lab-network-operations.py`,
  `tests/lab-network-operations-isolated.sh`,
  `tests/lab-network-lifecycle-isolated.sh`,
  `tests/lab-network-supervision-fixture.py` e
  `tests/lab-network-watchdog.py`: operações nomeadas e um observador da
  tabela. Parar o observador não fecha a rede.
- `tests/lab-vm-network-isolated.py`, `tests/lab-vm-network-isolated.sh` e os
  `lab-vm-network-config`, `lab-vm-network-meta-data` e
  `lab-vm-network-user-data`: primeira VM real em rede sintética. Provam boot
  e limpeza, não saída pública.
- `tests/lab-slot-controller.py` e `tests/lab-slot-recovery-isolated.sh`: o
  renovador do lease não consegue desligar a interface sem permissão, e o
  slot fica `UNKNOWN` com o recurso ainda ligado.
- `tests/lab-vm-crash-supervisor.py`,
  `tests/lab-vm-supervisor-death-isolated.py`,
  `tests/lab-vm-supervisor-death-isolated.sh`,
  `tests/lab-vm-lost-observer.py`,
  `tests/lab-vm-lost-observer-isolated.py`,
  `tests/lab-vm-lost-observer-isolated.sh`,
  `tests/lab-vm-tap-integrated.py` e `tests/lab-vm-tap-integrated.sh`: morte
  do supervisor ou do observador nas topologias antigas. Perder o observador
  não encerra a VM.
- `tests/lab-tap-helper.py`, `tests/lab-tap-helper-isolated.sh`,
  `tests/lab-tap-packet-fixture.py`, `tests/lab-fd-tap-owner.py`,
  `tests/lab-fd-tap-ownership-isolated.py`,
  `tests/lab-fd-tap-ownership-isolated.sh`, `tests/lab-fd-tap-qemu-owner.py`,
  `tests/lab-fd-tap-vm-isolated.py` e `tests/lab-fd-tap-vm-isolated.sh`:
  posse da TAP por descritor. Não criam a fronteira de saída.
- `tests/lab-fence-watchdog.py`, `tests/lab-independent-fence-isolated.py`,
  `tests/lab-independent-fence-isolated.sh`, `tests/lab-dual-loss-isolated.py`,
  `tests/lab-dual-loss-isolated.sh`, `tests/lab-dual-loss-observer.py`,
  `tests/lab-boundary-paths-isolated.py`,
  `tests/lab-boundary-paths-isolated.sh`, `tests/lab-boundary-network-config`
  e `tests/lab-boundary-user-data`: cerca em outro namespace e caminhos
  locais. A cerca não segura quando o encaminhamento continua.
- `tests/lab-bridge-boundary-isolated.py`,
  `tests/lab-bridge-boundary-isolated.sh`,
  `tests/lab-bridge-probe-user-data` e `tests/lab-bridge-watchdog.py`: guarda
  na bridge. Com a VM ativa, parar o watchdog reabre o caminho.
- `tests/lab-socket-boundary-isolated.py`,
  `tests/lab-socket-boundary-isolated.sh`, `tests/lab-socket-probe-user-data`,
  `tests/lab-socket-sink.py`, `tests/lab-native-socket-vm-isolated.py`,
  `tests/lab-native-socket-vm-isolated.sh`,
  `tests/lab-native-socket-network-config` e
  `tests/lab-native-socket-user-data`: socket e libslirp. Sem a guarda, o
  mesmo socket alcança host, LAN sintética e loopback.
- `tests/lab-dns-tcp-egress-isolated.py`,
  `tests/lab-dns-tcp-egress-isolated.sh`,
  `tests/lab-dns-tcp-serial-bridge.py`, `tests/lab-dns-tcp-vm-isolated.py`,
  `tests/lab-dns-tcp-vm-isolated.sh`, `tests/lab-dns-tcp-vm-user-data` e
  `tests/test_dns_tcp_egress.py`: DNS e TCP sintéticos. Não são a internet
  pública e não sobrevivem à perda da guarda.
- `tests/lab-synthetic-relay.py`, `tests/lab-synthetic-relay-isolated.py`,
  `tests/lab-synthetic-relay-isolated.sh`,
  `tests/lab-synthetic-relay-user-data` e `tests/test_synthetic_relay.py`:
  relay UDP com os dois alvos no mesmo namespace, sem internet.
- `tests/lab-topology-egress-vm-isolated.py` e
  `tests/lab-topology-egress-vm-isolated.sh`: roteador no meio. A rota
  default para um encaminhador que também alcança a LAN vaza quando a guarda
  some. É o motivo de a topologia vigente não ter rota default.

Contrato não exercido:

- `scripts/lab-access-create`, `scripts/lab-access-remove`,
  `scripts/lab-firewall-inspect` e `tests/lab-access-isolated.sh`: helper que
  só pode listar o firewall. Não há sudo correspondente neste host, e o
  ensaio vigente não precisou dele.

## Operações privilegiadas a preparar

As operações abaixo são um contrato proposto, não permissões sudo disponíveis:

1. **Inspecionar:** consultar interfaces, rotas, endereços e regras, sem
   modificações. Não expor uma interface genérica para executar `ip` ou `nft`.
2. **Criar fechado:** criar exclusivamente recursos de laboratório com nomes e
   identificadores fixos, sem bridge para a LAN. Instalar controles de input e
   forward antes de conectar a VM; negar por padrão, inclusive IPv6. Validar
   ausência de colisões e propriedades existentes antes de qualquer mudança.
3. **Habilitar saída:** somente após testar a proteção, liberar e aplicar NAT
   para o caminho aprovado, bloqueando o host e a rede local por destino e
   interface. Tratar endereço público do host, outras rotas, DNS, redireções e
   tráfego falsificado; classificação incompleta ou ambígua bloqueia a saída.
4. **Fechar e remover:** primeiro fechar o tráfego, depois parar a VM sob
   supervisão e remover apenas recursos cuja identidade e propriedade foram
   confirmadas. Estado desconhecido, colisão ou falha de limpeza interrompe a
   operação e exige intervenção; nunca limpar o ruleset global.

Não confiar em `accept` de uma base chain como garantia contra outras chains.
Preservar firewall e NAT existentes, inclusive tabelas gerenciadas por
iptables-nft. A seleção de hooks, prioridades, topologia, DNS, tratamento de
rotas e detecção de perda de regras ainda precisa de implementação e revisão.
Não há autorização genérica para shell root ou argumentos arbitrários.

## Evidências exigidas

- Em namespaces descartáveis, verificar criação fechada, colisões, rollback,
  regras IPv4/IPv6, spoofing, alterações de rota, perda parcial de proteção,
  conexões estabelecidas, remoção idempotente e coexistência com regras alheias.
- Depois, no host autorizado, testar acesso ao domínio público aprovado e
  negação a alvos sintéticos próprios representando host e rede local; verificar
  nos receptores que não houve tráfego. Não sondar serviços reais da LAN.
- Confirmar timeout, falhas de KVM, encerramento da VM, limpeza parcial e
  preservação do acesso de recuperação. Não declarar isolamento completo com
  base somente em regras estáticas ou num teste em namespace.

## Acesso provisório atual

`scripts/lab-access-create` instala somente um helper de inspeção de firewall;
`scripts/lab-access-remove` revoga essa permissão. Não concedem acesso para
alterar a rede. Não instalar como substituto das operações ainda não definidas.
`sh tests/lab-access-isolated.sh` exercita instalação e remoção usando user,
mount e network namespaces e dois tmpfs temporários. Não prova o comportamento
real de `sudo`, nem valida as operações de rede ou a segurança da VM.

`scripts/lab-network-closed.nft` é uma política experimental exclusivamente
para namespace descartável: bloqueia input e forward por uma interface fixa,
sem criar interface, liberar saída ou configurar NAT. O teste
`sh tests/lab-network-closed-isolated.sh` cria uma topologia sintética e
verifica o estado fechado. A remoção no teste ocorre somente dentro do namespace
descartável; ainda não existe operação de remoção autorizada para o host.

`scripts/lab-network-synthetic-egress.nft` e
`scripts/lab-network-synthetic-close.nft` são transações de laboratório sobre
essa mesma tabela. A primeira permite somente um destino IPv4 sintético,
aplica SNAT e mantém o bloqueio de input e de IPv6; a segunda fecha novamente
o encaminhamento e remove o SNAT. Não implementam acesso público geral,
supervisão, proteção contra perda arbitrária da tabela nem operação no host.

Os testes incluem um watchdog **experimental**, executado apenas no namespace
descartável. Ele compara a tabela com um snapshot obtido pelo próprio teste e,
ao detectar diferença ou erro, desliga a interface. Também desliga a interface
antes de tentar uma transação de fechamento. O ensaio mantém TCP estabelecido,
apaga a tabela e mede o tempo até o desligamento; depois injeta falha no
fechamento. Há uma janela entre perda e detecção. O snapshot não é uma raiz de
confiança para produção, e o watchdog não protege contra sua própria morte,
falha do comando de isolamento, falha do kernel ou uma alteração seguida de
reversão entre consultas. Não usar este watchdog no host nem como mecanismo de
segurança do Fleet.

Uma segunda experiência usa `scripts/lab-network-lease-guard.nft`: uma tabela
separada bloqueia forwarding de `rflab0` enquanto não houver autorização com
prazo no kernel. O teste mata o processo que renova o prazo e verifica uma
conexão TCP existente após o vencimento. A criação e a remoção são feitas
somente no namespace descartável, com a interface desligada antes da remoção.
Isso protege contra perda do renovador no cenário testado, não contra exclusão
ou alteração da própria tabela de guarda, travamento do kernel ou retomada
indevida. O prazo também deixa uma janela de tráfego após a morte do renovador.
Não é uma autorização nem um helper seguro de rede para o host.

`tests/lab-network-operations.py` é outro experimento **restrito a user
namespace descartável**, não um helper sudo: cria primeiro uma tabela que
bloqueia input e forwarding sem autorização temporária, depois cria um par
veth identificado e inicialmente desligado. Em remoção, verifica identidade,
isola a interface e confere o conteúdo da tabela antes de excluir recursos.
`sh tests/lab-network-operations-isolated.sh` verifica colisões, falha após
criação parcial, alteração da regra e alteração da identidade da interface.
O estado fica em tmpfs privado de teste: não é resistente a adulteração por
um operador privilegiado e não fornece o armazenamento nem a reconciliação
necessários para o host. `sh tests/lab-network-lifecycle-isolated.sh` liga a
outra extremidade do veth a um guest sintético, permite exclusivamente um alvo
de teste durante a renovação, mata o renovador e verifica uma conexão TCP
estabelecida após o prazo. Não conecta uma VM nem comprova essa política em uma
rede real. A remoção ou adulteração privilegiada da tabela, a janela até o
vencimento e a falha do kernel continuam sem proteção independente comprovada.

## Primeira VM externa offline — 2026-11-18

- Host Debian 13 AMD64, QEMU 10.0.13 e KVM aninhado habilitado no módulo Intel.
  VM externa com QEMU/KVM, `-cpu host`, duas vCPUs, 1 GiB de RAM e `-nic none`;
  nenhuma rede virtual, firewall ou regra sudo foi alterada.
- Imagem `debian-13-generic-amd64.qcow2`, obtida de
  `https://cloud.debian.org/images/cloud/trixie/latest/`. SHA-512:
  `e53a93ef33f828ceed0e7278c2cc2753bdc7d5098fbfae15bd64b6d878db350ea3744247763a1c8ecb6b4019a0f623c38caf6038ad6f9c357fb4e01493ddf1a3`.
  O digest coincide com o manifesto obtido pela mesma origem HTTPS. Não foi
  verificada assinatura independente; a procedência depende de HTTPS e da
  origem, portanto essa evidência não estabelece uma cadeia assinada.
- A VM inicializou sem rede e dentro dela `/dev/kvm` retornou API 12. Uma
  segunda tentativa criou VM e vCPU internas, mas `KVM_RUN` retornou erro
  porque o teste não havia configurado corretamente os registradores. Após
  corrigir a inicialização em uma terceira VM descartável, `KVM_RUN` executou
  uma instrução HLT e retornou o motivo de saída esperado. Isso comprova um
  ensaio mínimo de execução aninhada, não o boot de um sistema operacional
  completo na VM interna nem homologação de desempenho.
- As três VMs encerraram normalmente. Os três overlays e imagens de seed
  usados no ensaio foram removidos após verificação de que não estavam em uso.
  Imagem base, manifesto, configuração de teste e logs de console foram
  preservados em `/mnt/storage/runner-fleet-lab-a5Ahis2o` para auditoria.
- Rede controlada, saída pública, tratamento de falhas, integridade assinada da
  imagem e integração ao Fleet continuam pendentes.

## Imagem Ubuntu com manifesto assinado — 2026-11-18

- Candidata: Ubuntu 24.04 LTS AMD64, arquivo
  `ubuntu-24.04-server-cloudimg-amd64.img`, baixado de
  `https://cloud-images.ubuntu.com/releases/noble/release/`. SHA-256:
  `04e8f2461a16a44e78a370284471f29616cdd9baf1893df25807b71f985b6c94`.
  `sha256sum -c` confirmou que o arquivo corresponde ao manifesto.
- `gpgv` validou `SHA256SUMS.gpg` sobre `SHA256SUMS` e retornou `VALIDSIG`
  para a chave `D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`, identificada como
  UEC Image Automatic Signing Key. A impressão digital foi comparada à
  [documentação oficial da Canonical](https://ubuntu.com/docs/public-images/public-images-how-to/verify-image-checksum/);
  a chave foi obtida por HTTPS do servidor de chaves da Ubuntu. A confiança
  inicial na impressão digital depende da autenticidade dessa documentação e
  não é uma atestação independente da própria Canonical.
- Para a verificação, `gpgv` e suas bibliotecas foram extraídos de pacotes Debian
  em diretório privado, sem instalação no host. Os hashes dos pacotes
  coincidiram com os índices APT já disponíveis no sistema.
- Imagem, manifesto, assinatura, chave e verificador estão em
  `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV`. A assinatura tem data de
  2026-10-17. A validação inicial da assinatura não incluiu inicialização.

## Ubuntu assinado: VM externa offline — 2026-11-18

- Antes de iniciar, a assinatura foi novamente validada com a chave descrita
  acima e o SHA-256 da imagem novamente conferido com o manifesto.
- A imagem inicializou como Ubuntu 24.04.5 LTS, kernel 6.8.0-147-generic,
  em QEMU/KVM com `-cpu host`, duas vCPUs, 1 GiB de RAM e `-nic none`.
  O cloud-init leu uma seed local, sem credenciais nem rede.
- Dentro da VM externa, `/dev/kvm` reportou API 12. O teste criou VM e vCPU,
  executou `KVM_RUN` com uma instrução HLT e obteve o motivo de saída esperado:
  `FLEET_LAB_KVM_RUN_HLT=OK`. A VM desligou normalmente; `qemu-img check`
  não detectou erros no overlay.
- Overlay e seed foram removidos após o encerramento e verificação de uso.
  O console e a configuração de teste foram preservados em
  `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/offline-kvm-aMll1RU7`.
  Isso não é boot de um sistema completo na VM interna, nem valida rede,
  proteção contra falhas ou integração ao Fleet.

## VM real em rede sintética isolada — 2026-11-18

`sh tests/lab-vm-network-isolated.sh CAMINHO_DA_IMAGEM_VERIFICADA` executa
uma VM Ubuntu com KVM, uma TAP e um alvo sintético em namespaces descartáveis.
Não há interface com a LAN, Tailscale ou internet. A imagem assinada foi
novamente conferida antes do ensaio; o script recebe a imagem já verificada e
não implementa essa verificação por conta própria.

Na execução em `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/synthetic-network-k2550o8n`:

- Antes da autorização temporária, a VM registrou bloqueio do host e do alvo.
- Durante a renovação, o alvo recebeu quatro conexões sintéticas; o receptor
  protegido no host não recebeu nenhuma.
- Após `SIGKILL` do renovador e espera pelo prazo de três segundos, a VM
  registrou bloqueio do alvo e o receptor não recebeu novas conexões durante
  os três segundos de observação seguintes.
- O QEMU foi encerrado por SIGTERM e aguardado; o overlay e a seed foram
  removidos. Console e logs dos receptores foram preservados. Os namespaces e
  seus recursos de rede eram descartáveis; nenhuma regra do host foi alterada.

O ensaio abre conexões TCP curtas a partir da VM. A interrupção de uma
conexão estabelecida foi testada separadamente com guest sintético, não nessa
VM. A duração da janela após a morte do renovador, remoção da própria barreira,
falha do kernel, recuperação após reboot, sudo real e acesso público continuam
sem validação para esse cenário. Não usar o script como helper de host.

## Falhas com VM real em rede sintética — 2026-11-19

Após verificar novamente assinatura e checksum da imagem Ubuntu, o ensaio
`tests/lab-vm-network-isolated.sh` foi ampliado e executado com uma conexão TCP
persistente identificada. Evidência em
`/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/synthetic-network-9h4juk1l`:

- A VM trocou dados na conexão identificada como 3 enquanto o prazo era
  renovado. Após `SIGKILL` do renovador, o console registrou a interrupção da
  mesma conexão (`FLEET_VM_FLOW_CLOSED=3`); o receptor do alvo não registrou
  mais dados durante os três segundos de observação posteriores. O receptor do
  host registrou zero dados durante o ensaio.
- Com a concessão já expirada, uma transação de fechamento inválida deixou a
  TAP administrativamente desligada. Em seguida, com a guarda por prazo ainda
  presente e expirada, a exclusão da tabela de política principal foi
  detectada pelo watchdog de teste e a TAP foi desligada novamente.
- O processo QEMU pertencente ao ensaio recebeu `SIGKILL` e foi aguardado.
  Overlay e seed foram removidos; console e logs dos receptores foram retidos.
  Os recursos de rede existiam apenas nos namespaces descartáveis.

Esses resultados não demonstram proteção se a própria guarda for removida,
se o watchdog morrer ou não conseguir desligar a TAP, nem recuperação após
reboot ou reconciliação de uma reserva. A autorização permanece válida por
algum tempo após a morte do renovador. Nenhuma admissão do Fleet, regra do host,
saída pública ou sudo real foi exercitada.

## Slot experimental e isolamento incerto — 2026-11-19

`tests/lab-slot-controller.py` é um experimento de um slot, limitado a user,
mount e network namespaces descartáveis. Usa SQLite e lock em `/run` privado:
reserva o slot como `UNKNOWN` antes de criar recursos e só volta a `EMPTY`
após remover e verificar ausência dos recursos de teste. Estado corrompido,
falha de consulta, colisão ou falha de limpeza bloqueia admissão.

`sh tests/lab-slot-recovery-isolated.sh` foi executado duas vezes. Ao retirar
`CAP_NET_ADMIN` de um processo filho, a tentativa de desligar a interface
falhou com `Operation not permitted`; a interface permaneceu ligada, o slot
permaneceu `UNKNOWN` e uma nova admissão foi recusada. A limpeza posterior,
com a capacidade disponível no namespace, foi verificada antes de liberar o
slot. O teste também cobriu falha após criação parcial, saída abrupta após
reserva, duas admissões concorrentes (uma aceita), estado SQLite corrompido
(admissão recusada) e preservação de tabela alheia.

Isso demonstra apenas coordenação entre processos de teste e persistência no
tmpfs durante a vida do namespace. Não prova que a interface ligada está
isolada após falha, nem cobre processo QEMU, perda do host, reboot, durabilidade
do disco, recuperação automática ou admissão real do Fleet. O armazenamento
de teste não é confiável contra adulteração privilegiada e não deve ser usado
como controlador no host.

## Slot experimental com VM real — 2026-11-19

O ensaio `tests/lab-vm-network-isolated.sh` agora usa o controlador experimental
de um slot em `tests/lab-vm-slot.py`, com SQLite no diretório de evidências em
`/mnt/storage`. A reserva é gravada antes da criação dos recursos; a VM QEMU é
mantida pelo processo de teste através do próprio handle `Popen`.

Na execução em
`/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/synthetic-network-e9sqkfyf`:

- Com a VM ativa, o teste marcou o slot como `UNKNOWN` e tentou desligar a TAP
  num processo sem `CAP_NET_ADMIN`. A operação falhou; a TAP continuou ligada
  e uma nova reserva, tentada por outro processo que leu o SQLite, foi recusada.
- Mesmo após `SIGKILL` e `wait` no QEMU de teste, a liberação foi recusada
  enquanto havia recursos remanescentes. Após parar os receptores, remover TAP,
  veth, namespace, tabela de teste, overlay e seed, as consultas de confirmação
  permitiram mudar o slot para `EMPTY`. Uma tabela alheia foi preservada e uma
  nova reserva experimental passou. O SQLite final foi lido novamente como
  `EMPTY`; o ensaio não iniciou uma segunda VM.
- A mesma execução também repetiu a interrupção da conexão TCP estabelecida
  após a perda do renovador e os ensaios anteriores de falha de fechamento e
  exclusão parcial de política.

Esse controle só governa as chamadas do próprio experimento; não impede
processos externos de iniciar QEMU. A falha de desligar a TAP **não prova que
a VM continuou isolada**: o slot permaneceu bloqueado precisamente porque a
segurança era incerta. O teste não cobre morte do controlador, recuperação
do handle QEMU entre processos, perda de energia, reboot, adulteração por root
ou admissão do Fleet. O SQLite em disco foi lido por outro processo e após o
ensaio, mas sua durabilidade sob falhas do host não foi comprovada. Nenhum
helper, firewall do host ou sudo real foi alterado.

## Morte do controlador com VM ativa — 2026-11-19

O ensaio seguinte, em
`/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/synthetic-network-9gfu4q56`,
executou a renovação do prazo num processo controlador separado, enquanto o
processo de teste preservou o handle `Popen` do QEMU:

- Uma tentativa de recuperação enquanto o controlador ainda estava vivo foi
  recusada pelo lock. Depois de `SIGKILL` no controlador, um novo processo de
  recuperação marcou o slot como `UNKNOWN`; outra reserva foi recusada enquanto
  a VM original permanecia ativa. Nenhuma segunda VM foi iniciada.
- Após a expiração da autorização, o console registrou a interrupção da mesma
  conexão TCP (`FLEET_VM_FLOW_CLOSED=3`). A autorização não é revogada
  instantaneamente pela morte do controlador.
- A liberação permaneceu recusada enquanto havia recursos. Após desligar e
  aguardar o QEMU e confirmar a remoção dos recursos do teste, o slot voltou a
  `EMPTY`, lido novamente do SQLite; overlay e seed foram removidos e uma
  tabela alheia permaneceu. Uma reserva experimental subsequente foi aceita.

A recuperação foi acionada explicitamente pelo processo de teste; não há
detecção ou reinício automático. A morte testada foi do controlador que renovava
o prazo, **não** do processo supervisor que detinha o handle da VM. Não foram
testados perda desse handle, reboot, falta de energia, proteção contra root ou
integração ao Fleet. O mecanismo só bloqueia admissões que o consultem; não
impede outros processos de iniciar QEMU. O host e suas regras não foram
alterados.

## Morte do supervisor da VM — 2026-11-19

`sh tests/lab-vm-supervisor-death-isolated.sh IMAGEM_VERIFICADA` testa, apenas
em namespaces descartáveis, um supervisor que cria o QEMU e o controlador
de prazo. Antes da falha, o supervisor entrega os `pidfd`s dos dois processos
a um observador de teste e configura `PR_SET_PDEATHSIG=SIGKILL` nos filhos.
O observador é subreaper e retém os handles; não se usa PID isolado para
decidir qual processo encerrar.

Na execução em
`/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/supervisor-death-xrkgsvhq`:

- A VM estava ativa e trocava dados com o alvo sintético; uma segunda admissão
  foi recusada. Após `SIGKILL` no supervisor, QEMU e controlador encerraram
  por `SIGKILL`; o observador confirmou e aguardou ambos pelos respectivos
  pidfds.
- Outro processo marcou o slot `UNKNOWN`, e nova admissão foi recusada. A
  liberação também foi recusada sem handle do QEMU e enquanto restavam
  recursos. Só após remover e conferir os recursos do ensaio o slot passou a
  `EMPTY` e a reserva experimental voltou a ser aceita. Overlay e seed foram
  removidos; uma tabela alheia foi preservada.

O observador e seus pidfds sobreviveram à falha do supervisor neste ensaio.
Não foi demonstrada recuperação se o observador também morrer, após reboot ou
sem handle confiável; nesses casos a limpeza e a admissão não devem ser
consideradas comprovadas. `PR_SET_PDEATHSIG`, subreaper e a guarda de rede são
experimentos Linux específicos, não uma implementação do Fleet. Nenhuma regra
do host, autorização sudo real ou saída pública foi exercitada.

## Helper experimental para TAP — 2026-11-19

`tests/lab-tap-helper.py` é um helper **de teste**, restrito a namespaces
descartáveis. Aceita somente operações fixas de criação, isolamento e remoção;
instala primeiro uma tabela própria de bloqueio, depois cria uma TAP
identificada e inicialmente desligada. Antes de remover, desliga a interface
identificada e compara a tabela com o estado registrado. O comando adicional
de injeção de falha existe somente para o ensaio. Não há saída, NAT, execução
de shell ou parâmetros arbitrários de rede.

`sh tests/lab-tap-helper-isolated.sh` verifica:

- Colisões de interface e tabela, falha após criação da regra e retenção de
  uma TAP de identidade desconhecida em estado parcial.
- Pacotes sintéticos injetados na TAP bloqueados em `input` e `forward`, com
  contadores da regra e confirmação de ausência nos receptores. Após a remoção
  da guarda no namespace descartável, os mesmos tipos de pacote chegaram aos
  receptores, como controle positivo.
- Falha real de isolamento sem `CAP_NET_ADMIN`, alteração da política,
  alteração da identidade da TAP e perda da tabela. Nos casos incertos o
  recurso ou registro permanece; no teste de tabela perdida, a própria
  operação de isolamento ainda conseguiu desligar a TAP.
- Exclusão limitada aos recursos do experimento, duas criações concorrentes
  (uma aceita) e preservação byte a byte de uma tabela alheia com hooks
  sintéticos.

Essa coexistência se limita às regras artificiais ensaiadas e não comprova
compatibilidade com o firewall real ou com Tailscale. O registro usa tmpfs e
não é um vínculo de propriedade confiável ou durável no host; a verificação de
identidade é sujeita a corridas e adulteração privilegiada. A remoção da própria
guarda não é automaticamente detectada nem isolada por este helper. Naquele
ensaio ele ainda não estava integrado ao slot ou à VM. Não deve ser instalado
via sudo: ainda são necessários desenho e validação de privilégios reais,
recuperação e saída pública antes de qualquer instalação no host.

## Helper, slot e VM real em namespace — 2026-11-19

`sh tests/lab-vm-tap-integrated.sh IMAGEM_VERIFICADA` integra o helper de teste
ao slot experimental e a uma VM Ubuntu em namespaces descartáveis. Antes do
ensaio, a assinatura e o checksum da imagem foram novamente verificados.
Evidências:
`/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/tap-integrated-0nnflu3r`.

- A TAP criada fechada conectou a VM; nem o receptor do host sintético nem o
  receptor encaminhado registrou tráfego. A VM registrou ambos como negados.
- A tentativa de isolamento sem `CAP_NET_ADMIN` falhou com a VM ativa; o slot
  ficou `UNKNOWN` e outra reserva foi recusada. Uma mudança de identidade da
  TAP também foi recusada e a identidade original foi restaurada no teste.
- O kernel recusou remover a TAP enquanto o QEMU a mantinha aberta com
  `Device or resource busy`. A remoção pelo helper falhou, deixando TAP
  desligada, guarda e registro intactos, e o slot continuou reservado.
- Após `SIGKILL` e `wait` no QEMU, o slot ainda recusou liberação enquanto o
  registro do helper existia. O helper removeu a TAP e a guarda; depois de
  remover os demais recursos próprios e confirmar ausência, o slot passou a
  `EMPTY` e a reserva experimental voltou a funcionar. Uma tabela alheia ficou
  inalterada; overlay e seed foram removidos.

O resultado de TAP ocupada foi observado neste kernel e nesta configuração de
QEMU; não é uma garantia geral contra corridas, múltiplas filas ou VMMs. O
helper, seu journal temporário e o slot continuam inadequados para instalação
sudo. O ensaio testa somente o estado fechado, não egress, internet pública,
reboot ou o firewall real; nenhuma regra do host foi alterada.

## Propriedade experimental da TAP por descritor — 2026-11-19

`sh tests/lab-fd-tap-ownership-isolated.sh` testa, apenas em namespaces
descartáveis, uma TAP **não persistente** criada com `IFF_TUN_EXCL`. Um processo
proprietário mantém o descritor, entrega uma cópia a um consumidor sintético e
instala duas tabelas independentes que mantêm input e forward fechados. Ao
identificar a perda de uma guarda, ele encerra o consumidor; o slot do teste
permanece `UNKNOWN` até a verificação dos recursos.

Em duas execuções, o teste verificou:

- Colisão com tabela existente recusada sem criar parcialmente a outra tabela
  ou a TAP; uma tentativa concorrente de criar TAP com o mesmo nome falhou.
- Após perda de uma guarda, a outra descartou um pacote efetivamente injetado
  e o receptor sintético não recebeu dados. O consumidor foi encerrado; ao
  fechar o último descritor, a TAP original desapareceu.
- Uma TAP e uma tabela alheias criadas depois com os mesmos nomes foram
  preservadas e a admissão permaneceu bloqueada. A limpeza da tabela alheia no
  próprio teste foi feita somente pelo fixture que a criou.
- Ao matar o proprietário com `SIGKILL`, o consumidor sintético foi encerrado
  por parent-death signal e aguardado por pidfd; a TAP desapareceu, o slot
  continuou `UNKNOWN` e só foi liberado depois dos checks. Uma tabela alheia
  não foi alterada.

Esse mecanismo **ainda não é propriedade ou recuperação confiável para o
host**. O consumidor é sintético, não o QEMU; o teste conserva handles num
observador e usa estado temporário. A comparação seguida da exclusão da tabela
não é atômica contra concorrente privilegiado; alterações revertidas entre
leituras, perda simultânea das duas guardas, falha de kernel, reboot, morte do
observador e retomada de recursos não foram resolvidos. As duas guardas ficam
sempre fechadas neste ensaio: não há acesso público nem integração ao helper
sudo. Não instalar esse experimento no host.

## TAP não persistente por descritor com QEMU — 2026-11-19

`sh tests/lab-fd-tap-vm-isolated.sh IMAGEM_VERIFICADA guard-loss|owner-death`
integra a TAP não persistente ao QEMU por `-netdev tap,fd=...` dentro de
namespaces descartáveis. As duas guardas permanecem fechadas durante todo o
ensaio. Antes das execuções, a assinatura e o checksum da imagem Ubuntu foram
verificados; o script recebe uma imagem previamente verificada.

Os cenários finais foram executados em paralelo:

- **Perda de guarda:** em
  `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/fd-vm-guard-loss-de7khnun`,
  o QEMU encerrou após a detecção, a segunda guarda permaneceu e a TAP sumiu
  quando seus descritores fecharam. Uma TAP e uma tabela de substituição com
  os mesmos nomes foram preservadas; a admissão permaneceu bloqueada até a
  remoção explícita dos recursos criados pelo próprio fixture e os checks.
- **Morte do proprietário:** em
  `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/fd-vm-owner-death-lwhpuznz`,
  `SIGKILL` no proprietário causou `SIGKILL` no QEMU por parent-death signal;
  um observador sobrevivente confirmou e aguardou o QEMU por pidfd. A TAP
  desapareceu e o slot ficou `UNKNOWN` até a limpeza verificada.
- Em ambos os cenários, o contador da guarda confirmou que pacotes da VM
  alcançaram a regra de input, mas o receptor protegido não recebeu dados.
  Overlay e seed foram removidos, uma tabela alheia foi preservada e o SQLite
  final foi lido como `EMPTY`; uma nova reserva experimental foi aceita somente
  depois da limpeza.

A guarda remanescente foi exercitada com pacote sintético no teste anterior;
neste ensaio com VM foi verificado que ela permaneceu instalada, não que
interceptou um pacote após a perda da primeira. O observador e o pidfd
sobreviveram às falhas. Os checks seguidos de exclusão ainda não são atômicos
contra alterações privilegiadas concorrentes. Perda das duas guardas, morte do
observador, reboot, egress público, sudo e coexistência com firewall real não
foram validados. Este código continua sendo um experimento e não deve ser
instalado como helper do host.

## Perda do observador e dos pidfds da VM — 2026-11-19

`sh tests/lab-vm-lost-observer-isolated.sh IMAGEM_VERIFICADA` mantém o
supervisor, o QEMU, o controlador e os pidfds da VM dentro de um PID namespace
descartável. Um coordenador externo recebe **somente um pidfd separado para o
processo init desse namespace**. A imagem Ubuntu teve assinatura e checksum
verificados novamente antes do ensaio.

Na execução em
`/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/observer-loss-rcwolgjd`,
a VM trocou dados com o alvo sintético. O teste matou o init, que era também o
observador; os processos e handles da VM ficaram confinados ao PID namespace.
O coordenador confirmou o término do init pelo seu pidfd e aguardou o processo
lançador do namespace. Um processo de recuperação marcou o slot `UNKNOWN`:
outra reserva e uma liberação sem handle da VM foram recusadas.

Após a confirmação independente do término do namespace e a remoção dos
recursos de rede e arquivos do ensaio, o slot voltou a `EMPTY` e uma reserva
experimental foi aceita. Overlay e seed foram removidos, uma tabela alheia
permaneceu e os logs de console e receptores foram preservados.

O experimento **não perde todos os handles**: depende do pidfd do init, mantido
fora do namespace, e da garantia Linux de encerramento dos processos do PID
namespace quando seu init termina. Um adaptador de prova usado no teste não é
uma fronteira de confiança adequada para produção. Se o coordenador também
morrer ou esse handle independente for perdido, o ensaio não comprova limpeza
nem liberação segura. Não cobre reboot, escape de isolamento, sudo real,
internet pública ou integração ao Fleet; não alterou a rede do host.

## Falha combinada de guardas e observador — 2026-11-19

**Resultado: falha de isolamento; não instalar o protótipo no host.**
`sh tests/lab-dual-loss-isolated.sh IMAGEM_VERIFICADA` executa uma VM Ubuntu em
rede sintética descartável, sem rota para LAN, Tailscale ou internet. Para
reproduzir uma janela de falha, o teste suspende o proprietário enquanto o
QEMU está ativo e remove as duas guardas numa única transação. Ele mantém a
janela aberta até observar o resultado no receptor sintético; só então mata o
observador. Portanto, é uma sequência de falhas deliberadamente controlada,
não uma medição de falhas fisicamente simultâneas.

- Nas duas execuções, o host sintético estava bloqueado antes da falha, mas
  recebeu dados da VM após a exclusão das guardas. O primeiro recebimento foi
  observado após 1,00 s e 1,20 s, respectivamente. Esses valores não são
  tempo máximo de reação nem garantia de segurança.
- Na segunda execução, o observador confirmou que o QEMU ainda estava ativo
  com ambas as guardas ausentes imediatamente antes de o próprio observador
  ser morto. O encerramento do PID namespace foi confirmado por um pidfd
  independente do seu init; a TAP não persistente desapareceu.
- Outro processo marcou o slot como `UNKNOWN` e novas reservas foram recusadas.
  Após a confirmação da fronteira e a remoção dos recursos próprios, a tabela
  alheia permaneceu intacta e o slot voltou a `EMPTY`; overlay e seed foram
  removidos.

Evidências em
`/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/dual-loss-pnbogaor` e
`/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/dual-loss-enb3or7b`,
incluindo `events.log`, console da VM, receptor sintético e SQLite.

O bloqueio de admissão não bloqueou uma VM já ativa. A recuperação dependeu
de um coordenador e do pidfd do init que sobreviveram ao observador; perda
dessa fronteira, reboot e recuperação de energia não foram comprovados.
Uma proteção independente contra a perda conjunta das guardas precisa ser
desenhada e demonstrada antes de preparar instalação, sudo real ou saída
pública no host. Não houve tráfego para a rede real.

## Barreira em namespace de rede separado — 2026-11-19

`sh tests/lab-independent-fence-isolated.sh IMAGEM_VERIFICADA` ensaia uma
barreira **fechada** em outro namespace de rede. A VM e sua TAP entram em uma
bridge sem interface física; um veth leva ao namespace `fence`, onde estão o
receptor sintético e uma tabela de bloqueio própria. Não existe rota para
internet, LAN ou Tailscale.

O teste suspende o proprietário e, como controle positivo exclusivamente no
laboratório, remove as duas guardas originais: o receptor sintético recebe
dados da VM. Em seguida, instala a barreira no namespace `fence`, restaura as
guardas originais e as remove novamente numa transação, com o QEMU ainda ativo.
Assim, a barreira separada já está presente antes da segunda perda.

Em duas execuções:

- O contador da barreira aumentou **0→1** e **1→2**, respectivamente, após
  a perda das duas guardas originais. O receptor continuou com duas recepções,
  ambas do controle positivo, durante os três segundos adicionais observados.
- O slot foi marcado `UNKNOWN` pelo coordenador de teste e outra reserva foi
  recusada enquanto a VM ainda estava ativa. Após encerrar o observador, o
  processo init do PID namespace foi confirmado encerrado pelo pidfd que
  sobreviveu; o QEMU e sua TAP não persistente deixaram a fronteira de teste.
- O veth, a bridge, o namespace da barreira, o overlay e a seed foram removidos.
  Uma tabela alheia no namespace externo permaneceu inalterada. Após os checks,
  o SQLite registrou `EMPTY` e uma reserva experimental voltou a ser aceita.

Evidências em
`/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/independent-fence-lqxdiwvq` e
`/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/independent-fence-93batj6o`.

O resultado daquele ensaio cobre apenas o receptor IPv4 posicionado **atrás**
dessa barreira. Ele não demonstra proteção de serviços ou endereços no
namespace da VM, tráfego IPv6/L2, internet pública ou que a barreira seja inalcançável por um
processo privilegiado: ambos os namespaces compartilham a mesma autoridade de
teste. A configuração também não detecta automaticamente a perda das guardas;
o coordenador marcou o estado manualmente. Perda da própria barreira, reboot,
sudo real e coexistência com o firewall do host continuam sem prova. Não
instalar como helper do host nem considerar resolvida a falha geral anterior.

## Caminhos locais e falhas da barreira — 2026-11-19

`sh tests/lab-boundary-paths-isolated.sh IMAGEM_VERIFICADA mutate|delete`
executa a VM em uma bridge de laboratório, com receptores sintéticos no lado
da VM para TCP IPv4, TCP IPv6 e quadros Ethernet `0x88b5`. Um quarto receptor
IPv4 fica atrás da barreira em outro namespace. Não há conexão com a rede real.

O proprietário é suspenso e as duas guardas originais são removidas, enquanto
a barreira separada permanece instalada. Em **ambas** as execuções, os
receptores sintéticos locais receberam IPv4, IPv6 e L2; o receptor atrás da
barreira recebeu zero dados. Na configuração ensaiada, portanto, a barreira
separada **não protege serviços ou endereços no lado da VM**. Isso não é prova
de acesso ao host ou à LAN reais.

Um watcher experimental externo comparou a tabela da barreira com o snapshot
do próprio teste. A adição de uma regra (`mutate`) e a exclusão da tabela
(`delete`) foram detectadas, e o watcher sinalizou o init do PID namespace
pelo pidfd, encerrando a fronteira da VM. O receptor atrás da barreira
registrou zero recepções até o encerramento em ambos os ensaios; isso não
comprova ausência de uma janela de vazamento em outras temporizações.

Devido à exposição local já observada, o coordenador marcou manualmente o slot
como `UNKNOWN` antes de injetar a falha da barreira. Outra reserva foi recusada
antes e depois do encerramento. Somente após verificar a fronteira e remover
os recursos próprios o slot voltou a `EMPTY`; uma tabela alheia permaneceu
intacta, e overlay e seed foram removidos.

Evidências:

- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/boundary-paths-mutate-3cofsvek`
- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/boundary-paths-delete-eqwpd9s8`

O watcher usa consultas periódicas, o mesmo domínio de privilégios de teste e
um pidfd fornecido por um coordenador sobrevivente. Morte do watcher, falha de
entrega do sinal, acesso privilegiado concorrente e ausência desse pidfd não
estão resolvidos. **O protótipo continua inapto para instalação no host**;
sudo real, LAN, internet pública e reboot não foram validados.

## Guarda de bridge para caminhos locais e encaminhados — 2026-11-19

`sh tests/lab-bridge-boundary-isolated.sh IMAGEM_VERIFICADA` ensaia uma guarda
adicional da família nftables `bridge`, em namespaces descartáveis. O namespace
de trânsito começa sem endereços IP não-loopback ou sockets TCP/UDP de escuta;
o teste então adiciona intencionalmente três receptores sintéticos nesse mesmo
lado da VM e outros três em um namespace protegido conectado por veth.

Primeiro, com o proprietário suspenso e sem as guardas, o controle positivo
confirma que os seis receptores recebem: TCP IPv4, TCP IPv6 e um quadro Ethernet
de teste em cada localização. A guarda de bridge é instalada nos hooks de
`input` e `forward`, as duas guardas originais são restauradas e então removidas
novamente, com a VM ativa. A fase sem guardas existe apenas dentro do laboratório
descartável e não tem rota para a rede real.

Em duas execuções, após a segunda remoção das guardas originais:

- Os contadores de `input` para IPv4, IPv6 e o EtherType L2 de teste subiram de
  `0/0/0` para `1/2/1`. Os de `forward` subiram de `1/1/0` para `3/2/1`.
- Os seis receptores mantiveram uma única recepção cada, correspondente ao
  controle positivo; não receberam mensagens adicionais durante os três
  segundos de observação após os contadores avançarem.
- O coordenador marcou manualmente o slot `UNKNOWN`, e outra reserva foi
  recusada enquanto o QEMU estava ativo. Após confirmar o encerramento da
  fronteira de processos e remover os recursos próprios, o slot voltou a
  `EMPTY`, uma tabela alheia permaneceu inalterada e overlay e seed foram
  removidos.

Evidências:

- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/bridge-boundary-808usdt0`
- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/bridge-boundary-z_d_ndao`

Esse resultado cobre somente os endereços, sockets e o EtherType sintéticos
ensaiados enquanto a guarda adicional continuou instalada. Não prova proteção
de todos os protocolos L2, sockets associados diretamente à TAP, spoofing,
mudanças de topologia ou serviços reais do host. O proprietário, as guardas e
o coordenador ainda compartilham a autoridade privilegiada de teste; perda ou
adulteração da própria guarda de bridge, reboot e recuperação sem observador
não foram resolvidos. A detecção e o estado `UNKNOWN` foram acionados pelo
coordenador de teste, não por um mecanismo automático de produção. **Não
instalar no host** nem declarar validado sudo real, LAN ou egress público.

## Perda da guarda de bridge com VM ativa — 2026-11-19

O ensaio `tests/lab-bridge-boundary-isolated.sh` aceita agora os cenários
`mutate`, `delete` e `stall-delete`. Após retirar as duas guardas originais,
mantém a guarda de bridge e uma VM ativa enviando tráfego sintético; um watcher
separado consulta a tabela e, ao detectar diferença ou ausência, sinaliza o
init do PID namespace por pidfd. Os seis receptores locais e encaminhados são
observados até o encerramento.

- **Alteração:** em `bridge-boundary-mutate-sije60ot`, o watcher sinalizou a
  fronteira em 0,054 s; os seis receptores não registraram novas recepções.
  A regra de falha criada pelo teste foi removida apenas no namespace
  descartável, e a política restante foi conferida antes da limpeza.
- **Exclusão:** em `bridge-boundary-delete-6w1cdghz`, o watcher sinalizou em
  0,052 s; os receptores não registraram novas recepções observadas. Isso não
  prova que nenhuma temporização poderia permitir tráfego antes do sinal.
- **Watcher suspenso:** em `bridge-boundary-stall-delete-6lhumsvt`, o teste
  suspendeu o watcher antes de excluir a guarda. O receptor local IPv4
  recebeu dados sintéticos enquanto o watcher estava suspenso; houve três
  recepções adicionais no intervalo total de falha e encerramento. Após a
  retomada, o watcher sinalizou em 0,011 s. O bloqueio de admissão **não
  impediu o tráfego da VM já ativa**.

Os caminhos completos ficam sob
`/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/`, com `events.log`, logs dos
receptores, console e SQLite. Nos três casos o slot permaneceu `UNKNOWN` e
recusou reservas até o encerramento e a limpeza; depois voltou a `EMPTY`.
Overlay e seed foram removidos e uma tabela alheia foi preservada.

As durações são observações pontuais, não limites de reação. O watcher consulta
periodicamente, compartilha a autoridade de teste e depende do pidfd e de um
coordenador sobrevivente. Alteração revertida entre consultas, perda ou
suspensão do watcher, falha de sinal, acesso privilegiado concorrente e reboot
continuam sem proteção comprovada. O cenário de watcher suspenso demonstra
falha concreta de isolamento: **não instalar o protótipo no host**, nem
considerar validados sudo real, LAN ou saída pública.

## Guarda adicional de entrada na TAP — 2026-11-19

O cenário `ingress-stall-delete` de
`tests/lab-bridge-boundary-isolated.sh IMAGEM_VERIFICADA ingress-stall-delete`
acrescenta, no laboratório descartável, uma tabela `netdev` com hook `ingress`
na TAP. Ela descarta todo o tráfego de entrada da VM; regras específicas
contabilizam IPv4, IPv6 e o EtherType L2 sintético. A guarda é instalada
antes de suspender o watcher e remover a tabela de bridge.

Em duas execuções, com QEMU ativo, watcher suspenso e guarda de bridge ausente,
os contadores de entrada passaram de **1/0/0 para 12/1/2** para IPv4/IPv6/L2.
Os seis receptores sintéticos locais e encaminhados não registraram novas
mensagens durante a observação. O slot permaneceu `UNKNOWN` e recusou outra
reserva. O watcher foi depois retomado para encerrar a fronteira de processos;
após a limpeza e os checks, o slot voltou a `EMPTY`, overlay e seed foram
removidos e uma tabela alheia foi preservada.

Evidências:

- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/bridge-boundary-ingress-stall-delete-8kwyu5_u`
- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/bridge-boundary-ingress-stall-delete-opx1elhr`

**Limites:** essa guarda é separada da tabela e do hook de bridge, mas usa o
mesmo subsistema `nftables`, kernel e domínio de privilégios. Não protege
contra exclusão da própria tabela `netdev`, limpeza global, falha do kernel
ou autoridade privilegiada concorrente. O teste cobre apenas a TAP e os
protocolos sintéticos observados, não um possível caminho alternativo. O
estado foi marcado `UNKNOWN` pelo coordenador de teste, e o watcher precisou
ser retomado para terminar a VM. A guarda bloqueia toda saída, portanto não
implementa internet pública. Sudo real, reboot, LAN e coexistência com o
firewall do host continuam sem prova; **não instalar no host**.

## Backend de socket fechado, sem encaminhamento — 2026-11-19

`sh tests/lab-socket-boundary-isolated.sh IMAGEM_VERIFICADA` testa outra
fronteira em namespaces descartáveis: o único backend de rede configurado no
QEMU é um `socketpair` conectado a `tests/lab-socket-sink.py`, que consome e
descarta quadros e **não tem caminho de encaminhamento à TAP**. O QEMU é
iniciado com `-nodefaults -nic none` e com o dispositivo de socket explícito.
QEMU e sumidouro usam bounding set vazio e `no_new_privs`; na segunda execução,
o teste também conferiu `/proc` para verificar que nenhum dos dois possuía
descritor `/dev/net/tun`. Isso não é uma análise completa de segurança do VMM.

Uma TAP e seis receptores sintéticos locais/encaminhados existem em outro trecho
do laboratório. Antes de instalar as guardas, o próprio coordenador confiável
injeta diretamente quadros na TAP: os seis receptores recebem os dados. Esse
controle comprova o trecho TAP/receptores, **não** conectividade da VM a ele.
Durante o teste, o sumidouro não recebe a TAP e não pode encaminhar os quadros
da VM para esse trecho.

Em duas execuções, o watcher foi suspenso e as tabelas `netdev` e `bridge` de
teste foram removidas numa transação. O sumidouro continuou contabilizando
novos quadros IPv4, IPv6 e L2 vindos da VM, enquanto os seis receptores não
registraram novas mensagens. Também não houve recepções observadas durante a
suspensão e após a morte do sumidouro. O slot, marcado manualmente como
`UNKNOWN`, recusou reservas; após encerrar processos e conferir limpeza, voltou
a `EMPTY`. Overlay e seed foram removidos e uma tabela alheia foi preservada.

Evidências:

- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/socket-boundary-jbczy5fx`
- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/socket-boundary-iycb68b8`

**Limite essencial:** isto é uma VM de rede completamente fechada, não uma
solução de saída pública. Não há caminho para abrir egress com segurança,
governar destinos, recuperar após reboot ou resistir a comprometimento do VMM
ou do coordenador. A separação independe das regras nftables nesse ensaio, mas
continua dependendo do kernel, da configuração de QEMU e do código confiável.
A perda do sumidouro não prova uma política segura quando uma futura função de
encaminhamento estiver habilitada. O script recebe uma imagem previamente
verificada; não valida a assinatura por conta própria. Sudo real, LAN e
internet pública seguem pendentes; **não instalar no host**.

## Relay UDP sintético sobre socket

`tests/lab-synthetic-relay-isolated.sh IMAGEM_VERIFICADA` exercita um relay
unidirecional de laboratório: ele reconhece um quadro UDP específico e envia
um novo datagrama com payload fixo para `198.51.100.2:34690`. Não devolve
respostas à VM nem implementa encaminhamento transparente. QEMU e relay foram
executados sem capabilities, com `no_new_privs` e sem descritor TAP; o único
backend da VM foi o socket. A imagem foi conferida contra o manifesto assinado.

Na execução `synthetic-relay-fp329lf4`, os três receptores foram alcançados
diretamente antes da política como controle positivo. Depois uma política de
saída no kernel do namespace permitiu apenas o destino e porta sintéticos.
O alvo passou de 1 para 6 recepções, enquanto os receptores que representam
host e LAN permaneceram em 1 cada. O relay contabilizou quadros de host, LAN,
IPv6, L2, spoofing, fragmento e porta errada, além dos aceitos.

Após `SIGSTOP` do relay, foi aguardado um segundo para pacotes já enviados e o
alvo ficou sem novas recepções por mais dois segundos. Após `SIGKILL`, o slot
`UNKNOWN` recusou outra reserva; depois da remoção dos recursos do ensaio
voltou a `EMPTY`. Não se conclui que não havia pacotes em trânsito imediatamente
após a suspensão. A evidência está em
`/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/synthetic-relay-fp329lf4`.
`tests/test_synthetic_relay.py` cobre também quadros truncados, checksum ruim,
destino e payload incorretos.

O teste unidirecional não demonstrou saída pública geral, TCP, DNS, respostas ou proteção
contra comprometimento do relay/VMM. O filtro de saída adicional é nftables no
namespace de laboratório, não uma prova contra sua remoção ou privilégios
concorrentes. O relay não é helper de host e não deve ser instalado via sudo.

### Extensão bidirecional sintética

O relay e o ensaio acima foram posteriormente ampliados para devolver à VM
um único payload fixo `fleet-reply`, recebido pelo socket UDP conectado ao
alvo sintético após um pedido permitido. Há no máximo um pedido pendente,
timeout de um segundo e limite de 60 encaminhamentos por processo. O relay
descarta payloads de resposta diferentes; os quadros devolvidos usam
endereços e portas fixos. Essa tradução não constitui um proxy UDP geral.

Na execução `synthetic-relay-vukwudaf`, a VM registrou
`RELAY_VM_REPLY_OK`, o relay contabilizou pelo menos uma resposta válida e uma
inválida descartada, e o alvo permitido recebeu os pedidos. Os receptores
independentes de host e LAN sintéticos permaneceram com uma recepção cada,
do controle positivo inicial, inclusive durante as falhas. A suspensão do
alvo produziu um timeout. Após suspender o relay e aguardar um segundo para
tráfego em voo, não houve novas recepções no alvo nem respostas observadas
na VM durante dois segundos; após `SIGKILL`, uma nova reserva foi recusada
com slot `UNKNOWN`, e a limpeza terminou com `EMPTY`.

Evidências adicionais em
`/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/synthetic-relay-vukwudaf`;
o ensaio anterior da extensão também passou em `synthetic-relay-4k0mo1qf`.
O socket UDP conectado filtra origem e porta no kernel, mas o payload é fixo:
respostas atrasadas ou repetidas não têm identificador para correlação e podem
ser confundidas com uma solicitação posterior. Não há autenticação,
garantia de entrega, DNS, TCP, IPv6, egress público, proteção contra processo
privilegiado ou isolamento comprovado de um relay comprometido. O estado de
slot é apenas experimental. Não instalar no host nem interpretar esse ensaio
como validação de sudo, LAN real ou recuperação após reboot.

### Correlação de respostas sintéticas

O ensaio foi ampliado novamente: o pedido da VM inclui identificador de
8 bytes, e o relay associa um nonce aleatório de 16 bytes a cada pedido
encaminhado. O alvo devolve ambos; somente a resposta do socket UDP conectado
com identificador e nonce do pedido pendente é devolvida à VM. O relay mantém
um único pedido pendente por até um segundo e aceita no máximo 60 envios por
processo; não há fila de solicitações concorrentes.

Em duas execuções, o alvo de teste enviou primeiro uma resposta com os dados
corretos a partir de outro endereço sintético e não enviou a resposta válida
desse pedido. O primeiro pedido expirou. Durante o pedido seguinte, o alvo
enviou a resposta atrasada do primeiro e duas cópias da resposta correta do
segundo. Na execução `synthetic-relay-buiddc_k`, a VM não recebeu a resposta
do identificador 1 e recebeu uma única resposta para o identificador 5; o relay
contabilizou duas respostas fora de correlação e um timeout. A filtragem da
origem incorreta decorre do socket UDP conectado, não de um contador de
pacotes descartados no relay.

Os receptores independentes de host e LAN sintéticos permaneceram com apenas a
recepção anterior à política. A suspensão posterior do alvo gerou outro timeout;
após suspender e matar o relay, `UNKNOWN` bloqueou admissão até a limpeza.
O resultado final foi `EMPTY`. Evidências em
`/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/synthetic-relay-buiddc_k`
e `synthetic-relay-m49c0cbl`.

O nonce evita a associação observada de uma resposta atrasada a outro pedido
enquanto o processo está ativo, com probabilidade residual de colisão.
Não autentica o alvo, não garante unicidade dos IDs fornecidos pela VM,
entrega exatamente uma vez, nem recuperação ou deduplicação entre reinícios.
Não é um relay público geral ou uma fronteira comprovada contra comprometimento
ou privilégios concorrentes; sudo real, LAN real, reboot e internet pública
continuam pendentes.

### DNS e TCP sintéticos por broker de mensagens

`sh tests/lab-dns-tcp-egress-isolated.sh` testa um broker sem capabilities e
com `no_new_privs`, conectado a um cliente de teste por `socketpair`
`SOCK_SEQPACKET`. O cliente **não é uma VM**: este é um ensaio novo da
política de serviços, não uma validação de DNS ou TCP transparente do QEMU.
O broker aceita operações fixas, limitadas e sequenciais; não aceita
endereços ou portas arbitrários.

O DNS sintético UDP consulta somente `service.example` e responde com um
registro A fixo; o broker verifica a resposta DNS completa e o identificador
da transação. O serviço TCP sintético recebe e devolve mensagens fixas. No
namespace descartável, nftables permite apenas `198.51.100.2:35353/udp` e
`198.51.100.3:38080/tcp`, além de loopback, e bloqueia o restante da saída.
Esses endereços e serviços existem apenas no namespace receptor.

Em execuções repetidas (`/mnt/storage/dns-tcp-egress-yzc550xi`,
`/mnt/storage/dns-tcp-egress-78cszp8x` e `/mnt/storage/dns-tcp-egress-8eg9056_`),
todos os oito serviços receberam
controles positivos antes da política. Em seguida, DNS e TCP permitidos
responderam; receptores DNS/TCP representando host e LAN não tiveram novas
recepções. Tentativas deliberadas de contornar a lista da aplicação para
host, LAN e combinações de porta/destino trocadas foram recusadas pelo kernel
e os receptores correspondentes permaneceram inalterados.

A suspensão do serviço DNS resultou em erro limitado por timeout, e uma
consulta posterior passou após sua retomada. A suspensão e morte do broker
deixaram uma solicitação enfileirada no socket sem resposta; no último ensaio
ela também não chegou ao alvo TCP. Não foi demonstrada sua recuperação nem
ausência de efeitos para trabalho já enviado.
Os processos, veth, namespace e tabela de teste foram removidos. Os logs dos
receptores estão nos diretórios de evidência.

Não há integração com VM, resolução geral, DNS por TCP, fluxo TCP arbitrário,
TLS, política por IP público ou prova contra alteração da tabela por outro
processo privilegiado. A resposta sintética DNS não resolve um endereço real
nem autoriza seu uso. O teste não comprova isolamento do host/LAN reais,
reboot ou sudo; não instalar no host.

### Operações DNS/TCP por porta serial de uma VM

`sh tests/lab-dns-tcp-vm-isolated.sh IMAGEM_VERIFICADA` conecta uma VM Ubuntu
QEMU a esse broker por `virtio-serial`, socket Unix e um adaptador de framing
limitado. O QEMU usa `-nodefaults -nic none`: **não existe interface de rede
da VM nesse ensaio**. Os comandos são mensagens de aplicação fixas; DNS e TCP
são executados pelo broker, não pela pilha de rede da VM. QEMU, adaptador e
broker executam sem capabilities e com `no_new_privs`; o ensaio conferiu que
nenhum deles tinha descritor `/dev/net/tun`.

Em duas execuções, a VM registrou `dns:203.0.113.2`, `tcp:fleet-response`,
recusas dos pedidos fixos para host e LAN, e recusa pelo kernel das tentativas
de teste que contornavam a lista de aplicação para host, LAN e portas trocadas.
Os oito receptores receberam controles positivos antes da política. Na
execução final, DNS e TCP permitidos passaram de 1 para 3 recepções cada; os
quatro receptores DNS/TCP que representam host e LAN permaneceram em 1.

Ao suspender o serviço DNS, a VM observou `dns:upstream-error`; após a
retomada, uma consulta posterior passou. Ao suspender o broker, depois de um
segundo de acomodação, a VM não registrou novas respostas por dois segundos.
Após `SIGKILL`, o slot marcado manualmente `UNKNOWN` recusou outra reserva;
QEMU, adaptador, broker, receptores e rede foram encerrados, overlay e seed
removidos, e o slot terminou `EMPTY`. Não se conclui que solicitações já em
voo foram recuperadas ou que efeitos tenham sido desfeitos.

Evidências:

- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/dns-tcp-vm-2ic_b20o`
- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/dns-tcp-vm-d82ea5fu`

O resultado cobre apenas operações de aplicação sintéticas e serial;
não cobre DNS/TCP transparentes, internet pública, controle de destinos
arbitrários, relay comprometido, tráfego IPv6, reboot ou sudo real. O filtro
nftables compartilha privilégios com o ambiente do ensaio e não prova proteção
contra sua remoção por outro processo privilegiado. Não instalar no host.

### DNS e TCP da pilha da VM sobre backend de socket

`sh tests/lab-native-socket-vm-isolated.sh IMAGEM_VERIFICADA` usa uma placa
virtio-net na VM, ligada por `socketpair` ao backend `socket` de um segundo
processo QEMU. Esse processo atua apenas como hub entre o socket e o backend
de rede de usuário `libslirp`; ambos os processos QEMU estão em namespaces
descartáveis, sem capabilities e com `no_new_privs`, sem descritor TAP. A
pilha da VM inicia uma consulta DNS UDP e uma conexão TCP normais aos serviços
sintéticos; não usa o broker serial da seção anterior.

A VM consulta diretamente um servidor DNS sintético em
`198.51.100.2:35353/udp` e troca bytes TCP com `198.51.100.3:38080`.
Uma tabela nftables no namespace do tradutor permite somente esses dois
destinos/portas e bloqueia o restante, inclusive loopback. Os receptores
sintéticos de host, LAN e loopback receberam controles positivos antes da
política, mas nenhuma recepção adicional durante o ensaio. No resultado final,
os receptores permitidos passaram de 1 para 3 recepções cada.

Após `SIGSTOP` no processo do tradutor, a VM observou falhas DNS e TCP; após
`SIGCONT`, ambas as operações voltaram a funcionar. Após `SIGKILL`, a VM
observou novamente falhas e o slot marcado manualmente `UNKNOWN` recusou
uma reserva. As verificações finais removeram processos, interface, namespace,
tabela, overlay e seed e registraram `EMPTY`; uma tabela alheia foi preservada.
As execuções completas finais estão em:

- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/native-socket-vm-qw46_w22`
- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/native-socket-vm-46uxbf27`

A primeira tentativa (`native-socket-vm-1ktbxqv6`) falhou porque o tradutor
foi iniciado com `-S`; a VM não alcançou os serviços. Os discos dessa tentativa
foram preservados pelo caminho conservador de falha. Um controle ARP isolado
reproduziu o problema e orientou a remoção de `-S`.

O DNS testado é uma consulta sintética diretamente a um endereço/porta
fixos, não resolução geral pelo sistema da VM. O teste não comprova acesso
público geral, bloqueio de todas as faixas privadas, IPv6, política contra
comprometimento do tradutor ou remoção das regras, nem recuperação após reboot.
QEMU/libslirp, filtro nftables e kernel permanecem componentes confiáveis
nesse experimento. Host/LAN reais e sudo não foram exercitados; não instalar
no host.

### Perda da política do tradutor socket/libslirp

**Falha de isolamento observada: não instalar no host.** O cenário
`sh tests/lab-native-socket-vm-isolated.sh IMAGEM_VERIFICADA guard-loss`
remove a tabela `inet native_socket_lab` no namespace descartável enquanto a
VM e o tradutor socket/libslirp permanecem ativos. O coordenador de teste
marca manualmente o slot `UNKNOWN` antes da remoção; não há detecção automática.

Antes da remoção, os seis receptores DNS e TCP que representam host, LAN e
loopback permaneceram com apenas a recepção do controle positivo. Após
remover a tabela, todos os seis receberam tráfego adicional em três execuções.
Na execução final `native-socket-vm-guard-loss-2hzva3hb`, os incrementos
DNS/TCP foram respectivamente **2/1 para host**, **2/2 para LAN** e **2/2
para loopback**. O loopback é do namespace descartável do tradutor, não o
loopback real do host.

O slot bloqueou outra reserva enquanto a VM estava ativa. Após encerrar VM e
tradutor e remover os discos, uma tentativa de liberar o slot ainda foi
recusada enquanto a rede de teste existia; a liberação ocorreu somente após
removê-la e verificar os recursos, resultando em `EMPTY`. Uma tabela alheia
foi preservada. Evidência em:

- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/native-socket-vm-guard-loss-oe8z93ol`
- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/native-socket-vm-guard-loss-9e33qsh_`
- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/native-socket-vm-guard-loss-2hzva3hb`

Uma primeira execução com sufixo `2k64a6tg` não injetou essa falha por uma
colisão do nome da variável de modo com o laço de serviços; apenas repetiu o
cenário normal. A variável foi corrigida antes das três execuções acima.
Os resultados não demonstram acesso à rede real, nem todos os protocolos ou
uma recuperação após reboot. Demonstram que a separação por socket/libslirp,
sozinha, não protege a VM ativa quando a política de saída desaparece.

### Topologia fechada independente da tabela nftables

`sh tests/lab-topology-egress-vm-isolated.sh IMAGEM_VERIFICADA` testa uma
topologia diferente, inteiramente descartável: a VM usa socket/libslirp; o
namespace do tradutor tem apenas rotas `/32` para dois serviços sintéticos em
outro namespace, sem rota default. Os serviços que representam host e LAN,
assim como um loopback sintético, ficam em um terceiro namespace sem enlace
com o tradutor durante o teste. Antes de iniciar QEMU, não havia listeners
TCP/UDP no namespace do tradutor. QEMU e tradutor foram conferidos sem capabilities, com
`no_new_privs` e sem descritores TAP.

Antes de iniciar a VM, um veth temporário e rotas temporárias conectaram o
tradutor aos serviços sintéticos de host e LAN: os controles UDP e TCP
chegaram a todos eles. O loopback foi controlado localmente no namespace
protegido. O veth temporário foi então removido, e consultas de rota
confirmaram ausência de caminho para host e LAN sintéticos.

Com a VM ativa, a tabela nftables do experimento foi removida. Em duas
execuções, a VM continuou recebendo respostas DNS e TCP dos serviços
permitidos, enquanto os seis receptores protegidos ficaram em uma recepção
cada, anterior à remoção do enlace. A VM também registrou falhas nas
tentativas sintéticas para host, LAN e gateway. Após suspender o tradutor,
DNS e TCP falharam; após retomá-lo, voltaram a funcionar. A morte do tradutor
deixou o slot manualmente marcado `UNKNOWN`, bloqueando nova reserva até a
limpeza. Overlay e seed foram removidos, uma tabela alheia foi preservada e o
slot terminou `EMPTY`.

Evidências:

- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/topology-egress-vm-lnu8bwo1`
- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/topology-egress-vm-63o71o22`

Essa é uma prova da topologia **sem caminho para os receptores protegidos**,
não de uma política que permita internet pública e bloqueie simultaneamente
todos os endereços locais. Adicionar rota default, outro enlace ou um
encaminhador muda a fronteira e exige novos testes; uma autoridade privilegiada
pode alterar rotas ou interfaces. O loopback protegido foi colocado em outro
namespace, e a ausência de listeners no tradutor é uma pré-condição observada,
não uma garantia contra criação posterior de serviços. Comprometimento do
tradutor, acesso à LAN real, IPv6, reboot, sudo e recuperação automática
continuam sem prova. Não instalar no host.

### Encaminhador sintético e rota default

`sh tests/lab-topology-egress-vm-isolated.sh IMAGEM_VERIFICADA router`
introduz um namespace encaminhador entre o tradutor socket/libslirp e os
serviços DNS/TCP sintéticos. O namespace do tradutor tem rota default para o
encaminhador, que tem encaminhamento IPv4 habilitado e rotas `/32` para os
serviços permitidos. O encaminhador não tem rota default nem rota para os
receptores de host e LAN sintéticos, que continuam em namespace sem enlace.
Não existe conexão com a internet ou rede real.

Um enlace temporário confirmou a acessibilidade prévia dos receptores
protegidos e foi removido antes da VM iniciar. O loopback protegido foi
controlado dentro de seu namespace; o tradutor não tinha listeners TCP/UDP
antes do início da VM. Após remover a tabela nftables do tradutor, a VM
continuou recebendo DNS e TCP dos alvos sintéticos, e o contador de pacotes
transmitidos na interface de saída do encaminhador avançou (30→36 e 30→37
nas duas execuções). Os receptores protegidos permaneceram com apenas uma
recepção de controle cada.

**Lacuna observada:** após a remoção da tabela, a VM alcançou os serviços
DNS e TCP sintéticos instalados no endereço local do próprio encaminhador;
cada um passou de 1 para 2 recepções. Portanto, a ausência de rota para host
e LAN não protege serviços locais do encaminhador. A topologia não é uma
fronteira geral segura para uso no host.

A suspensão e retomada do tradutor interromperam e restauraram o tráfego
permitido; após sua morte, o slot `UNKNOWN`, marcado manualmente, recusou
reserva até a remoção da rede e dos processos e terminou `EMPTY`. A tabela
alheia permaneceu. Evidências:

- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/topology-egress-vm-router-mesieoek`
- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/topology-egress-vm-router-60pjynww`

A primeira preparação (`topology-egress-vm-router-_7qsvlcc`) falhou antes
de iniciar a VM: faltava uma rota de vizinhança para o gateway na rede de
teste. A rota foi acrescentada no namespace descartável antes das duas
execuções acima. O cenário anterior sem encaminhador também passou novamente.

O encaminhador tem somente rotas para dois destinos fixos, não uma rota para
a internet pública. Acrescentar uma saída real ou uma rota para a LAN altera
a propriedade demonstrada. IPv6, proteção contra alteração privilegiada de
rotas, acesso público geral, reboot e sudo real continuam sem prova.

### Guarda local no encaminhador sintético

O cenário `router-fence` de `tests/lab-topology-egress-vm-isolated.sh` instala
uma tabela nftables de entrada **dentro do namespace do encaminhador**, separada
da tabela de saída do tradutor. Ela descarta tráfego direcionado ao próprio
encaminhador vindo da interface do tradutor; o tráfego encaminhado aos dois
serviços sintéticos continua permitido. Antes de instalar a guarda, controles
TCP e UDP confirmam que os receptores locais do encaminhador funcionam.

Em duas execuções com VM ativa e tabela do tradutor removida, os contadores
locais da guarda subiram de TCP/UDP `0/0` para `2/1`; os dois receptores
locais permaneceram com apenas a recepção do controle. Os serviços
encaminhados responderam, e os receptores de host, LAN e loopback sintéticos
permaneceram inalterados. A suspensão e retomada do tradutor interromperam e
restauraram DNS/TCP permitidos; a guarda permaneceu instalada.

O teste então removeu deliberadamente a guarda **do encaminhador**: a VM
voltou a alcançar seus receptores locais TCP e DNS. O slot experimental,
marcado `UNKNOWN` pelo coordenador, recusou novas reservas, mas não bloqueou
essa VM ativa. Após encerrar os processos e remover os recursos, terminou
`EMPTY`, com uma tabela alheia preservada. Evidências:

- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/topology-egress-vm-router-fence-edpsaa4l`
- `/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/topology-egress-vm-router-fence-bhs77z92`

A proteção resiste à perda da **outra** tabela no tradutor, não à sua própria
remoção. As duas tabelas compartilham kernel, nftables e autoridade de teste;
limpeza global, alteração por processo privilegiado, roteamento para uma LAN
real e comprometimento não foram resolvidos. Os únicos destinos encaminhados
são sintéticos, sem internet. Não instalar no host; sudo real e reboot seguem
sem prova.

### LAN conectada e saída pública sintética

O cenário `router-lan` de `tests/lab-topology-egress-vm-isolated.sh` acrescenta
ao laboratório uma LAN sintética efetivamente conectada ao encaminhador e um
namespace de upstream sintético pela rota default do encaminhador. A VM acessa
um DNS e um serviço TCP no endereço de documentação `203.0.113.10`; não há
enlace com internet ou rede real. Um veth temporário confirma previamente que
os receptores de host e LAN funcionam. Em seguida ele é removido; a rota para
host e LAN permanece pelo encaminhador.

Com a VM ativa, a tabela de saída do tradutor é removida. A tabela independente
no namespace do encaminhador bloqueia entrada aos próprios serviços locais e
encaminhamento aos dois endereços de host e LAN sintéticos; outros destinos
são encaminhados no laboratório. O teste verifica contadores TCP/UDP em ambos
os hooks e exige que os receptores protegidos não mudem. O arquivo
`counts.json`, gravado somente após essas verificações, registrou 1 recepção
de controle para cada serviço protegido, 2 DNS e 3 TCP no destino público
sintético. A VM registrou `NATIVE_PUBLIC_DNS=OK` e `NATIVE_PUBLIC_TCP=OK`.

O ensaio então remove deliberadamente a própria guarda do encaminhador. Os logs
da VM registraram `NATIVE_HOST=OK`, `NATIVE_HOST_DNS=OK`, `NATIVE_LAN=OK` e
`NATIVE_LAN_DNS=OK`; os logs finais dos receptores confirmaram recepções além
do controle. Assim, **perder essa segunda guarda também causa vazamento**.
O slot persistido terminou `EMPTY` e overlay e seed estão ausentes; o código
somente libera o slot depois de verificar e remover os recursos. O processo
QEMU do ensaio não permaneceu ativo.

Evidência recuperada após reinicialização do servidor em
`/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/topology-egress-vm-router-lan-f73h4ph3`.
A saída completa do comando foi interrompida pela reinicialização; os arquivos
`counts.json`, `serial.log`, logs dos receptores e SQLite foram lidos de volta.
Não se conhecem os valores numéricos dos contadores nftables dessa execução.

A regra do encaminhador bloqueia apenas dois endereços sintéticos específicos,
não faixas privadas em geral. Ela compartilha o subsistema nftables e
privilégios com o restante do laboratório; sua remoção comprovadamente expõe
a LAN sintética. O destino público é simulado, não existe saída pública real;
sudo, proteção da LAN real, alterações privilegiadas e reboot não foram
validados. **Não instalar esse protótipo no host.**

### Dois destinos sintéticos com resposta

O relay experimental e o filtro de saída do namespace foram ampliados para
permitir apenas UDP `34690` a dois destinos explícitos, `198.51.100.2` e
`203.0.113.2`. A VM alterna pedidos para ambos; o relay usa um socket UDP
conectado por destino, preservando o único pedido pendente, seu ID, nonce,
destino e timeout. As respostas são emitidas com o endereço sintético do
destino correspondente. A política de teste também permite loopback interno;
não é uma política geral para um processo comprometido.

Em duas execuções completas, a VM observou respostas dos dois destinos. Na
execução `synthetic-relay-bh2tuodx`, os receptores permitidos passaram de uma
recepção de controle para 5 e 4; os receptores que representam host, LAN e
destino não permitido `203.0.113.3` permaneceram em uma recepção cada. Todos
foram atingidos antes da política como controle positivo. O filtro de saída do
kernel e a lista fixa do relay bloquearam os caminhos não permitidos no ensaio;
isso não prova qual das duas camadas, isoladamente, bloqueou cada tentativa.

Com o alvo A suspenso, houve timeout e as respostas do alvo B ainda avançaram
de 1 para 3. Com o relay suspenso, após um segundo para tráfego em voo, os
dois alvos e as respostas observadas na VM permaneceram quietos por dois
segundos. Após matar o relay, o slot `UNKNOWN` recusou novas reservas até a
limpeza verificada, terminando `EMPTY`. O ensaio também repetiu as respostas
atrasadas, duplicadas e de origem incorreta do cenário anterior.

Evidências em
`/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/synthetic-relay-rfrqwii2`
e `synthetic-relay-bh2tuodx`. Os dois alvos estão no mesmo namespace de
receptores descartável, em sub-redes sintéticas, sem internet. Isso não prova
política de internet pública geral, DNS, TCP, IPv6, proteção do host/LAN real,
resiliência a relay comprometido, reboot ou sudo. Não instalar no host.

## Saída pública por slirp sem rota default — 2026-11-21

`sh tests/lab-public-egress-vm-isolated.sh IMAGEM_VERIFICADA` prepara o
protótipo num user namespace com root mapeado. O processo `slirp4netns` usa a
rede do host só como saída; o tap `rfegress0` e a VM nascem num netns filho.
O host não recebe rota, endereço, tabela nft nem bridge novos. O `--configure`
do slirp instala rota default nesse netns; o ensaio a apaga e interrompe se
ela permanecer. As únicas rotas de saída são `/32` via `10.0.2.2` para
`1.1.1.1`, `8.8.8.8` e os registros A do domínio autorizado que não coincidem
com um endereço do próprio host. Blackholes cobrem as faixas não públicas,
incluindo `10.0.0.0/8`, `100.64.0.0/10`, RFC1918, link-local, multicast e
`240.0.0.0/4`. A rede de trânsito `10.0.2.0/24` continua mais específica que
o blackhole de `10.0.0.0/8`. Endereços do host fora dessas faixas e fora do
trânsito recebem blackhole `/32`. NAT e o drop de encaminhamento IPv6 e das
faixas bloqueadas existem só no netns, como camada adicional. O controle que
sobra se essa tabela nft desaparecer é a ausência de rota, não a tabela.

Antes da VM, o mesmo comando repete a perda de rota num veth sintético. Com
apenas o `/32` público, apagar os blackholes manteve `192.168.50.2` fechado.
Inserir `default via 10.0.2.2` fez um observador de 20 ms derrubar
`rfegress0`. Nesta execução o log foi `ROUTE LOSS: upstream down; synthetic
LAN deliveries during reaction=10`. Essas dez entregas ocorreram dentro da
janela, para um receptor no namespace de teste, e a conexão seguinte falhou
com o enlace já desligado. A janela não é zero e o valor varia entre
execuções.

A VM usou a imagem Ubuntu 24.04 já conferida. O guest resolveu
`cicleta.lucaswilliameufrasio.com` por DNS direto em `1.1.1.1`, concluiu TLS
com o armazenamento de CAs da imagem e recebeu resposta HTTP. O probe não
segue redirecionamento nem consulta OCSP. Em seguida registrou negação para
`10.1.0.1`, `172.16.0.1`, `192.168.1.1`, `169.254.1.1`, `100.64.0.1`, o
gateway slirp `10.0.2.2` na porta do receptor do host, `fd00::1`,
`2606:4700:4700::1111` e dois endereços não loopback do host. Não houve linha
`=OPEN`. O `127.0.0.1` do guest é o próprio guest; o loopback do host foi
observado pelo receptor em `127.0.0.1` e pela tentativa ao gateway slirp com
`--disable-host-loopback`. Três receptores do host, ligados antes da VM,
permaneceram com uma recepção cada: a do controle positivo. Depois do
`SIGKILL` do slirp, o laço do guest — que ainda tinha duas confirmações HTTPS
— passou a registrar `PUBLIC_HTTPS=DENIED`, e os receptores continuaram em 1.

O slot foi marcado `UNKNOWN` e recusou outra reserva. QEMU recebeu SIGTERM do
supervisor. Overlay, seed, os dois taps e as tabelas `public_egress_nat` e
`public_egress_guard` do netns foram removidos; o slot terminou `EMPTY`.
A comparação do host usa o texto de `ip -4 route` e as tuplas interface,
endereço e prefixo, sem o lifetime que muda a cada segundo. O processo
terminou com código 0 e a contagem de rotas IPv4 do host continuou em 2.
Interfaces `rflab0` e `rfegress0` não ficaram no host. `nft` no netns do host
não é legível por este usuário; o ensaio não o altera, e a liberação do slot
só ocorreu depois de as tabelas do netns de laboratório terem sumido.

Evidência em
`/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/public-egress-vm-8fth0ylf`.
`python3 tests/test_public_egress.py` cobriu a classificação: faixas privadas,
CGNAT, IPv6 e o trânsito `10.0.2.0/24`. Uma tentativa anterior no mesmo dia
morreu antes do boot, num erro de pertinência de endereço e num snapshot
sensível a lifetime; esta execução já contém a correção.

O alcance positivo é o domínio autorizado e os dois resolvedores, não a
internet em geral. Reintroduzir rota default reabre o caminho até o enlace
cair, como mostram as dez entregas. O alvo `100.64.0.1` é sintético; não
exercita um peer Tailscale nem autoriza mudança nas tabelas Tailscale. IPv6
foi negado no guest, sem receptor IPv6 remoto. Não há helper sudo, prova de
reboot, integração ao Fleet nem instalação no host. O README permanece para a
última etapa do plano.

## Limites da mesma topologia — 2026-11-22

O observador da rota default passou a esperar o evento netlink, com uma
consulta curta para o caso de o aviso chegar antes do socket. Na execução
isolada e de novo junto com a VM, o log foi `reaction=1`. A janela diminuiu
em relação às dez entregas anteriores e continua existindo.

`sh tests/lab-public-egress-cleanup-isolated.sh` cria o slot, marca
`UNKNOWN` e tenta liberar. Com `rflab0` ainda presente, a liberação é
recusada e uma nova reserva também. Depois da interface removida, a tabela
`public_egress_guard` produz a mesma recusa. Sem interface e sem tabela, a
liberação chega a `EMPTY`.

A VM da execução `public-egress-vm-c5kf_fa4` repetiu DNS e HTTPS do domínio
autorizado. Além das negações já vistas, o guest não abriu TCP para um par
sintético em outro netns (`198.51.100.10` e `fd00:9::10`), nem para o
gateway `192.0.2.1` e `fd00:2::1`. Cada um desses quatro receptores teve uma
conexão de controle antes da VM e permaneceu em 1. Os três receptores do
host também permaneceram em 1. O guest não montou 9p, virtiofs, NFS ou CIFS
e não encontrou o socket do Docker; isso mostra que o QEMU deste ensaio não
recebeu esses compartilhamentos, não que um escape do QEMU seja impossível.
Um disco virtio cru de 64 MiB recebeu escrita até a falha, o arquivo no host
continuou com 67108864 bytes e o guest registrou `DISK_BOUND=HELD`. O
`SIGKILL` do slirp fez o HTTPS seguinte falhar. O slot terminou `EMPTY`. As
rotas IPv4 do host continuaram em 2.

`sh tests/lab-public-egress-supervisor-isolated.sh` espera o QEMU subir e
envia `SIGKILL` ao processo que é pid 1 do namespace. QEMU e o slirp do
ensaio desapareceram. O slot ficou `ACTIVE`, não `EMPTY`: a morte do
supervisor não faz a limpeza dos arquivos. O harness removeu o diretório
depois de registrar o estado. As rotas do host continuaram em 2 e o slirp
alheio do Docker rootless permaneceu.

Evidência da VM em
`/mnt/storage/runner-fleet-signed-image-Lhb2NvtV/public-egress-vm-c5kf_fa4`.
O par da outra rede é um netns sintético, não uma segunda Ubuntu. O IPv6
remoto comprovado é o desse netns; o endereço público IPv6 foi só negado no
guest. O limite de disco é o segundo disco, não uma cota do overlay raiz.
Não houve reboot, helper sudo, instalação no host, integração ao Fleet nem
revisão do README.
