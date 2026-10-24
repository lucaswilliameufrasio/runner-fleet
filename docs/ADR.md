# Decisões de implementação

1. **REST + webhooks na primeira versão.** Escopos por repo e org, registro tradicional efêmero, labels cumulativas e grupos. O cliente oficial `actions/scaleset` é alternativa para escala maior, não uma segunda implementação concorrente. Não validamos Scale Sets em GitHub real neste ambiente.
2. **Monólito Go + SPA SvelteKit.** Um banco SQLite local, WAL e transações para reservas/comandos. Não exige Node ou Kubernetes na execução do servidor.
3. **mTLS direto no Go.** Nginx stream passa TLS do hostname de agentes; não aceitar certificado por header arbitrário. Rotação de certificado individual com sobreposição de duas identidades e revogação no banco.
4. **Capacidade antes de efeitos externos.** Slots reservados precedem inscrição e criação. Ociosos também consomem orçamento. Estado desconhecido mantém reserva. GitHub faz matching e não permite pin de job por nosso coordenador.
5. **Containers efêmeros para código confiável.** Base rootless sem host mounts. CPU/RAM via runtime; disco reservado/monitorado, quota rígida por filesystem fora do suporte atual. Nenhum cache local compartilhado entre jobs; workflows podem usar actions/cache no GitHub.
6. **Docker isolado por job opt-in.** Sidecar Docker privilegiado apenas em máquina dedicada e dentro de Docker rootless. Volume/socket privados por instância, rede compartilhada. Compatibilidade e segurança operacional dependem do canário; não é fronteira de VM para código hostil.
7. **Drain via GitHub.** Remover registro somente se API permitir e, depois, parar listener local. Em indisponibilidade de API, aguardar; nunca matar job com base apenas em um heartbeat antigo.
8. **Criptografia de backups.** Argon2id + AES-GCM, formato versionado, VACUUM INTO, upload S3 verificado por HEAD antes de retenção. Recovery kit fora do banco é obrigatório. Senhas não ficam em texto no SQLite.
9. **Migração conservadora.** Patches somente em destinos estáticos validados pelo parser. Não reformatar arquivo inteiro nem usar regex em matrizes/expressões. SHA atual deve coincidir antes de PR.
10. **Distribuição assinada.** Ed25519 protege manifestos; checksum verifica binários. Chave de assinatura fica fora do pacote; a confiança inicial pode ser fixada antes de bootstrap.

Skills utilizadas nesta entrega: openai-library:library para persistência do pacote. Nenhuma skill externa de terceiros foi invocada; o plano pede aplicar instruções disponíveis, sem exigir um repositório de skills particular.
