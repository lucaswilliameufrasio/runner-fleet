# Validação de implantação

Use repositórios de teste antes de ativar produção. Não execute contra orgs de terceiros sem autorização.

- [ ] Registrar App em duas organizações e um repo pessoal; confirmar isolamento das instalações.
- [ ] Permissões de conteúdo/Actions/admin/runners/grupos e capacidade do plano GitHub.
- [ ] Ver inventário de runner/grupo com acesso selecionado e workflow reutilizável externo.
- [ ] Enroll por comando e SSH privado, fingerprint divergente recusada, código não reutilizável.
- [ ] mTLS público na porta 443 via SNI; agente sem certificado/identidade revogada rejeitado.
- [ ] Rootless Docker/cgroup v2/systemd na distro real; doctor e limites CPU/RAM verificados.
- [ ] Build real x64 e ARM64 em máquinas próprias; não inferir sucesso ARM64 a partir de cross-compile.
- [ ] Perfil base, Node/Bun, Go e Rust; ferramentas e actions de seus workflows.
- [ ] Docker sidecar dedicado: build, push, container actions, job containers, service containers, volumes/rede, limpeza.
- [ ] Desconectar control plane/agent/GitHub separadamente; conferir reservas e ausência de duplicação.
- [ ] Reboot no meio do provisionamento e no job; conferir resíduos e estado atribuído pelo GitHub.
- [ ] Drain ocioso e busy; nenhuma interrupção indevida. Runner removido do GitHub antes do stop.
- [ ] Memória/disco sob pressão; suspender slots novos. Orçamento de disco não é quota rígida.
- [ ] Webhooks atrasados/duplicados; polling converge.
- [ ] PR em branch de teste; revisão do diff; SHA divergente recusado; rollback por revert.
- [ ] S3/R2 real: upload, HEAD, retenção scoped, restore, senha errada e recovery kit.
- [ ] Webhook Discord real; retry/cooldown e conteúdo sem segredos.
- [ ] Release assinada, assinatura inválida e update após drain; rollback local.
- [ ] Spot-only em pool de teste: IAM mínima, AMI/subnets/security groups permitidos, IMDSv2 obrigatório, volume EBS criptografado e tags de launch.
- [ ] Enrollment Spot com instance ID correto e divergente; código de bootstrap single-use, expiração, não exposição em UI/logs e remoção após enrollment.
- [ ] Spot sem capacidade e com fallback desligado: nenhum On-Demand lançado e fila preservada; fallback autorizado após delay apenas para erros de capacidade.
- [ ] Fallback On-Demand em conta de teste: tipo permitido, limite de máquinas/custo, retries idempotentes após resposta de launch perdida e reconciliação por tag.
- [ ] Scale-in: runner ocioso removido do GitHub antes da terminação EC2; runner busy não é removido; medir idle timeout.
- [ ] Aviso de interrupção Spot: drain ocioso, job ativo pode ser perdido, substituição da capacidade e estado/alerta visível no painel.
- [ ] IAM/AMI/subnet/security group inválidos e credenciais AWS ausentes: erro observável, sem fallback pago em erro não classificado como falta de capacidade.
- [ ] O Fleet não cria VPC/IAM; validar egress HTTPS e ausência de endpoints Docker públicos nas subnets/SGs.
- [ ] Auditoria/retention/export; não distribuir prints, chaves ou dados da conta.
