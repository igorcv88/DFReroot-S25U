# Early Boot / Pre-Zygote — avaliação inicial (2026-09-29)

> **Atualização pré-release.** Esta avaliação pre-zygote continua sendo NO-GO,
> mas a investigação de um gatilho *pós-system_server e anterior a
> LOCKED_BOOT_COMPLETED* avançou. Jobs de outros componentes foram observados
> nessa janela, portanto
> `JOBSCHEDULER_CAN_DISPATCH_PRE_LOCKED_BOOT=PHYSICAL_PASS`. Isso não prova a
> elegibilidade do DFR: `DFR_PERSISTED_JOB_EARLY_CALLBACK=UNVERIFIED` e
> `DFR_JOB_STAGEHOP_READY=UNVERIFIED`.
>
> A próxima APK contém somente um experimento observacional explicitamente
> armado: `DfrEarlyBootJobService`, persisted/direct-boot, one-shot e incapaz de
> executar Auto Root, DirtyFrag, StageHop dispatch, transporte root ou soft
> reboot. O callback grava marcador atômico com identidade real do processo e
> resolve, sem invocar, ProcessRecord, IApplicationThread e
> `scheduleReceiver/12`. Um disparo no mesmo boot de arming é registrado como
> `EARLY_JOB_FIRED_SAME_BOOT` e nunca promovido a PASS.

> **Atualização 2026-10-02 — a pergunta observacional foi respondida.** Em três
> full boots consecutivos (`48bf5c32…`, `9af4b55f…`, `ab10e200…`, APK
> `2.0.15-zzic`) o callback armado ocorreu a **14,6-16,9 s** do boot do kernel,
> em boot novo, com `bootanim_exit=0` e `user_unlocked=0`, e com os quatro
> componentes do StageHop já resolvidos - 2,69-2,90 s antes de
> `LOCKED_BOOT_COMPLETED`. Portanto
> `DFR_PERSISTED_JOB_EARLY_CALLBACK=PHYSICAL_PASS` e
> `DFR_JOB_STAGEHOP_READY=PHYSICAL_PASS`, 3/3. O registro autoritativo está em
> `docs/S25U_ZZIC_COMPATIBILITY.md` § *Early-job probe acceptance*.
>
> Isso **não** muda o veredito pre-zygote desta avaliação. O ponto medido é
> posterior a `system_server`, ao AMS e ao NetworkStack; `TRUE_PRE_ZYGOTE`
> continua não comprovado e esta rodada continua NO-GO para aquele caminho. O
> que foi construído sobre a janela medida - um despacho *dentro* da animação de
> boot, sem evidência física ainda - está em `docs/EARLY_ROOT.md`.

## Escopo e decisão

Esta rodada é uma revisão documental do `main` de `igorcv88/DFReroot-S25U`. Não houve acesso ao Galaxy S25 Ultra, captura de um full boot, inventário do firmware em execução ou ensaio físico. Por isso, nenhum horário, daemon candidato, capability observada ou vetor de execução anterior ao zygote é declarado como provado.

| Objetivo | Veredito nesta rodada | Fundamento |
|---|---|---|
| Integrated Boot | Candidato de produto; ainda não aceito fisicamente | A cadeia de Auto Root tem evidência parcial. O transporte de Apply Modules está implementado em fonte, mas sua aceitação física permanece pendente. O despacho automático após o closeout ainda não está demonstrado. |
| True Pre-Zygote usando a cadeia atual | NO-GO arquitetural | A cadeia documentada depende de `system_server` e do processo NetworkStack, ambos posteriores ao primeiro zygote. |
| True Pre-Zygote com um primeiro estágio diferente | NÃO DEMONSTRADO; NO-GO para implementação agora | Não há prova de execução persistente de código controlado entre a disponibilidade de /data e o primeiro zygote, nem de que tal ambiente satisfaça os requisitos do fluxo atual. |

A decisão operacional é concentrar as mudanças de produto no Integrated Boot enquanto a pergunta de existência de um primeiro estágio pre-zygote continuar sem evidência. Esta decisão não afirma impossibilidade universal no firmware ZZIC.

## Evidência examinada e correções de estado

- `AGENTS.md` descreve explicitamente o projeto como second-stage reroot, com o caminho `system_server → NetworkStack → libexp.so`. Também exige evidência do mesmo `boot_id` e recusa diante de dados ausentes.
- `docs/AUTO_ROOT.md` § Preflight exige `sys.boot_completed == 1` e visibilidade do NetworkStack antes de iniciar o fluxo automático. Receber `LOCKED_BOOT_COMPLETED` não significa começar a cadeia naquele instante. Logo, o Auto Root existente não pode ser descrito como concluído antes da primeira UI utilizável com base apenas no nome do broadcast.
- `docs/S25U_ZZIC_COMPATIBILITY.md` registra Gate I como PASS físico. A matriz classifica `AUTO_ROOT_FULL_BOOT` como **PARTIALLY ACCEPTED**: execução automática, recusa de segunda tentativa e novo full boot foram observados; o teste negativo de opt-out com qualificação válida no mesmo build ainda falta.
- `docs/HANDOFF.md` linhas iniciais chamavam `AUTO_ROOT_FULL_BOOT` de PASS. Para o estado de prova, a própria regra de precedência do repositório faz a matriz de compatibilidade prevalecer. **Corrigido em 2026-09-29**: o handoff agora diz *partially accepted* e nomeia o teste negativo de opt-out como o que falta.
- `docs/AUTO_ROOT.md` linhas iniciais ainda dizem que nenhum Auto Root rodou em hardware, outra redação desatualizada diante das capturas posteriores da matriz.
- O registro do boot `2e447aaf…` prova `POST_ROOT_COMPLETE`, versão KernelSU 32601, UAPI 2 e SELinux 1 no mesmo boot. Ele não identifica se o primeiro disparo veio de `LOCKED_BOOT_COMPLETED` ou de `BOOT_COMPLETED`; os horários de zygote e de disponibilidade de /data não foram preservados.
- A implementação do transporte de Apply Modules descrita no handoff e em `AUTO_ROOT.md` ainda deve ser distinguida de aceitação física. A matriz registra a investigação e diz que o resultado físico é devido.
- `docs/PHYSICAL_TESTING.md` foi escrito para uma versão anterior; seus comandos e estados não substituem a matriz atual.

## Timeline física

> **Correção de 2026-09-29 — esta seção foi superada no mesmo dia.** O
> `BLOCKED` abaixo descreve a rodada documental; horas depois uma captura
> física do aparelho (`DFR_EARLYBOOT_20260929_112543.tar.gz`, SHA-256
> `d1503ad7…`) foi registrada em `docs/AUTO_ROOT.md` § *Early Integrated Boot*,
> com tempos monotônicos do mesmo boot para NetworkStack, `bootanim.exit`,
> `LOCKED_BOOT_COMPLETED`, o handoff do receiver e `RUN_NATIVE`. **Aquela
> seção é a cópia autoritativa da timeline; a tabela abaixo é histórica.**
> Ela continua correta no que diz respeito ao pre-zygote: a captura mede a
> janela do broadcast, e não `/data` pronta, APEX ou o primeiro zygote, que
> permanecem não medidos.

**Status na rodada documental: BLOCKED (sem captura do aparelho).** Não se deve preencher a tabela com horários derivados de wall-clock, de boots diferentes ou da ordem genérica do AOSP.

| Evento | BOOTTIME_MS | boot_id | Estado |
|---|---:|---|---|
| /data disponível | — | — | Não medido |
| APEX pronto | — | — | Não medido |
| Primeiro zygote | — | — | Não medido |
| Primeiro system_server | — | — | Não medido |
| Primeiro NetworkStack | — | — | Não medido |
| Primeiro disparo DFR / início nativo | — | — | Não medido |
| KernelSU carregado | — | — | Não medido |
| POST_ROOT_COMPLETE | — | — | Estado final observado em boots anteriores; timestamp monotônico correlacionado não medido |

Critério da captura futura: todos os eventos devem pertencer ao mesmo `boot_id`, usar um relógio monotônico comparável e conservar a origem e a incerteza de cada timestamp. A diferença entre /data pronta e o primeiro zygote só pode ser calculada depois disso.

## Inventário e ambiente pre-zygote

**Inventário de serviços nativos: BLOCKED.** Não há, nos cinco documentos revisados, lista física de serviços iniciados antes do primeiro zygote com PID, starttime, domínio SELinux, CapEff, seccomp e acesso comprovado aos recursos necessários. Não inferir essas propriedades de um arquivo `init.rc` ou de capabilities declaradas: o estado efetivo do processo e o instante importam.

| Propriedade | Evidência do ambiente pós-zygote atual | Evidência de candidato pre-zygote |
|---|---|---|
| Execução do DFR | NetworkStack observado no alvo | Ausente |
| Domínio SELinux efetivo | NetworkStack documentado | Ausente |
| Capabilities efetivas | Gate do NetworkStack documentado | Ausente |
| Seccomp aplicável | Sem conclusão transferível | Ausente |
| /data e artefatos acessíveis na janela | Sem medição da janela | Ausente |
| APEX/runtime prontos na janela | Sem medição da janela | Ausente |
| Execução persistente após full reboot antes do zygote | Não é propriedade da cadeia atual | Ausente |

Nenhum candidato real e nenhum execution vector persistente foi identificado nesta rodada. A ausência de inventário não prova que não exista um. Ela impede um GO. Não há base para planejar um launcher que o `init` stock nunca foi observado iniciando.

## Interfaces arquiteturais condicionais

A separação conceitual `frontend JNI → core compartilhado ← frontend nativo` só deve ser considerada depois de comprovado um ambiente de execução apropriado. Uma extração desse tipo exigiria preservar as verificações de identidade, a política de recusa, os limites de estágio, a atribuição de evidência por boot e um único mecanismo compartilhado, sem duplicar comportamento entre frontends. Não existe justificativa para refatorar o core nesta rodada.

O `late-load` documentado é um lifecycle tardio. Um hipotético lifecycle antecipado teria de separar o que pertence a post-fs-data/mounts do que depende dos marcos posteriores do boot, preservar SELinux Enforcing no estado final e evitar disparar service/boot-completed antes dos respectivos eventos. Isso é um requisito de desenho, não uma afirmação de que o firmware permite realizá-lo.

## Recovery e aceite

Qualquer desenho que anteceda o primeiro zygote precisaria liberar o boot stock quando a etapa opcional falhar, ter um prazo máximo medido por relógio monotônico, impedir repetição no mesmo boot, prever desativação persistente e tratar um estado ambíguo após alteração de memória como motivo para recovery. Nenhum desses requisitos foi implementado ou testado para um primeiro estágio antecipado.

`TRUE_PRE_ZYGOTE=PASS` exigiria registro físico de um mesmo full boot com root e lifecycle concluídos antes do primeiro zygote, primeiro `system_server` já instrumentado, SELinux Enforcing e nenhuma reinicialização de zygote/framework. Hoje: **não comprovado**.

Para Integrated Boot, a próxima aceitação deve preservar a evidência de `POST_ROOT_COMPLETE` e SELinux Enforcing antes da operação de módulos, diferenciar despacho de conclusão real do framework e provar que o mesmo `boot_id` não autoriza outro Auto Root. O comportamento de ReZygisk, LSPosed e HMA deve ser observado depois do framework final. A rota de transporte de Apply Modules ainda aguarda resultado físico; a alternativa de despacho pelo daemon é apenas hipótese de desenho.

## Decisão da primeira rodada

- **NO-GO** para portar o fluxo ao boot anterior ao zygote ou alterar o exploit.
- **GO para investigação observacional**, se houver uma captura física de um full boot e inventário de estado efetivo do firmware.
- **Integrated Boot é o caminho prático a validar**, sem declarar que já ocorre automaticamente ou que termina antes do primeiro unlock.

Fontes no repositório: `AGENTS.md`, `docs/HANDOFF.md`, `docs/S25U_ZZIC_COMPATIBILITY.md`, `docs/AUTO_ROOT.md` e `docs/PHYSICAL_TESTING.md`, consultados no `main` em 2026-09-29.
