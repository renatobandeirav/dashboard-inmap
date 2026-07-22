const { buscarTodosDeals } = require("./client");
const { transformarListaDeals } = require("./service");
const { PIPELINES } = require("./constants");

function criarSincronizadorPiperun(db) {

    async function iniciarLogSincronizacao({
  pipelineId,
  pipelineNome,
  tipoSincronizacao = "completa"
}) {
  const [resultado] = await db.query(
    `
    INSERT INTO piperun_sync_log (
      pipeline_id,
      pipeline_nome,
      tipo_sincronizacao,
      status,
      iniciado_em
    )
    VALUES (?, ?, ?, 'executando', NOW())
    `,
    [
      pipelineId,
      pipelineNome,
      tipoSincronizacao
    ]
  );

  return resultado.insertId;
}

async function finalizarLogSincronizacao({
  logId,
  status,
  recebidos = 0,
  tratados = 0,
  salvos = 0,
  totalPaginas = 0,
  duracaoMs = null,
  ultimaDataPiperun = null,
  mensagemErro = null,
  codigoErro = null
}) {
  await db.query(
    `
    UPDATE piperun_sync_log
    SET
      status = ?,
      recebidos = ?,
      tratados = ?,
      salvos = ?,
      total_paginas = ?,
      finalizado_em = NOW(),
      duracao_ms = ?,
      ultima_data_piperun = ?,
      mensagem_erro = ?,
      codigo_erro = ?
    WHERE id = ?
    `,
    [
      status,
      recebidos,
      tratados,
      salvos,
      totalPaginas,
      duracaoMs,
      ultimaDataPiperun,
      mensagemErro,
      codigoErro,
      logId
    ]
  );
}


  async function salvarOportunidade(oportunidade) {
    const sql = `
      INSERT INTO piperun_oportunidades (
        deal_id,
        person_id,
        pipeline_id,
        stage_id,
        etapa,
        status_piperun,
        cliente,
        vendedor_nome,
        vendedor_ixc_id,
        responsavel_piperun_id,
        responsavel_piperun_nome,
        cidade,
        bairro,
        latitude,
        longitude,
        campanha_ixc_id,
        campanha_nome,
        canal_venda_ixc_id,
        canal_venda_nome,
        plano_ixc_id,
        plano_nome,
        valor,
        mrr,
        instalacao_valor,
        instalacao_gratis,
        data_origem,
        data_entrada_funil,
        data_entrada_etapa,
        lead_time,
        oportunidade_origem_id,
        origin_id,
        criado_piperun_em,
        atualizado_piperun_em,
        sincronizado_em
      )
      VALUES (
        ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NOW()
      )
      ON DUPLICATE KEY UPDATE
        person_id = VALUES(person_id),
        pipeline_id = VALUES(pipeline_id),
        stage_id = VALUES(stage_id),
        etapa = VALUES(etapa),
        status_piperun = VALUES(status_piperun),
        cliente = VALUES(cliente),
        vendedor_nome = VALUES(vendedor_nome),
        vendedor_ixc_id = VALUES(vendedor_ixc_id),
        responsavel_piperun_id = VALUES(responsavel_piperun_id),
        responsavel_piperun_nome = VALUES(responsavel_piperun_nome),
        cidade = VALUES(cidade),
        bairro = VALUES(bairro),
        latitude = VALUES(latitude),
        longitude = VALUES(longitude),
        campanha_ixc_id = VALUES(campanha_ixc_id),
        campanha_nome = VALUES(campanha_nome),
        canal_venda_ixc_id = VALUES(canal_venda_ixc_id),
        canal_venda_nome = VALUES(canal_venda_nome),
        plano_ixc_id = VALUES(plano_ixc_id),
        plano_nome = VALUES(plano_nome),
        valor = VALUES(valor),
        mrr = VALUES(mrr),
        instalacao_valor = VALUES(instalacao_valor),
        instalacao_gratis = VALUES(instalacao_gratis),
        data_origem = VALUES(data_origem),
        data_entrada_funil = VALUES(data_entrada_funil),
        data_entrada_etapa = VALUES(data_entrada_etapa),
        lead_time = VALUES(lead_time),
        oportunidade_origem_id = VALUES(oportunidade_origem_id),
        origin_id = VALUES(origin_id),
        criado_piperun_em = VALUES(criado_piperun_em),
        atualizado_piperun_em = VALUES(atualizado_piperun_em),
        sincronizado_em = NOW()
    `;

    const valores = [
      oportunidade.deal_id,
      oportunidade.person_id,
      oportunidade.pipeline_id,
      oportunidade.stage_id,
      oportunidade.etapa,
      oportunidade.status_piperun,
      oportunidade.cliente,
      oportunidade.vendedor_nome,
      oportunidade.vendedor_ixc_id,
      oportunidade.responsavel_piperun_id,
      oportunidade.responsavel_piperun_nome,
      oportunidade.cidade,
      oportunidade.bairro,
      oportunidade.latitude,
      oportunidade.longitude,
      oportunidade.campanha_ixc_id,
      oportunidade.campanha_nome,
      oportunidade.canal_venda_ixc_id,
      oportunidade.canal_venda_nome,
      oportunidade.plano_ixc_id,
      oportunidade.plano_nome,
      oportunidade.valor,
      oportunidade.mrr,
      oportunidade.instalacao_valor,
      oportunidade.instalacao_gratis,
      oportunidade.data_origem,
      oportunidade.data_entrada_funil,
      oportunidade.data_entrada_etapa,
      oportunidade.lead_time,
      oportunidade.oportunidade_origem_id,
      oportunidade.origin_id,
      oportunidade.criado_piperun_em,
      oportunidade.atualizado_piperun_em
    ];

    await db.query(sql, valores);
  }

            async function sincronizarPerdidos({
            show = 100,
            limitePaginas = 100
            } = {}) {
            const inicio = Date.now();

            const pipelineId = PIPELINES.PERDIDOS.id;
            const pipelineNome = PIPELINES.PERDIDOS.nome;

            let logId = null;

            try {
                logId = await iniciarLogSincronizacao({
                pipelineId,
                pipelineNome,
                tipoSincronizacao: "completa"
                });

                const resultado = await buscarTodosDeals({
                pipelineId,
                show,
                limitePaginas
                });

                const oportunidades = transformarListaDeals(
                resultado.dados
                );

                let salvos = 0;

                for (const oportunidade of oportunidades) {
                await salvarOportunidade(oportunidade);
                salvos += 1;
                }

                const datasPiperun = oportunidades
                .map(oportunidade => {
                    return (
                    oportunidade.atualizado_piperun_em ||
                    oportunidade.criado_piperun_em
                    );
                })
                .filter(Boolean)
                .sort();

                const ultimaDataPiperun =
                datasPiperun.length > 0
                    ? datasPiperun[datasPiperun.length - 1]
                    : null;

                const retorno = {
                recebidos: resultado.dados.length,
                tratados: oportunidades.length,
                salvos,
                total_paginas: resultado.totalPaginas
                };

                await finalizarLogSincronizacao({
                logId,
                status: "sucesso",
                recebidos: retorno.recebidos,
                tratados: retorno.tratados,
                salvos: retorno.salvos,
                totalPaginas: retorno.total_paginas,
                duracaoMs: Date.now() - inicio,
                ultimaDataPiperun
                });

                return retorno;

            } catch (erro) {
                if (logId) {
                try {
                    await finalizarLogSincronizacao({
                    logId,
                    status: "erro",
                    duracaoMs: Date.now() - inicio,
                    mensagemErro: String(
                        erro?.message || "Erro desconhecido"
                    ).slice(0, 500),
                    codigoErro: String(
                        erro?.code ||
                        erro?.status ||
                        ""
                    ).slice(0, 100) || null
                    });
                } catch (erroLog) {
                    console.error(
                    "[PIPERUN] Não foi possível finalizar o log da sincronização:",
                    erroLog
                    );
                }
                }

                throw erro;
            }
            }

  return {
    sincronizarPerdidos
  };
}

module.exports = {
  criarSincronizadorPiperun
};