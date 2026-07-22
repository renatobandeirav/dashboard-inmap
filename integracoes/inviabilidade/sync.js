const {
  normalizarCategoriaInviabilidade,
  ehMotivoDeInviabilidade,
  gerarCodigoMotivo
} = require("./normalizador");

function criarSincronizadorInviabilidade(db) {
  if (!db) {
    throw new Error(
      "A conexão com o banco é obrigatória no sincronizador de inviabilidade."
    );
  }

  async function buscarOportunidadesPiperun() {
    const [registros] = await db.query(`
      SELECT
        deal_id,
        person_id,
        cliente,
        etapa,
        vendedor_nome,
        vendedor_ixc_id,
        campanha_nome,
        canal_venda_nome,
        plano_nome,
        cidade,
        bairro,
        latitude,
        longitude,
        data_origem,
        data_entrada_etapa,
        sincronizado_em
      FROM piperun_oportunidades
      WHERE
        latitude IS NOT NULL
        AND longitude IS NOT NULL
      ORDER BY deal_id
    `);

    return registros;
  }

  async function salvarInviabilidade(oportunidade) {
    const categoria =
      normalizarCategoriaInviabilidade(
        oportunidade.etapa
      );

    const motivoCodigo =
      gerarCodigoMotivo(
        oportunidade.etapa
      );

    const sql = `
      INSERT INTO inviabilidades_mapa (
        origem,
        origem_id,
        deal_id,
        person_id,
        cliente,
        motivo_codigo,
        motivo_nome,
        categoria,
        vendedor_nome,
        vendedor_ixc_id,
        campanha_nome,
        canal_venda_nome,
        plano_nome,
        cidade,
        bairro,
        latitude,
        longitude,
        data_origem,
        data_inviabilidade,
        status,
        sincronizado_em
      )
      VALUES (
        'PIPERUN',
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        ?,
        'ATIVA',
        NOW()
      )
      ON DUPLICATE KEY UPDATE
        deal_id = VALUES(deal_id),
        person_id = VALUES(person_id),
        cliente = VALUES(cliente),
        motivo_codigo = VALUES(motivo_codigo),
        categoria = VALUES(categoria),
        vendedor_nome = VALUES(vendedor_nome),
        vendedor_ixc_id = VALUES(vendedor_ixc_id),
        campanha_nome = VALUES(campanha_nome),
        canal_venda_nome = VALUES(canal_venda_nome),
        plano_nome = VALUES(plano_nome),
        cidade = VALUES(cidade),
        bairro = VALUES(bairro),
        latitude = VALUES(latitude),
        longitude = VALUES(longitude),
        data_origem = VALUES(data_origem),
        data_inviabilidade = VALUES(data_inviabilidade),
        status = 'ATIVA',
        sincronizado_em = NOW()
    `;

    const valores = [
      oportunidade.deal_id,
      oportunidade.deal_id,
      oportunidade.person_id,
      oportunidade.cliente,
      motivoCodigo,
      oportunidade.etapa,
      categoria,
      oportunidade.vendedor_nome,
      oportunidade.vendedor_ixc_id,
      oportunidade.campanha_nome,
      oportunidade.canal_venda_nome,
      oportunidade.plano_nome,
      oportunidade.cidade,
      oportunidade.bairro,
      oportunidade.latitude,
      oportunidade.longitude,
      oportunidade.data_origem,
      oportunidade.data_entrada_etapa
    ];

    await db.query(sql, valores);
  }

  async function sincronizarPiperun() {
    const inicio = Date.now();

    const oportunidades =
      await buscarOportunidadesPiperun();

    const inviabilidades =
      oportunidades.filter(oportunidade =>
        ehMotivoDeInviabilidade(
          oportunidade.etapa
        )
      );

    let salvos = 0;
    let ignorados = 0;

    for (const oportunidade of inviabilidades) {
      try {
        await salvarInviabilidade(
          oportunidade
        );

        salvos += 1;
      } catch (erro) {
        ignorados += 1;

        console.error(
          "[INVIABILIDADE] Erro ao salvar oportunidade:",
          {
            deal_id: oportunidade.deal_id,
            motivo: oportunidade.etapa,
            mensagem: erro.message
          }
        );
      }
    }

    return {
      origem: "PIPERUN",
      recebidos: oportunidades.length,
      identificados_como_inviabilidade:
        inviabilidades.length,
      salvos,
      ignorados,
      duracao_ms: Date.now() - inicio
    };
  }

  return {
    sincronizarPiperun
  };
}

module.exports = {
  criarSincronizadorInviabilidade
};