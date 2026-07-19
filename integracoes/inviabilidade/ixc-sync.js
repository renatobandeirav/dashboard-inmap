const ORIGEM = "IXC";
const MOTIVO_CODIGO = "STATUS_VIABILIDADE_N";
const MOTIVO_NOME = "Lead não viável no IXC";
const CATEGORIA = "OUTRA";

function aguardar(ms) {
  return new Promise(resolve => {
    setTimeout(resolve, ms);
  });
}

function textoOuNull(valor) {
  const texto = String(valor ?? "").trim();

  return texto || null;
}

function numeroInteiroOuNull(valor) {
  const numero = Number(valor);

  if (
    !Number.isInteger(numero) ||
    numero <= 0
  ) {
    return null;
  }

  return numero;
}

function coordenadaNumericaValida(
  latitude,
  longitude
) {
  const lat = Number(latitude);
  const lng = Number(longitude);

  return (
    Number.isFinite(lat) &&
    Number.isFinite(lng) &&
    lat !== 0 &&
    lng !== 0
  );
}

function coordenadaDentroDaArea(
  latitude,
  longitude
) {
  const lat = Number(latitude);
  const lng = Number(longitude);

  if (
    !coordenadaNumericaValida(
      lat,
      lng
    )
  ) {
    return false;
  }

  /*
   * Faixa geográfica ampla usada no diagnóstico.
   * Exclui coordenadas claramente fora da operação,
   * inclusive o ponto inválido -21,-48.
   */
  return (
    lat >= -5 &&
    lat <= 0.5 &&
    lng >= -51 &&
    lng <= -46
  );
}

function ehLeadInviavelIXC(contato) {
  const lead = String(
    contato?.lead || ""
  )
    .trim()
    .toUpperCase();

  const statusViabilidade = String(
    contato?.status_viabilidade || ""
  )
    .trim()
    .toUpperCase();

  return (
    lead === "S" &&
    statusViabilidade === "N"
  );
}

function montarObservacaoIXC(contato) {
  const dados = [
    "Importado automaticamente do IXC.",
    `Ativo no IXC: ${textoOuNull(contato.ativo) || "NÃO INFORMADO"}`,
    `Status de viabilidade: ${textoOuNull(contato.status_viabilidade) || "NÃO INFORMADO"}`,
    `Distância da caixa: ${textoOuNull(contato.distancia_caixa_mais_proxima) || "NÃO INFORMADA"}`,
    `Caixa FTTH: ${textoOuNull(contato.id_caixa_ftth) || "NÃO INFORMADA"}`
  ];

const observacaoOriginal =
    textoOuNull(
        contato.obs ||
        contato.observacao
    );

  if (observacaoOriginal) {
    dados.push(
      `Observação do IXC: ${observacaoOriginal}`
    );
  }

  return dados.join("\n");
}

function criarSincronizadorInviabilidadeIXC({
  db,
  buscarPaginaIXC,
  buscarCidadeIXCCache
}) {
  if (!db) {
    throw new Error(
      "A conexão com o banco é obrigatória no sincronizador IXC."
    );
  }

  if (
    typeof buscarPaginaIXC !== "function"
  ) {
    throw new Error(
      "A função buscarPaginaIXC é obrigatória no sincronizador IXC."
    );
  }

    if (
    typeof buscarCidadeIXCCache !==
    "function"
  ) {
    throw new Error(
      "A função buscarCidadeIXCCache é obrigatória no sincronizador IXC."
    );
  }

  async function salvarContatoIXC(contato) {
    const contatoId =
      numeroInteiroOuNull(contato.id);

    if (!contatoId) {
      throw new Error(
        "Contato do IXC sem ID válido."
      );
    }

    const latitude =
      Number(contato.latitude);

    const longitude =
      Number(contato.longitude);

        const cidadeId =
          textoOuNull(
            contato.cidade ||
            contato.cidade_id
          );

        const cidadeIdValido =
          cidadeId &&
          cidadeId !== "0" &&
          cidadeId !== "-";

        const cidadeNome =
          cidadeIdValido
            ? await buscarCidadeIXCCache(
                cidadeId
              )
            : null;

        const cidade =
          cidadeNome &&
          cidadeNome !== "-" &&
          cidadeNome !==
            `Cidade ${cidadeId}`
            ? textoOuNull(cidadeNome)
            : null;

    const sql = `
      INSERT INTO inviabilidades_mapa (
        origem,
        origem_id,
        lead_ixc_id,
        cliente,
        motivo_codigo,
        motivo_nome,
        categoria,
        cidade,
        bairro,
        endereco,
        numero,
        complemento,
        referencia,
        latitude,
        longitude,
        data_origem,
        data_inviabilidade,
        status,
        observacao,
        sincronizado_em
      )
      VALUES (
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
        ?,
        NOW()
      )
      ON DUPLICATE KEY UPDATE
        lead_ixc_id =
          VALUES(lead_ixc_id),

        cliente =
          VALUES(cliente),

        motivo_codigo =
          VALUES(motivo_codigo),

        categoria =
          VALUES(categoria),

        cidade =
          VALUES(cidade),

        bairro =
          VALUES(bairro),

        endereco =
          VALUES(endereco),

        numero =
          VALUES(numero),

        complemento =
          VALUES(complemento),

        referencia =
          VALUES(referencia),

        latitude =
          VALUES(latitude),

        longitude =
          VALUES(longitude),

        data_origem =
          VALUES(data_origem),

        data_inviabilidade =
          VALUES(data_inviabilidade),

        observacao =
          VALUES(observacao),

        sincronizado_em = NOW()
    `;

    const valores = [
      ORIGEM,
      contatoId,
      contatoId,
      textoOuNull(contato.nome),
      MOTIVO_CODIGO,
      MOTIVO_NOME,
      CATEGORIA,
      cidade,
      textoOuNull(contato.bairro),
      textoOuNull(contato.endereco),
      textoOuNull(contato.numero),
      textoOuNull(contato.complemento),
      textoOuNull(contato.referencia),
      latitude,
      longitude,
      textoOuNull(contato.data_cadastro),
      textoOuNull(contato.data_cadastro),
      montarObservacaoIXC(contato)
    ];

    const [resultado] =
      await db.query(sql, valores);

    return {
      contato_id: contatoId,
      inserido:
        resultado.affectedRows === 1,
      atualizado:
        resultado.affectedRows === 2
    };
  }

  async function normalizarCidadesExistentesIXC() {
  const [cidadesNumericas] =
    await db.query(`
      SELECT DISTINCT
        cidade
      FROM inviabilidades_mapa
      WHERE origem = 'IXC'
        AND cidade IS NOT NULL
        AND cidade REGEXP '^[0-9]+$'
        AND cidade NOT IN ('0')
    `);

  let cidadesConvertidas = 0;
  let registrosAtualizados = 0;

  for (
    const item of cidadesNumericas
  ) {
    const cidadeId =
      textoOuNull(item.cidade);

    if (!cidadeId) {
      continue;
    }

    const cidadeNome =
      textoOuNull(
        await buscarCidadeIXCCache(
          cidadeId
        )
      );

    if (
      !cidadeNome ||
      cidadeNome === "-" ||
      cidadeNome ===
        `Cidade ${cidadeId}`
    ) {
      continue;
    }

    const [resultado] =
      await db.query(
        `
        UPDATE inviabilidades_mapa
        SET cidade = ?
        WHERE origem = 'IXC'
          AND cidade = ?
        `,
        [
          cidadeNome,
          cidadeId
        ]
      );

    cidadesConvertidas += 1;

    registrosAtualizados +=
      Number(
        resultado.affectedRows || 0
      );
  }

  const [resultadoSemCidade] =
    await db.query(`
      UPDATE inviabilidades_mapa
      SET cidade = NULL
      WHERE origem = 'IXC'
        AND cidade IN ('0', '-')
    `);

  return {
    cidades_convertidas:
      cidadesConvertidas,

    registros_atualizados:
      registrosAtualizados,

    registros_sem_cidade:
      Number(
        resultadoSemCidade
          .affectedRows || 0
      )
  };
}

  async function buscarTodosContatosInviaveis({
    registrosPorPagina = 500,
    limitePaginas = 20,
    intervaloMs = 250
  } = {}) {
    const registros = [];

    let pagina = 1;
    let totalIXC = 0;
    let totalPaginas = 1;

    while (
      pagina <= totalPaginas &&
      pagina <= limitePaginas
    ) {
      const retorno =
        await buscarPaginaIXC({
          pagina,
          registrosPorPagina
        });

      const registrosPagina =
        Array.isArray(retorno?.registros)
          ? retorno.registros
          : [];

      if (pagina === 1) {
        totalIXC =
          Number(retorno?.total || 0);

        totalPaginas = Math.max(
          Math.ceil(
            totalIXC /
            registrosPorPagina
          ),
          1
        );
      }

      registros.push(
        ...registrosPagina
      );

      console.log(
        `[IXC INVIABILIDADE] Página ${pagina}/${totalPaginas} ` +
        `- recebidos: ${registrosPagina.length}`
      );

      if (!registrosPagina.length) {
        break;
      }

      pagina += 1;

      if (
        pagina <= totalPaginas &&
        pagina <= limitePaginas &&
        intervaloMs > 0
      ) {
        await aguardar(intervaloMs);
      }
    }

    return {
      total_ixc: totalIXC,
      paginas_previstas:
        totalPaginas,
      paginas_processadas:
        pagina - 1,
      consulta_completa:
        pagina > totalPaginas,
      registros
    };
  }

  async function sincronizarIXC({
    registrosPorPagina = 500,
    limitePaginas = 20,
    intervaloMs = 250
  } = {}) {
    const inicio = Date.now();

    const consulta =
      await buscarTodosContatosInviaveis({
        registrosPorPagina,
        limitePaginas,
        intervaloMs
      });

    const leadsInviaveis =
      consulta.registros.filter(
        ehLeadInviavelIXC
      );

    const elegiveis =
      leadsInviaveis.filter(contato =>
        coordenadaDentroDaArea(
          contato.latitude,
          contato.longitude
        )
      );

      if (elegiveis.length > 0) {
  const contatoExemplo =
    elegiveis[0];

  console.log(
    "[IXC INVIABILIDADE] CAMPOS DE CIDADE:",
    {
      id:
        contatoExemplo.id,

      cidade:
        contatoExemplo.cidade,

      cidade_id:
        contatoExemplo.cidade_id,

      id_cidade:
        contatoExemplo.id_cidade,

      nome_cidade:
        contatoExemplo.nome_cidade,

      cidade_nome:
        contatoExemplo.cidade_nome,

      municipio:
        contatoExemplo.municipio,

      municipio_nome:
        contatoExemplo.municipio_nome
    }
  );

  console.log(
    "[IXC INVIABILIDADE] CHAVES DISPONÍVEIS:",
    Object.keys(contatoExemplo)
  );
}


    const ignoradosForaDaArea =
      leadsInviaveis.length -
      elegiveis.length;

    let inseridos = 0;
    let atualizados = 0;
    let erros = 0;

    const amostraErros = [];

    for (const contato of elegiveis) {
      try {
        const resultado =
          await salvarContatoIXC(
            contato
          );

        if (resultado.inserido) {
          inseridos += 1;
        } else {
          atualizados += 1;
        }
      } catch (erro) {
        erros += 1;

        console.error(
          "[IXC INVIABILIDADE] Erro ao salvar contato:",
          {
            contato_id:
              contato?.id,
            mensagem:
              erro.message
          }
        );

        if (
          amostraErros.length < 20
        ) {
          amostraErros.push({
            contato_id:
              contato?.id || null,
            mensagem:
              erro.message
          });
        }
      }
    }

    const normalizacaoCidades =
  await normalizarCidadesExistentesIXC();

    return {
      origem: ORIGEM,

      total_ixc:
        consulta.total_ixc,

      paginas_previstas:
        consulta.paginas_previstas,

      paginas_processadas:
        consulta.paginas_processadas,

      consulta_completa:
        consulta.consulta_completa,

      recebidos:
        consulta.registros.length,

      leads_inviaveis:
        leadsInviaveis.length,

      elegiveis:
        elegiveis.length,

      ignorados_fora_da_area:
        ignoradosForaDaArea,

      inseridos,
      atualizados,
      erros,

      normalizacao_cidades:
          normalizacaoCidades,

      amostra_erros:
        amostraErros,

      duracao_ms:
        Date.now() - inicio
    };
  }

  return {
    sincronizarIXC,
    buscarTodosContatosInviaveis
  };
}

module.exports = {
  criarSincronizadorInviabilidadeIXC,
  coordenadaDentroDaArea,
  ehLeadInviavelIXC
};